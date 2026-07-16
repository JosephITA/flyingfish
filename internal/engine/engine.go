// Package engine implements the layered check runner described in
// LIQO_CONNECTIVITY_DIAGNOSTICS.md §4: checks form a DAG, run layer by
// layer, and a failed dependency marks its dependents as skipped so the
// report points at the first broken link instead of a cascade.
package engine

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Status string

const (
	Pass Status = "PASS"
	Warn Status = "WARN"
	Fail Status = "FAIL"
	Skip Status = "SKIP"
)

// Layers in diagnostic order. The first failing layer is the diagnosis.
var Layers = []string{"env", "api", "gateway", "tunnel", "fabric", "ipam", "cni", "reflection"}

type Result struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Layer       string   `json:"layer"`
	Cluster     string   `json:"cluster"`
	Status      Status   `json:"status"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

type Check struct {
	ID        string
	Name      string
	Layer     string
	DependsOn []string
	// NeedsDual marks checks that correlate both clusters; they are
	// skipped in single-cluster mode.
	NeedsDual bool
	Run       func(ctx context.Context, c *Ctx) Result
}

// Ctx carries cluster access and a memoization cache shared across checks.
type Ctx struct {
	Local  Cluster
	Remote Cluster // nil in single-cluster mode
	Peer   string  // optional ForeignCluster name filter

	Timeout time.Duration

	mu    sync.Mutex
	cache map[string]any
	facts []Fact
}

// Fact is a concrete, copy-pasteable piece of connectivity information
// (an IP, an endpoint, a CIDR) with an optional manual test command.
type Fact struct {
	Label   string `json:"label"`
	Value   string `json:"value"`
	Command string `json:"command,omitempty"`
}

// AddFact records a fact for the end-of-report cheat sheet. Duplicate
// label+value pairs are dropped.
func (c *Ctx) AddFact(label, value, command string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.facts {
		if f.Label == label && f.Value == value {
			return
		}
	}
	c.facts = append(c.facts, Fact{Label: label, Value: value, Command: command})
}

func (c *Ctx) Facts() []Fact {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Fact(nil), c.facts...)
}

// Cluster is the minimal surface checks need; satisfied by kube.Cluster.
type Cluster interface {
	DisplayName() string
	IsNil() bool
}

func NewCtx(local, remote Cluster, peer string, timeout time.Duration) *Ctx {
	return &Ctx{Local: local, Remote: remote, Peer: peer, Timeout: timeout, cache: map[string]any{}}
}

func (c *Ctx) Dual() bool { return c.Remote != nil && !c.Remote.IsNil() }

// Memo caches expensive lookups (tenant namespaces, CR lists) across checks.
// The lock is NOT held while fn runs: memoized loaders call other memoized
// loaders (e.g. identity secrets → tenant namespaces), which would deadlock
// on a held mutex. Duplicate computation on a cold cache is acceptable.
func Memo[T any](c *Ctx, key string, fn func() (T, error)) (T, error) {
	c.mu.Lock()
	if v, ok := c.cache[key]; ok {
		if cached, ok := v.(memoEntry[T]); ok {
			c.mu.Unlock()
			return cached.val, cached.err
		}
	}
	c.mu.Unlock()

	val, err := fn()

	c.mu.Lock()
	c.cache[key] = memoEntry[T]{val, err}
	c.mu.Unlock()
	return val, err
}

type memoEntry[T any] struct {
	val T
	err error
}

// Run executes all checks layer by layer and returns results in order.
// onResult, if non-nil, is invoked as each check completes (for live output).
func Run(ctx context.Context, c *Ctx, checks []Check, onResult func(Result)) []Result {
	byID := map[string]Status{}
	var results []Result

	for _, layer := range Layers {
		for _, chk := range checks {
			if chk.Layer != layer {
				continue
			}
			res := runOne(ctx, c, chk, byID)
			byID[chk.ID] = res.Status
			results = append(results, res)
			if onResult != nil {
				onResult(res)
			}
		}
	}
	return results
}

func runOne(ctx context.Context, c *Ctx, chk Check, done map[string]Status) Result {
	base := Result{ID: chk.ID, Name: chk.Name, Layer: chk.Layer, Cluster: c.Local.DisplayName()}

	if chk.NeedsDual && !c.Dual() {
		base.Status = Skip
		base.Detail = "requires --remote-kubeconfig (dual-cluster mode)"
		return base
	}
	for _, dep := range chk.DependsOn {
		if st, ok := done[dep]; ok && st == Fail {
			base.Status = Skip
			base.Detail = fmt.Sprintf("skipped: dependency %s failed", dep)
			return base
		}
	}

	cctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	resCh := make(chan Result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resCh <- Result{Status: Fail, Detail: fmt.Sprintf("check panicked: %v", r)}
			}
		}()
		resCh <- chk.Run(cctx, c)
	}()

	select {
	case r := <-resCh:
		r.ID, r.Name, r.Layer = chk.ID, chk.Name, chk.Layer
		if r.Cluster == "" {
			r.Cluster = c.Local.DisplayName()
		}
		return r
	case <-cctx.Done():
		base.Status = Fail
		base.Detail = fmt.Sprintf("check timed out after %s", c.Timeout)
		return base
	}
}

// Diagnosis picks the primary finding: the first Fail in layer order,
// falling back to the first Warn.
func Diagnosis(results []Result) *Result {
	for _, want := range []Status{Fail, Warn} {
		for _, r := range results {
			if r.Status == want {
				res := r
				return &res
			}
		}
	}
	return nil
}
