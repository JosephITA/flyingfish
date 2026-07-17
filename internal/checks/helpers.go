// Package checks implements the passive check catalog from
// LIQO_CONNECTIVITY_DIAGNOSTICS.md §5 (layers ENV → REF).
package checks

import (
	"context"
	"fmt"
	"time"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	liqoNS = "liqo"

	groupCore    = "core.liqo.io"
	groupNet     = "networking.liqo.io"
	groupIPAM    = "ipam.liqo.io"
	groupAuth    = "authentication.liqo.io"
	groupOffload = "offloading.liqo.io"
)

func cl(c engine.Cluster) *kube.Cluster {
	k, _ := c.(*kube.Cluster)
	return k
}

func pass(detail string, evidence ...string) engine.Result {
	return engine.Result{Status: engine.Pass, Detail: detail, Evidence: evidence}
}

func warn(detail, remediation string, evidence ...string) engine.Result {
	return engine.Result{Status: engine.Warn, Detail: detail, Remediation: remediation, Evidence: evidence}
}

func fail(detail, remediation string, evidence ...string) engine.Result {
	return engine.Result{Status: engine.Fail, Detail: detail, Remediation: remediation, Evidence: evidence}
}

func skip(detail string) engine.Result {
	return engine.Result{Status: engine.Skip, Detail: detail}
}

// listCR lists a Liqo CR on a cluster, memoized per (cluster, group, resource).
func listCR(ctx context.Context, c *engine.Ctx, k *kube.Cluster, group, resource string) ([]unstructured.Unstructured, error) {
	key := fmt.Sprintf("cr/%s/%s/%s", k.Name, group, resource)
	return engine.Memo(c, key, func() ([]unstructured.Unstructured, error) {
		return k.List(ctx, group, resource, "")
	})
}

func tenantNamespaces(ctx context.Context, c *engine.Ctx, k *kube.Cluster) ([]string, error) {
	key := "tenantns/" + k.Name
	return engine.Memo(c, key, func() ([]string, error) {
		return k.TenantNamespaces(ctx)
	})
}

// nestedString reads a nested string field, returning "" when absent.
func nestedString(obj map[string]any, path ...string) string {
	s, _, _ := unstructured.NestedString(obj, path...)
	return s
}

// nestedAny reads a nested value of any shape, returning nil when absent.
func nestedAny(obj map[string]any, path ...string) any {
	v, ok, _ := unstructured.NestedFieldNoCopy(obj, path...)
	if !ok {
		return nil
	}
	return v
}

// nestedInt reads a nested integer field (JSON numbers land as int64/float64).
func nestedInt(obj map[string]any, path ...string) (int64, bool) {
	v := nestedAny(obj, path...)
	switch t := v.(type) {
	case int64:
		return t, true
	case float64:
		return int64(t), true
	}
	return 0, false
}

// crName renders "namespace/name" for evidence lines.
func crName(u unstructured.Unstructured) string {
	if u.GetNamespace() == "" {
		return u.GetName()
	}
	return u.GetNamespace() + "/" + u.GetName()
}

// humanDuration renders a duration the way an operator reads uptime: the two
// most significant units ("3d4h", "2h15m", "42s"), never Go's raw "72h3m0.5s".
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh%dm", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%dm", mins)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

// humanBytes renders a byte count as e.g. "4.2MiB".
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// conditionInfo is one entry of a Kubernetes-style status.conditions array.
type conditionInfo struct {
	Type, Status, Message string
	LastTransition        time.Time
	HasTransition         bool
}

// conditionsAt reads a []metav1.Condition-shaped list at the given path.
// Liqo CRDs vary in exactly where conditions live, so callers pass the path
// explicitly rather than this function assuming one schema.
func conditionsAt(obj map[string]any, path ...string) []conditionInfo {
	arr, ok := nestedAny(obj, path...).([]any)
	if !ok {
		return nil
	}
	var out []conditionInfo
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ci := conditionInfo{
			Type:    fmt.Sprint(m["type"]),
			Status:  fmt.Sprint(m["status"]),
			Message: fmt.Sprint(m["message"]),
		}
		if ts, ok := m["lastTransitionTime"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				ci.LastTransition, ci.HasTransition = t, true
			}
		}
		out = append(out, ci)
	}
	return out
}
