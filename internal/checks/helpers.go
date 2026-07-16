// Package checks implements the passive check catalog from
// LIQO_CONNECTIVITY_DIAGNOSTICS.md §5 (layers ENV → REF).
package checks

import (
	"context"
	"fmt"

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
