package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/JosephITA/flyingfish/internal/engine"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// PeeringInfo gathers a human-shareable dump of live peering resources —
// ForeignClusters, ResourceSlices, Identities, Tenants, NamespaceOffloadings
// and virtual node capacity — as ready-to-render tables. It reuses the same
// memoized reads the checks already performed, so this costs nothing extra
// for resources already fetched (ForeignClusters). Returns nil if there is
// no peering on the local cluster — nothing to show.
func PeeringInfo(ctx context.Context, c *engine.Ctx) []engine.Table {
	k := cl(c.Local)
	fcs, err := listCR(ctx, c, k, groupCore, "foreignclusters")
	if err != nil || len(fcs) == 0 {
		return nil
	}
	if c.Peer != "" {
		var filtered []unstructured.Unstructured
		for _, fc := range fcs {
			if fc.GetName() == c.Peer {
				filtered = append(filtered, fc)
			}
		}
		fcs = filtered
		if len(fcs) == 0 {
			return nil
		}
	}

	now := time.Now()
	var tables []engine.Table

	fcTable := engine.Table{Title: "Foreign Clusters (peerings) — on " + k.Name, Headers: []string{"Name", "Role", "Age"}}
	for _, fc := range fcs {
		role := nestedString(fc.Object, "status", "role")
		if role == "" {
			role = "-"
		}
		fcTable.Rows = append(fcTable.Rows, []string{
			fc.GetName(), role, humanDuration(now.Sub(fc.GetCreationTimestamp().Time)),
		})
	}
	tables = append(tables, fcTable)

	if rss, err := listCR(ctx, c, k, groupAuth, "resourceslices"); err == nil && len(rss) > 0 {
		t := engine.Table{Title: "Resource Slices", Headers: []string{"Name", "CPU req/acc", "Memory req/acc", "Pods req/acc", "Status"}}
		for _, rs := range rss {
			cpu := resourcePair(rs.Object, "cpu")
			mem := resourcePair(rs.Object, "memory")
			pods := resourcePair(rs.Object, "pods")
			status := conditionsSummary(conditionsAt(rs.Object, "status", "conditions"))
			t.Rows = append(t.Rows, []string{crName(rs), cpu, mem, pods, status})
		}
		tables = append(tables, t)
	}

	if ids, err := listCR(ctx, c, k, groupAuth, "identities"); err == nil && len(ids) > 0 {
		t := engine.Table{Title: "Identities", Headers: []string{"Name", "Type", "Age"}}
		for _, id := range ids {
			typ := nestedString(id.Object, "spec", "type")
			if typ == "" {
				typ = "-"
			}
			t.Rows = append(t.Rows, []string{crName(id), typ, humanDuration(now.Sub(id.GetCreationTimestamp().Time))})
		}
		tables = append(tables, t)
	}

	if tenants, err := listCR(ctx, c, k, groupAuth, "tenants"); err == nil && len(tenants) > 0 {
		t := engine.Table{Title: "Tenants (this cluster acting as provider)", Headers: []string{"Name", "Age"}}
		for _, tn := range tenants {
			t.Rows = append(t.Rows, []string{crName(tn), humanDuration(now.Sub(tn.GetCreationTimestamp().Time))})
		}
		tables = append(tables, t)
	}

	if nos, err := listCR(ctx, c, k, groupOffload, "namespaceoffloadings"); err == nil && len(nos) > 0 {
		t := engine.Table{Title: "Namespace Offloading", Headers: []string{"Namespace", "Strategy", "Status"}}
		for _, no := range nos {
			strat := nestedString(no.Object, "spec", "podOffloadingStrategy")
			if strat == "" {
				strat = "-"
			}
			status := conditionsSummary(conditionsAt(no.Object, "status", "conditions"))
			t.Rows = append(t.Rows, []string{no.GetNamespace(), strat, status})
		}
		tables = append(tables, t)
	}

	if nodes, err := k.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "liqo.io/type=virtual-node"}); err == nil && len(nodes.Items) > 0 {
		t := engine.Table{Title: "Virtual Nodes (offered capacity)", Headers: []string{"Name", "CPU", "Memory", "Pods", "Age", "Ready"}}
		for _, n := range nodes.Items {
			ready := "Unknown"
			for _, cond := range n.Status.Conditions {
				if cond.Type == corev1.NodeReady {
					ready = string(cond.Status)
				}
			}
			t.Rows = append(t.Rows, []string{
				n.Name,
				n.Status.Capacity.Cpu().String(),
				n.Status.Capacity.Memory().String(),
				n.Status.Capacity.Pods().String(),
				humanDuration(now.Sub(n.CreationTimestamp.Time)),
				ready,
			})
		}
		tables = append(tables, t)
	}

	return tables
}

// resourcePair renders "<requested>/<accepted>" for one resource name found
// under spec.resources / status.resources of a ResourceSlice.
func resourcePair(obj map[string]any, resource string) string {
	req := nestedString(obj, "spec", "resources", resource)
	acc := nestedString(obj, "status", "resources", resource)
	if req == "" {
		req = "-"
	}
	if acc == "" {
		acc = "-"
	}
	return fmt.Sprintf("%s/%s", req, acc)
}

func conditionsSummary(conds []conditionInfo) string {
	if len(conds) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(conds))
	for _, cnd := range conds {
		parts = append(parts, fmt.Sprintf("%s=%s", cnd.Type, cnd.Status))
	}
	return strings.Join(parts, ", ")
}
