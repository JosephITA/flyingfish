package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/JosephITA/flyingfish/internal/engine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func fabricChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "FAB-01", Name: "Fabric daemonset covers every node", Layer: "fabric", DependsOn: []string{"ENV-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				ds, err := k.Clientset.AppsV1().DaemonSets(liqoNS).Get(ctx, "liqo-fabric", metav1.GetOptions{})
				if err != nil {
					return fail("liqo-fabric daemonset not found: "+err.Error(),
						"without the fabric agent nodes cannot reach the gateway over Geneve; reinstall/upgrade Liqo")
				}
				if ds.Status.NumberReady < ds.Status.DesiredNumberScheduled {
					return fail(fmt.Sprintf("liqo-fabric ready on %d/%d nodes — pods on uncovered nodes cannot reach remote clusters (node-partial failures)",
						ds.Status.NumberReady, ds.Status.DesiredNumberScheduled),
						"kubectl -n liqo get pods -l app.kubernetes.io/name=fabric -o wide; fix the nodes where it is not ready")
				}
				return pass(fmt.Sprintf("liqo-fabric ready on all %d nodes", ds.Status.DesiredNumberScheduled))
			},
		},
		{
			ID: "FAB-02", Name: "Overlay wiring exists for every node", Layer: "fabric", DependsOn: []string{"FAB-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				internal, err := listCR(ctx, c, k, groupNet, "internalnodes")
				if err != nil {
					return warn("cannot list internalnodes: "+err.Error(), "")
				}
				nodes, err := k.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
				if err != nil {
					return warn("cannot list nodes: "+err.Error(), "")
				}
				have := map[string]bool{}
				for _, in := range internal {
					have[in.GetName()] = true
				}
				var missing []string
				physical := 0
				for _, n := range nodes.Items {
					if n.Labels["liqo.io/type"] == "virtual-node" {
						continue
					}
					physical++
					if !have[n.Name] {
						missing = append(missing, n.Name)
					}
				}
				if len(missing) > 0 {
					return fail("nodes without an InternalNode (no Geneve wiring): "+strings.Join(missing, ", "),
						"pods scheduled on these nodes cannot cross the tunnel — typical for recently added nodes; check liqo-fabric logs on them and controller-manager reconciliation")
				}
				return pass(fmt.Sprintf("InternalNode present for all %d physical nodes", physical))
			},
		},
		{
			ID: "FAB-04", Name: "Firewall configurations applied (incl. MSS clamping)", Layer: "fabric", DependsOn: []string{"FAB-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				fws, err := listCR(ctx, c, k, groupNet, "firewallconfigurations")
				if err != nil {
					return warn("cannot list firewallconfigurations: "+err.Error(), "")
				}
				if len(fws) == 0 {
					return warn("no FirewallConfiguration resources found",
						"MSS clamping ships as a FirewallConfiguration; its absence can cause MTU-style hangs (large responses stall) even when ping works")
				}
				hasClamp := false
				var evidence []string
				for _, fw := range fws {
					if strings.Contains(fw.GetName(), "mssclamp") {
						hasClamp = true
					}
					evidence = append(evidence, crName(fw))
				}
				if !hasClamp {
					return warn("no MSS-clamping FirewallConfiguration detected",
						"TCP sessions may hang on large payloads; verify Liqo's gw mss-clamp rules exist (helm template liqo-gw-mssclamp)", evidence...)
				}
				return pass(fmt.Sprintf("%d firewall configuration(s) present, MSS clamping included", len(fws)), evidence...)
			},
		},
	}
}
