package checks

import (
	"context"
	"fmt"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/netutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func reflectionChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "REF-01", Name: "Reflected endpoints fall inside remapped CIDRs", Layer: "reflection",
			DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				offloaded, err := offloadedNamespaces(ctx, c)
				if err != nil || len(offloaded) == 0 {
					return skip("no offloaded namespaces to inspect")
				}
				configs, _ := listCR(ctx, c, k, groupNet, "configurations")
				var localCIDRs, remoteCIDRs []string
				for _, cfg := range configs {
					localCIDRs = append(localCIDRs, netutil.ExtractCIDRs(nestedAny(cfg.Object, "spec", "local"))...)
					remoteCIDRs = append(remoteCIDRs, netutil.ExtractCIDRs(nestedAny(cfg.Object, "status", "remote"))...)
				}
				if len(remoteCIDRs) == 0 {
					return skip("no remapped peer CIDRs known yet")
				}
				var orphans []string
				total := 0
				for _, ns := range offloaded {
					epss, err := k.Clientset.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{})
					if err != nil {
						continue
					}
					for _, eps := range epss.Items {
						for _, ep := range eps.Endpoints {
							for _, addr := range ep.Addresses {
								total++
								if inAny(localCIDRs, addr) || inAny(remoteCIDRs, addr) {
									continue
								}
								orphans = append(orphans, fmt.Sprintf("%s/%s endpoint %s is in neither the local CIDRs nor the peer's remapped CIDRs", ns, eps.Name, addr))
							}
						}
					}
				}
				if len(orphans) > 0 {
					return fail("reflected endpoints point at unreachable addresses (remapping drift)",
						"the network configuration changed after reflection; unoffload/re-offload the namespace or re-peer so EndpointSlices are re-translated",
						orphans...)
				}
				return pass(fmt.Sprintf("%d endpoint address(es) in offloaded namespaces are all routable", total))
			},
		},
		{
			ID: "REF-02", Name: "Virtual nodes Ready", Layer: "reflection", DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				nodes, err := k.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "liqo.io/type=virtual-node"})
				if err != nil {
					return warn("cannot list virtual nodes: "+err.Error(), "")
				}
				if len(nodes.Items) == 0 {
					return skip("no virtual nodes (offloading module not active on this side)")
				}
				var notReady []string
				for _, n := range nodes.Items {
					for _, cond := range n.Status.Conditions {
						if cond.Type == corev1.NodeReady && cond.Status != corev1.ConditionTrue {
							notReady = append(notReady, fmt.Sprintf("%s: Ready=%s (%s)", n.Name, cond.Status, cond.Message))
						}
					}
				}
				if len(notReady) > 0 {
					return fail("virtual node(s) NotReady — offloaded pods will not run",
						"usually a control-plane problem, not fabric: re-check API-01/API-03 and the virtual-kubelet pod logs in the tenant namespace",
						notReady...)
				}
				return pass(fmt.Sprintf("%d virtual node(s) Ready", len(nodes.Items)))
			},
		},
	}
}

func inAny(cidrs []string, ip string) bool {
	for _, c := range cidrs {
		if netutil.Contains(c, ip) {
			return true
		}
	}
	return false
}
