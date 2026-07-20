package checks

import (
	"context"
	"fmt"
	"time"

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
				if total == 0 {
					return skip(fmt.Sprintf("no reflected endpoints exist yet in %d offloaded namespace(s) (no running services with remote backends)", len(offloaded)))
				}
				return pass(fmt.Sprintf("%d reflected endpoint address(es) checked, all routable", total))
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
					sawReady := false
					for _, cond := range n.Status.Conditions {
						if cond.Type != corev1.NodeReady {
							continue
						}
						sawReady = true
						if cond.Status != corev1.ConditionTrue {
							notReady = append(notReady, fmt.Sprintf("%s: Ready=%s (%s)", n.Name, cond.Status, cond.Message))
						}
					}
					if !sawReady {
						// No NodeReady condition at all is not "Ready" — the
						// virtual kubelet has not reported status yet.
						notReady = append(notReady, fmt.Sprintf("%s: no NodeReady condition reported yet (virtual kubelet still starting?)", n.Name))
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

func offloadingUsageChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "REF-03", Name: "Offloading usage (virtual node age & workload count)", Layer: "reflection",
			DependsOn: []string{"REF-02"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				nodes, err := k.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "liqo.io/type=virtual-node"})
				if err != nil {
					return warn("cannot list virtual nodes: "+err.Error(), "")
				}
				if len(nodes.Items) == 0 {
					return skip("no virtual nodes (offloading module not active on this side)")
				}
				now := time.Now()
				var evidence []string
				var idle []string
				for _, n := range nodes.Items {
					age := now.Sub(n.CreationTimestamp.Time)
					pods, err := k.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + n.Name})
					running := 0
					total := 0
					if err == nil {
						total = len(pods.Items)
						for _, p := range pods.Items {
							if p.Status.Phase == corev1.PodRunning {
								running++
							}
						}
					}
					evidence = append(evidence, fmt.Sprintf("%s: age %s, %d pod(s) scheduled (%d running)", n.Name, humanDuration(age), total, running))
					c.AddFact("virtual node age ("+n.Name+")", humanDuration(age), "kubectl get node "+n.Name)
					if age > time.Hour && running == 0 {
						idle = append(idle, n.Name)
					}
				}
				if len(idle) > 0 {
					return warn("virtual node(s) Ready but no pods currently scheduled on them",
						"the peering's data plane may be healthy but nothing is being offloaded right now — expected if you haven't deployed offloaded workloads yet",
						evidence...)
				}
				return pass(fmt.Sprintf("%d virtual node(s) actively running workloads", len(nodes.Items)), evidence...)
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
