package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/netutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func cniChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "CNI-01", Name: "CNI known-caveat scan", Layer: "cni",
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				dss, err := k.Clientset.AppsV1().DaemonSets("kube-system").List(ctx, metav1.ListOptions{})
				if err != nil {
					return skip("cannot list kube-system daemonsets: " + err.Error())
				}
				var warns, evidence []string
				var allNames []string
				cni := "unknown"
				for _, ds := range dss.Items {
					name := ds.Name
					allNames = append(allNames, name)
					switch {
					case strings.Contains(name, "calico-node"):
						cni = "calico"
						method := ""
						for _, ctr := range ds.Spec.Template.Spec.Containers {
							for _, env := range ctr.Env {
								if env.Name == "IP_AUTODETECTION_METHOD" {
									method = env.Value
								}
							}
						}
						evidence = append(evidence, "calico IP_AUTODETECTION_METHOD="+method)
						if !strings.Contains(method, "skip-interface") {
							warns = append(warns, "Calico may grab Liqo-created interfaces for BGP autodetection; set IP_AUTODETECTION_METHOD=skip-interface=liqo.*")
						}
					case strings.Contains(name, "cilium"):
						cni = "cilium"
						cm, err := k.Clientset.CoreV1().ConfigMaps("kube-system").Get(ctx, "cilium-config", metav1.GetOptions{})
						if err == nil {
							kpr := cm.Data["kube-proxy-replacement"]
							evidence = append(evidence, "cilium kube-proxy-replacement="+kpr)
							if kpr == "true" || kpr == "strict" {
								warns = append(warns, "Cilium kube-proxy replacement (eBPF/socket-LB) can bypass the nftables rules Liqo installs; if cross-cluster service traffic misbehaves, test with socket-LB scoped down")
							}
						}
					case strings.Contains(name, "flannel"):
						cni = "flannel"
					case strings.Contains(name, "weave"):
						cni = "weave"
					case strings.Contains(name, "antrea"):
						cni = "antrea"
					case strings.Contains(name, "kube-router"):
						cni = "kube-router"
					}
				}
				if cni == "unknown" {
					// Don't shrug — hand over the raw daemonset names so
					// someone who knows their own cluster can ID it in 2 seconds.
					evidence = append([]string{"couldn't fingerprint the CNI from known patterns (calico/cilium/flannel/weave/antrea/kube-router)"}, evidence...)
					if len(allNames) > 0 {
						evidence = append(evidence, "kube-system daemonsets present: "+strings.Join(allNames, ", "))
					} else {
						evidence = append(evidence, "no daemonsets found in kube-system at all")
					}
					return warn("could not identify the CNI in use — none of the known interference patterns could be checked",
						"identify your CNI from the daemonset list above and check it manually for Liqo interference (interface autodetection grabbing liqo* devices, eBPF/kube-proxy-replacement bypassing nftables)",
						evidence...)
				}
				evidence = append([]string{"detected CNI: " + cni}, evidence...)
				if len(warns) > 0 {
					return warn("CNI configuration has known Liqo interference patterns", strings.Join(warns, " | "), evidence...)
				}
				return pass("no known CNI caveats detected", evidence...)
			},
		},
		{
			ID: "CNI-02", Name: "NetworkPolicies vs remapped peer CIDRs", Layer: "cni", DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				offloaded, err := offloadedNamespaces(ctx, c)
				if err != nil {
					return skip("cannot determine offloaded namespaces: " + err.Error())
				}
				if len(offloaded) == 0 {
					return skip("no offloaded namespaces yet")
				}
				configs, _ := listCR(ctx, c, k, groupNet, "configurations")
				var remapped []string
				for _, cfg := range configs {
					remapped = append(remapped, netutil.ExtractCIDRs(nestedAny(cfg.Object, "status", "remote"))...)
				}
				var suspicious []string
				for _, ns := range offloaded {
					pols, err := k.Clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
					if err != nil {
						continue
					}
					for _, p := range pols.Items {
						suspicious = append(suspicious, fmt.Sprintf("%s/%s", ns, p.Name))
					}
				}
				if len(suspicious) > 0 {
					return warn("NetworkPolicies exist in offloaded namespaces — remote pods have IPs outside the local pod CIDR, so podSelector-based allows will NOT match them",
						fmt.Sprintf("audit these policies and allow the peer's remapped CIDRs via ipBlock: %v", remapped),
						suspicious...)
				}
				return pass(fmt.Sprintf("no NetworkPolicies in %d offloaded namespace(s)", len(offloaded)))
			},
		},
	}
}

func offloadedNamespaces(ctx context.Context, c *engine.Ctx) ([]string, error) {
	k := cl(c.Local)
	return engine.Memo(c, "offloadedns/"+k.Name, func() ([]string, error) {
		items, err := listCR(ctx, c, k, groupOffload, "namespaceoffloadings")
		if err != nil {
			return nil, err
		}
		var out []string
		for _, it := range items {
			out = append(out, it.GetNamespace())
		}
		return out, nil
	})
}
