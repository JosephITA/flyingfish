package checks

import (
	"context"
	"fmt"
	"regexp"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/netutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var bareIPRe = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

func ipamChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "IPAM-02", Name: "Remapped peer CIDRs do not collide with local infrastructure", Layer: "ipam",
			DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				configs, err := listCR(ctx, c, k, groupNet, "configurations")
				if err != nil {
					return fail("cannot list configurations: "+err.Error(), "")
				}
				if len(configs) == 0 {
					return skip("no Configuration resources — networking not negotiated yet")
				}
				nodes, _ := k.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})

				var problems, evidence []string
				for _, cfg := range configs {
					localCIDRs := netutil.ExtractCIDRs(nestedAny(cfg.Object, "spec", "local"))
					remapped := netutil.ExtractCIDRs(nestedAny(cfg.Object, "status", "remote"))
					evidence = append(evidence,
						fmt.Sprintf("%s — %s, %s", crName(cfg),
							netutil.HumanList("local", localCIDRs),
							netutil.HumanList("peer remapped", remapped)))
					for _, r := range remapped {
						c.AddFact("peer CIDR as seen from this cluster (remapped)", r,
							"ping -c1 <ip-in-this-range>   # run inside a local pod; keep the remote pod's host bits, swap the prefix")
					}

					// The whole point of remapping is that the peer's remapped view
					// must not intersect anything real on this side.
					if a, b, hit := netutil.FirstOverlap(remapped, localCIDRs); hit {
						problems = append(problems, fmt.Sprintf("%s: peer remapped CIDR %s overlaps local CIDR %s", crName(cfg), a, b))
					}
					if nodes != nil {
						for _, n := range nodes.Items {
							for _, addr := range n.Status.Addresses {
								if !bareIPRe.MatchString(addr.Address) {
									continue
								}
								for _, r := range remapped {
									if netutil.Contains(r, addr.Address) {
										problems = append(problems, fmt.Sprintf("%s: node %s address %s falls inside peer remapped CIDR %s — traffic to that range blackholes",
											crName(cfg), n.Name, addr.Address, r))
									}
								}
							}
						}
					}
				}
				if len(problems) > 0 {
					return fail("CIDR collision between the peer's remapped ranges and local infrastructure",
						"add the colliding local ranges to Liqo's ipam.reservedSubnets at install time so IPAM remaps the peer elsewhere, then re-peer",
						append(problems, evidence...)...)
				}
				return pass("no collision between remapped peer CIDRs and local pod/node networks", evidence...)
			},
		},
		{
			ID: "IPAM-04", Name: "IP remappings allocated", Layer: "ipam", DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				ips, err := listCR(ctx, c, k, groupIPAM, "ips")
				if err != nil {
					return warn("cannot list ips.ipam.liqo.io: "+err.Error(), "")
				}
				if len(ips) == 0 {
					return skip("no IP remapping resources (none needed unless using in-band proxy or external hosts)")
				}
				var unallocated []string
				for _, ip := range ips {
					status := nestedAny(ip.Object, "status")
					m, _ := status.(map[string]any)
					if len(m) == 0 || !bareIPRe.MatchString(fmt.Sprint(m)) {
						unallocated = append(unallocated, crName(ip))
					}
				}
				if len(unallocated) > 0 {
					return fail("IP resources without an allocated remapped address",
						"liqo-ipam failed the allocation; check liqo-ipam logs (exhausted externalCIDR?)", unallocated...)
				}
				return pass(fmt.Sprintf("%d IP remapping(s) allocated", len(ips)))
			},
		},
	}
}
