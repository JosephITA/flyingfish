package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/kube"
	corev1 "k8s.io/api/core/v1"
)

func tunnelChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "TUN-01", Name: "Connection resources report Connected", Layer: "tunnel", DependsOn: []string{"GW-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				conns, err := listCR(ctx, c, k, groupNet, "connections")
				if err != nil {
					return fail("cannot list connections: "+err.Error(), "")
				}
				if len(conns) == 0 {
					return fail("no Connection resource — the tunnel was never negotiated",
						"run `liqoctl network connect` (or `liqoctl peer`); check GW-02/GW-03 first")
				}
				var down, up []string
				for _, conn := range conns {
					val := nestedString(conn.Object, "status", "value")
					if strings.EqualFold(val, "Connected") {
						up = append(up, fmt.Sprintf("%s: %s", crName(conn), val))
					} else {
						down = append(down, fmt.Sprintf("%s: %q", crName(conn), val))
					}
				}
				if len(down) > 0 {
					return fail("tunnel not established",
						"work down the gateway layer: endpoint reachability (GW-02/03/04), UDP port open through firewalls, WireGuard keys (TUN-02). The Liqo FAQ has a UDP echo-server procedure to prove the UDP path outside WireGuard",
						append(down, up...)...)
				}
				return pass(fmt.Sprintf("%d connection(s) Connected", len(up)), up...)
			},
		},
		{
			ID: "TUN-02", Name: "WireGuard handshake fresh", Layer: "tunnel", DependsOn: []string{"GW-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				pods, err := gatewayPods(ctx, c, k)
				if err != nil || len(pods) == 0 {
					return skip("no gateway pods to exec into")
				}
				var stale, fresh, errs []string
				now := time.Now()
				for _, p := range pods {
					out, err := k.Exec(ctx, p.Namespace, p.Name, wgContainer(p.Spec.Containers), []string{"wg", "show", "all", "latest-handshakes"})
					if err != nil {
						errs = append(errs, fmt.Sprintf("%s/%s: %v", p.Namespace, p.Name, err))
						continue
					}
					for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
						fields := strings.Fields(line)
						if len(fields) < 3 {
							continue
						}
						epoch, _ := strconv.ParseInt(fields[len(fields)-1], 10, 64)
						if epoch == 0 {
							stale = append(stale, fmt.Sprintf("%s/%s: NO handshake ever completed on %s", p.Namespace, p.Name, fields[0]))
						} else if age := now.Sub(time.Unix(epoch, 0)); age > 3*time.Minute {
							stale = append(stale, fmt.Sprintf("%s/%s: last handshake %s ago", p.Namespace, p.Name, age.Round(time.Second)))
						} else {
							fresh = append(fresh, fmt.Sprintf("%s/%s: handshake %s ago", p.Namespace, p.Name, age.Round(time.Second)))
						}
					}
				}
				if len(stale) > 0 {
					return fail("WireGuard peers without a recent handshake",
						"no handshake ever → endpoint/port unreachable or key mismatch (stale PublicKey after gateway recreation; re-exchange with `liqoctl network connect`). Handshake stopped → UDP path broke (NAT mapping expired, firewall change)",
						append(stale, fresh...)...)
				}
				if len(fresh) == 0 {
					return warn("could not read WireGuard state from any gateway pod", "verify the wireguard container name and RBAC for pods/exec", errs...)
				}
				return pass("WireGuard handshakes are fresh", fresh...)
			},
		},
		{
			ID: "TUN-06", Name: "Tunnel uptime & data activity", Layer: "tunnel", DependsOn: []string{"GW-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				now := time.Now()
				var evidence []string

				conns, _ := listCR(ctx, c, k, groupNet, "connections")
				for _, conn := range conns {
					age := now.Sub(conn.GetCreationTimestamp().Time)
					evidence = append(evidence, fmt.Sprintf("%s: connection resource created %s ago", crName(conn), humanDuration(age)))
					c.AddFact("tunnel resource age ("+conn.GetName()+")", humanDuration(age), "")
					for _, cond := range conditionsAt(conn.Object, "status", "conditions") {
						if cond.HasTransition {
							evidence = append(evidence, fmt.Sprintf("  condition %s=%s for %s", cond.Type, cond.Status, humanDuration(now.Sub(cond.LastTransition))))
						}
					}
				}

				pods, err := gatewayPods(ctx, c, k)
				if err != nil || len(pods) == 0 {
					if len(evidence) == 0 {
						return skip("no gateway pods or connections to inspect")
					}
					return pass("tunnel resource age reported (gateway pods unavailable for traffic counters)", evidence...)
				}

				var totalRx, totalTx int64
				var haveCounters bool
				for _, p := range pods {
					start := p.CreationTimestamp.Time
					if p.Status.StartTime != nil {
						start = p.Status.StartTime.Time
					}
					uptime := now.Sub(start)
					evidence = append(evidence, fmt.Sprintf("%s/%s: gateway pod running for %s", p.Namespace, p.Name, humanDuration(uptime)))
					c.AddFact("gateway pod uptime ("+p.Name+")", humanDuration(uptime),
						fmt.Sprintf("kubectl -n %s get pod %s", p.Namespace, p.Name))

					out, err := k.Exec(ctx, p.Namespace, p.Name, wgContainer(p.Spec.Containers), []string{"wg", "show", "all", "transfer"})
					if err != nil {
						evidence = append(evidence, fmt.Sprintf("  transfer counters unavailable: %v", err))
						continue
					}
					for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
						fields := strings.Fields(line)
						if len(fields) < 2 {
							continue
						}
						rx, errR := strconv.ParseInt(fields[len(fields)-2], 10, 64)
						tx, errT := strconv.ParseInt(fields[len(fields)-1], 10, 64)
						if errR == nil && errT == nil {
							totalRx += rx
							totalTx += tx
							haveCounters = true
						}
					}
				}

				if !haveCounters {
					return warn("could not read WireGuard traffic counters", "verify RBAC for pods/exec and the wireguard container name", evidence...)
				}
				c.AddFact("tunnel data exchanged (rx/tx)", fmt.Sprintf("%s / %s", humanBytes(totalRx), humanBytes(totalTx)), "")
				evidence = append(evidence, fmt.Sprintf("total: %s received, %s sent (since the gateway pod last started — counters reset on restart)",
					humanBytes(totalRx), humanBytes(totalTx)))

				if totalRx == 0 && totalTx == 0 {
					return warn("tunnel is connected but zero bytes have been exchanged since the gateway pod started",
						"either the peering is brand new, idle, or genuinely unused — this alone doesn't mean it's broken (TUN-01/TUN-02 already cover liveness); confirm with an actual pod-to-pod test if you expected traffic",
						evidence...)
				}
				return pass(fmt.Sprintf("tunnel active: %s received / %s sent", humanBytes(totalRx), humanBytes(totalTx)), evidence...)
			},
		},
		{
			ID: "MTU-01", Name: "Tunnel MTU consistent", Layer: "tunnel", DependsOn: []string{"GW-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				localMTUs, evLocal := tunnelMTUs(ctx, c, cl(c.Local))
				evidence := evLocal
				if len(localMTUs) == 0 {
					return warn("could not read the tunnel interface MTU from any gateway pod", "", evidence...)
				}
				for _, m := range localMTUs {
					c.AddFact("tunnel MTU", fmt.Sprintf("%d", m),
						fmt.Sprintf("ping -c1 -M do -s %d <remote-pod-ip>   # run inside a pod; largest payload that must pass", m-28))
				}
				if c.Dual() {
					remoteMTUs, evRemote := tunnelMTUs(ctx, c, cl(c.Remote))
					evidence = append(evidence, evRemote...)
					if len(remoteMTUs) > 0 && !sameInts(localMTUs, remoteMTUs) {
						return fail(fmt.Sprintf("tunnel MTU mismatch between clusters: local %v vs remote %v — Liqo requires the same value on both sides", localMTUs, remoteMTUs),
							"set the same --mtu on both sides (liqoctl peer/network connect, default 1340) and recreate the connection",
							evidence...)
					}
				}
				for _, m := range localMTUs {
					if m < 1280 {
						return warn(fmt.Sprintf("tunnel MTU %d is unusually low — expect heavy fragmentation and poor throughput", m),
							"check the underlay path MTU; WireGuard overhead is 60B (IPv4) / 80B (IPv6) below the physical MTU", evidence...)
					}
				}
				detail := fmt.Sprintf("tunnel interface MTU %v", localMTUs)
				if !c.Dual() {
					detail += " (single-cluster mode: cannot verify the peer uses the same value — Liqo requires it)"
				}
				return pass(detail, evidence...)
			},
		},
		{
			ID: "TUN-05", Name: "Tunnel latency within bounds", Layer: "tunnel", DependsOn: []string{"TUN-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				conns, err := listCR(ctx, c, k, groupNet, "connections")
				if err != nil || len(conns) == 0 {
					return skip("no connections to measure")
				}
				var high, all []string
				for _, conn := range conns {
					lat := nestedString(conn.Object, "status", "latency", "value")
					if lat == "" {
						continue
					}
					all = append(all, fmt.Sprintf("%s: latency %s", crName(conn), lat))
					if d, err := time.ParseDuration(lat); err == nil && d > 200*time.Millisecond {
						high = append(high, fmt.Sprintf("%s: %s", crName(conn), lat))
					}
				}
				if len(all) == 0 {
					return skip("Connection resources expose no latency value on this Liqo version")
				}
				if len(high) > 0 {
					return warn("inter-gateway latency above 200ms (informational)",
						"expect slow cross-cluster calls; consider gateway placement closer to the peer", append(high, all...)...)
				}
				return pass("tunnel latency nominal (gateway pinger: 2s interval, status refresh 10s)", all...)
			},
		},
	}
}

// tunnelMTUs reads the MTU of every WireGuard interface inside the gateway
// pods of one cluster (via `wg show interfaces` + /sys/class/net/<if>/mtu).
func tunnelMTUs(ctx context.Context, c *engine.Ctx, k *kube.Cluster) ([]int, []string) {
	var mtus []int
	var evidence []string
	pods, err := gatewayPods(ctx, c, k)
	if err != nil {
		return nil, []string{fmt.Sprintf("%s: cannot list gateway pods: %v", k.Name, err)}
	}
	for _, p := range pods {
		ctr := wgContainer(p.Spec.Containers)
		ifaces, err := k.Exec(ctx, p.Namespace, p.Name, ctr, []string{"wg", "show", "interfaces"})
		if err != nil {
			evidence = append(evidence, fmt.Sprintf("%s %s/%s: %v", k.Name, p.Namespace, p.Name, err))
			continue
		}
		for _, iface := range strings.Fields(ifaces) {
			out, err := k.Exec(ctx, p.Namespace, p.Name, ctr, []string{"cat", "/sys/class/net/" + iface + "/mtu"})
			if err != nil {
				evidence = append(evidence, fmt.Sprintf("%s %s/%s: reading %s mtu: %v", k.Name, p.Namespace, p.Name, iface, err))
				continue
			}
			if m, err := strconv.Atoi(strings.TrimSpace(out)); err == nil {
				mtus = append(mtus, m)
				evidence = append(evidence, fmt.Sprintf("%s %s/%s: interface %s mtu %d", k.Name, p.Namespace, p.Name, iface, m))
			}
		}
	}
	return mtus, evidence
}

func sameInts(a, b []int) bool {
	set := map[int]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if !set[y] {
			return false
		}
	}
	return len(set) > 0
}

// wgContainer picks the WireGuard container of a gateway pod, falling back to
// the first container (custom gateway templates may differ).
func wgContainer(containers []corev1.Container) string {
	for _, ctr := range containers {
		if ctr.Name == "wireguard" {
			return ctr.Name
		}
	}
	if len(containers) > 0 {
		return containers[0].Name
	}
	return ""
}
