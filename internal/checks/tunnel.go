package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/JosephITA/flyingfish/internal/engine"
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
