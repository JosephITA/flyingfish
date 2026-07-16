package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/kube"
	"github.com/JosephITA/flyingfish/internal/netutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func gatewayChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "GW-01", Name: "Gateway pods running", Layer: "gateway", DependsOn: []string{"ENV-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				pods, err := gatewayPods(ctx, c, cl(c.Local))
				if err != nil {
					return fail("cannot list gateway pods: "+err.Error(), "")
				}
				if len(pods) == 0 {
					return fail("no gateway pods found in any tenant namespace",
						"networking module never started; run `liqoctl network connect` or check FC-01 / controller-manager logs")
				}
				var bad []string
				for _, p := range pods {
					if p.Status.Phase != corev1.PodRunning || !podReady(&p) {
						bad = append(bad, fmt.Sprintf("%s/%s phase=%s ready=%v", p.Namespace, p.Name, p.Status.Phase, podReady(&p)))
					}
				}
				if len(bad) > 0 {
					return fail("gateway pod(s) not running/ready",
						"kubectl -n <tenant-ns> describe pod <gw-pod>; check node pressure and image pulls", bad...)
				}
				return pass(fmt.Sprintf("%d gateway pod(s) running and ready", len(pods)))
			},
		},
		{
			ID: "GW-02", Name: "Gateway server service exposed", Layer: "gateway", DependsOn: []string{"GW-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				gws, err := listCR(ctx, c, k, groupNet, "gatewayservers")
				if err != nil || len(gws) == 0 {
					return skip("no GatewayServer on this cluster (it acts as gateway client; run flyingfish against the peer to test its exposure)")
				}
				svcs, err := gatewayServices(ctx, c, k)
				if err != nil {
					return fail("cannot list services in tenant namespaces: "+err.Error(), "")
				}
				var problems, evidence []string
				for _, s := range svcs {
					switch s.Spec.Type {
					case corev1.ServiceTypeLoadBalancer:
						if len(s.Status.LoadBalancer.Ingress) == 0 {
							problems = append(problems, fmt.Sprintf("%s/%s: LoadBalancer stuck <pending>", s.Namespace, s.Name))
						} else {
							for _, ing := range s.Status.LoadBalancer.Ingress {
								addr := ing.IP
								if addr == "" {
									addr = ing.Hostname
								}
								evidence = append(evidence, fmt.Sprintf("%s/%s: LoadBalancer %s", s.Namespace, s.Name, addr))
								if netutil.IsPrivate(addr) {
									problems = append(problems, fmt.Sprintf("%s/%s: LoadBalancer IP %s is private — unreachable from a peer outside this network", s.Namespace, s.Name, addr))
								}
							}
						}
					case corev1.ServiceTypeNodePort:
						nodes, _ := k.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
						allPrivate := true
						for _, n := range nodes.Items {
							for _, a := range n.Status.Addresses {
								if a.Type == corev1.NodeExternalIP && !netutil.IsPrivate(a.Address) {
									allPrivate = false
								}
							}
						}
						for _, p := range s.Spec.Ports {
							evidence = append(evidence, fmt.Sprintf("%s/%s: NodePort %d/%s", s.Namespace, s.Name, p.NodePort, p.Protocol))
						}
						if allPrivate && len(nodes.Items) > 0 {
							problems = append(problems, fmt.Sprintf("%s/%s: NodePort service but no node has a public ExternalIP — peer must share this private network", s.Namespace, s.Name))
						}
					}
				}
				if len(svcs) == 0 {
					return fail("GatewayServer exists but no gateway Service found in tenant namespaces",
						"the gateway controller did not create/label the service; check liqo-controller-manager logs")
				}
				if len(problems) > 0 {
					return fail("gateway server service is not (or not usefully) exposed",
						"LoadBalancer pending → no LB controller or your cloud LB cannot do UDP (DigitalOcean: UDP health checks unsupported — use NodePort). Private-only addresses → open/assign a public endpoint or peer over a shared private network",
						append(problems, evidence...)...)
				}
				return pass("gateway service exposed", evidence...)
			},
		},
		{
			ID: "GW-03", Name: "Advertised gateway endpoint matches the Service", Layer: "gateway", DependsOn: []string{"GW-02"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				gws, err := listCR(ctx, c, k, groupNet, "gatewayservers")
				if err != nil || len(gws) == 0 {
					return skip("no GatewayServer on this cluster")
				}
				var evidence, problems []string
				for _, gw := range gws {
					addrs := extractStrings(nestedAny(gw.Object, "status", "endpoint", "addresses"))
					port, hasPort := nestedInt(gw.Object, "status", "endpoint", "port")
					if len(addrs) == 0 || !hasPort {
						problems = append(problems, fmt.Sprintf("%s: status.endpoint not populated (addresses=%v port set=%v)", crName(gw), addrs, hasPort))
						continue
					}
					evidence = append(evidence, fmt.Sprintf("%s advertises %v:%d", crName(gw), addrs, port))
					for _, a := range addrs {
						c.AddFact("gateway server endpoint (WireGuard, UDP)",
							fmt.Sprintf("%s:%d", a, port),
							fmt.Sprintf("nc -vzu %s %d   # UDP: no ICMP-unreachable = port likely open", a, port))
					}
				}
				if len(problems) > 0 {
					return fail("GatewayServer has no advertised endpoint — clients have nothing valid to dial",
						"usually follows a GW-02 exposure problem; if the Service looks fine, restart liqo-controller-manager and re-check",
						append(problems, evidence...)...)
				}
				return pass("all GatewayServers advertise an endpoint", evidence...)
			},
		},
		{
			ID: "GW-04", Name: "Client dials the endpoint the server advertises", Layer: "gateway", NeedsDual: true,
			DependsOn: []string{"GW-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				res := compareClientServer(ctx, c, cl(c.Local), cl(c.Remote))
				if res != nil {
					return *res
				}
				res = compareClientServer(ctx, c, cl(c.Remote), cl(c.Local))
				if res != nil {
					return *res
				}
				return skip("no GatewayClient/GatewayServer pair found across the two clusters")
			},
		},
		{
			ID: "GW-05", Name: "Gateway UDP port reachable from this machine", Layer: "gateway", DependsOn: []string{"GW-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				gws, err := listCR(ctx, c, k, groupNet, "gatewayservers")
				if err != nil || len(gws) == 0 {
					return skip("no GatewayServer on this cluster (nothing to probe)")
				}
				var refused, silent, responded, evidence []string
				for _, gw := range gws {
					port, hasPort := nestedInt(gw.Object, "status", "endpoint", "port")
					if !hasPort {
						continue
					}
					for _, a := range extractStrings(nestedAny(gw.Object, "status", "endpoint", "addresses")) {
						addr := fmt.Sprintf("%s:%d", a, port)
						state, perr := netutil.ProbeUDP(addr, 3*time.Second)
						evidence = append(evidence, fmt.Sprintf("udp probe %s → %s", addr, state))
						switch state {
						case netutil.UDPRefused:
							refused = append(refused, addr)
						case netutil.UDPResponded:
							responded = append(responded, addr)
						case netutil.UDPError:
							evidence = append(evidence, fmt.Sprintf("  probe error: %v", perr))
						default:
							silent = append(silent, addr)
						}
					}
				}
				if len(refused) > 0 {
					return fail("gateway UDP endpoint actively refused (ICMP port unreachable) — nothing is listening there from this network's viewpoint",
						"the advertised endpoint is wrong or a firewall/LB rejects UDP; verify the Service and any NAT in front of it",
						evidence...)
				}
				if len(silent)+len(responded) == 0 {
					return skip("no advertised endpoints to probe")
				}
				return pass("no ICMP-unreachable from the gateway endpoint (WireGuard is silent by design, so this proves the path does not actively reject UDP; TUN-02's handshake is the definitive proof)",
					evidence...)
			},
		},
		{
			ID: "GW-06", Name: "Gateway stability (restarts)", Layer: "gateway", DependsOn: []string{"GW-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				pods, err := gatewayPods(ctx, c, cl(c.Local))
				if err != nil || len(pods) == 0 {
					return skip("no gateway pods to inspect")
				}
				var flapping []string
				for _, p := range pods {
					for _, cs := range p.Status.ContainerStatuses {
						if cs.RestartCount > 3 {
							flapping = append(flapping, fmt.Sprintf("%s/%s container %s restarted %d times", p.Namespace, p.Name, cs.Name, cs.RestartCount))
						}
					}
				}
				if len(flapping) > 0 {
					return warn("gateway containers are restarting — the tunnel flaps with them",
						"check container logs and resources; note the Helm default is a single gateway replica (SPOF)", flapping...)
				}
				return pass("gateway pods stable (no excessive restarts)")
			},
		},
	}
}

func podReady(p *corev1.Pod) bool {
	for _, cond := range p.Status.Conditions {
		if cond.Type == corev1.PodReady {
			return cond.Status == corev1.ConditionTrue
		}
	}
	return false
}

// gatewayPods finds the per-peer gateway pods in tenant namespaces.
func gatewayPods(ctx context.Context, c *engine.Ctx, k *kube.Cluster) ([]corev1.Pod, error) {
	return engine.Memo(c, "gwpods/"+k.Name, func() ([]corev1.Pod, error) {
		nss, err := tenantNamespaces(ctx, c, k)
		if err != nil {
			return nil, err
		}
		var out []corev1.Pod
		for _, ns := range nss {
			pods, err := k.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}
			for _, p := range pods.Items {
				if p.Labels["networking.liqo.io/component"] == "gateway" || strings.HasPrefix(p.Name, "gw-") {
					out = append(out, p)
				}
			}
		}
		return out, nil
	})
}

// gatewayServices lists LoadBalancer/NodePort UDP services in tenant namespaces.
func gatewayServices(ctx context.Context, c *engine.Ctx, k *kube.Cluster) ([]corev1.Service, error) {
	return engine.Memo(c, "gwsvcs/"+k.Name, func() ([]corev1.Service, error) {
		nss, err := tenantNamespaces(ctx, c, k)
		if err != nil {
			return nil, err
		}
		var out []corev1.Service
		for _, ns := range nss {
			svcs, err := k.Clientset.CoreV1().Services(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}
			for _, s := range svcs.Items {
				if s.Spec.Type == corev1.ServiceTypeLoadBalancer || s.Spec.Type == corev1.ServiceTypeNodePort {
					out = append(out, s)
				}
			}
		}
		return out, nil
	})
}

// compareClientServer checks every GatewayClient on clientSide against the
// endpoints advertised by GatewayServers on serverSide.
func compareClientServer(ctx context.Context, c *engine.Ctx, clientSide, serverSide *kube.Cluster) *engine.Result {
	clients, err := listCR(ctx, c, clientSide, groupNet, "gatewayclients")
	if err != nil || len(clients) == 0 {
		return nil
	}
	servers, _ := listCR(ctx, c, serverSide, groupNet, "gatewayservers")

	serverAddrs := map[string]bool{}
	var advertised []string
	for _, s := range servers {
		port, _ := nestedInt(s.Object, "status", "endpoint", "port")
		for _, a := range extractStrings(nestedAny(s.Object, "status", "endpoint", "addresses")) {
			key := fmt.Sprintf("%s:%d", a, port)
			serverAddrs[key] = true
			advertised = append(advertised, key)
		}
	}

	var mismatches, evidence []string
	for _, cli := range clients {
		port, _ := nestedInt(cli.Object, "spec", "endpoint", "port")
		addrs := extractStrings(nestedAny(cli.Object, "spec", "endpoint", "addresses"))
		matched := false
		for _, a := range addrs {
			key := fmt.Sprintf("%s:%d", a, port)
			evidence = append(evidence, fmt.Sprintf("client %s on %s dials %s", crName(cli), clientSide.Name, key))
			if serverAddrs[key] {
				matched = true
			}
		}
		if !matched && len(serverAddrs) > 0 {
			mismatches = append(mismatches, fmt.Sprintf("client %s dials %v:%d but %s advertises %v",
				crName(cli), addrs, port, serverSide.Name, advertised))
		}
	}
	if len(mismatches) > 0 {
		r := fail("GatewayClient endpoint does not match what the GatewayServer advertises",
			"the classic stale-endpoint failure: the server Service changed (new LB IP / NodePort) after peering. Re-run `liqoctl network connect` or patch the GatewayClient spec.endpoint",
			append(mismatches, evidence...)...)
		return &r
	}
	if len(evidence) > 0 {
		r := pass(fmt.Sprintf("gateway client on %s dials an endpoint advertised by %s", clientSide.Name, serverSide.Name), evidence...)
		return &r
	}
	return nil
}

func extractStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case string:
		out = append(out, t)
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
