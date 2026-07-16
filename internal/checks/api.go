package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// identityEndpoint is a provider API-server endpoint extracted from an
// Identity kubeconfig secret in a tenant namespace.
type identityEndpoint struct {
	secret   string
	server   string
	certExp  time.Time
	hasCert  bool
}

func apiChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "FC-01", Name: "ForeignCluster module conditions", Layer: "api", DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				fcs, err := listCR(ctx, c, k, groupCore, "foreignclusters")
				if err != nil {
					return fail("cannot list foreignclusters: "+err.Error(), "check Liqo CRDs and RBAC")
				}
				if len(fcs) == 0 {
					return warn("no ForeignCluster found — no peering exists on this cluster",
						"establish a peering first: liqoctl peer --remote-kubeconfig <peer>")
				}
				var bad, seen []string
				for _, fc := range fcs {
					if c.Peer != "" && fc.GetName() != c.Peer {
						continue
					}
					seen = append(seen, fc.GetName())
					modules := nestedAny(fc.Object, "status", "modules")
					mmap, _ := modules.(map[string]any)
					for mod, v := range mmap {
						vm, _ := v.(map[string]any)
						conds, _ := vm["conditions"].([]any)
						for _, cd := range conds {
							cdm, _ := cd.(map[string]any)
							ctype, _ := cdm["type"].(string)
							cstatus, _ := cdm["status"].(string)
							msg, _ := cdm["message"].(string)
							if !isHealthyCondition(cstatus) {
								bad = append(bad, fmt.Sprintf("%s: module %s condition %s=%s (%s)",
									fc.GetName(), mod, ctype, cstatus, msg))
							}
						}
					}
				}
				if len(seen) == 0 {
					return warn(fmt.Sprintf("no ForeignCluster matches peer filter %q", c.Peer), "check --peer value; available: see kubectl get foreignclusters")
				}
				if len(bad) > 0 {
					return fail("ForeignCluster modules report unhealthy conditions",
						"the failing module tells you which layer to look at: networking → gateway/tunnel checks, authentication → api checks, offloading → virtual node",
						bad...)
				}
				return pass(fmt.Sprintf("all module conditions healthy on %d ForeignCluster(s)", len(seen)),
					seen...)
			},
		},
		{
			ID: "API-01", Name: "Provider API server reachable (control plane)", Layer: "api", DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				eps, err := identityEndpoints(ctx, c, cl(c.Local))
				if err != nil {
					return warn("cannot inspect Identity kubeconfig secrets: "+err.Error(), "")
				}
				if len(eps) == 0 {
					return skip("no Identity kubeconfig secrets found in tenant namespaces (nothing to test — this side may be the provider)")
				}
				var down, up []string
				for _, ep := range eps {
					if err := dialTLS(ctx, ep.server); err != nil {
						down = append(down, fmt.Sprintf("%s (%s): %v", ep.server, ep.secret, err))
					} else {
						up = append(up, ep.server)
					}
				}
				if len(down) > 0 {
					return fail("provider API server endpoint(s) unreachable from this machine",
						"note: tested from the machine running flyingfish, not from inside the cluster. If reachable in-cluster this may be a local network artifact; otherwise check firewalls / use in-band peering (liqoctl peer --in-band)",
						down...)
				}
				return pass("provider API endpoints reachable", up...)
			},
		},
		{
			ID: "API-02", Name: "In-band API proxy healthy", Layer: "api", DependsOn: []string{"ENV-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				dep, err := k.Clientset.AppsV1().Deployments(liqoNS).Get(ctx, "liqo-proxy", metav1.GetOptions{})
				if err != nil {
					return skip("liqo-proxy deployment not found (in-band peering not in use)")
				}
				want := int32(1)
				if dep.Spec.Replicas != nil {
					want = *dep.Spec.Replicas
				}
				if dep.Status.ReadyReplicas < want {
					return fail(fmt.Sprintf("liqo-proxy not ready (%d/%d)", dep.Status.ReadyReplicas, want),
						"in-band peering routes API traffic through this proxy over the tunnel; kubectl -n liqo logs deploy/liqo-proxy")
				}
				return pass("liqo-proxy ready (in-band control-plane path available)")
			},
		},
		{
			ID: "API-03", Name: "Identity certificates not expiring", Layer: "api", DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				eps, err := identityEndpoints(ctx, c, cl(c.Local))
				if err != nil || len(eps) == 0 {
					return skip("no Identity kubeconfig secrets to inspect")
				}
				var expiring []string
				now := time.Now()
				for _, ep := range eps {
					if !ep.hasCert {
						continue
					}
					left := ep.certExp.Sub(now)
					if left <= 0 {
						expiring = append(expiring, fmt.Sprintf("%s: client certificate EXPIRED %s", ep.secret, ep.certExp.Format(time.RFC3339)))
					} else if left < 30*24*time.Hour {
						expiring = append(expiring, fmt.Sprintf("%s: client certificate expires in %dd", ep.secret, int(left.Hours()/24)))
					}
				}
				if len(expiring) > 0 {
					return warn("Identity credentials near or past expiry",
						"renew the peering identity (re-run liqoctl peer or rotate the Identity resource)", expiring...)
				}
				return pass(fmt.Sprintf("%d identity credential(s) valid", len(eps)))
			},
		},
	}
}

func isHealthyCondition(status string) bool {
	switch strings.ToLower(status) {
	case "true", "established", "ready", "healthy":
		return true
	}
	return false
}

// identityEndpoints scans tenant namespaces for kubeconfig-bearing secrets and
// extracts the API server URL and client certificate expiry.
func identityEndpoints(ctx context.Context, c *engine.Ctx, k *kube.Cluster) ([]identityEndpoint, error) {
	return engine.Memo(c, "identityeps/"+k.Name, func() ([]identityEndpoint, error) {
		nss, err := tenantNamespaces(ctx, c, k)
		if err != nil {
			return nil, err
		}
		var out []identityEndpoint
		for _, ns := range nss {
			secrets, err := k.Clientset.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}
			for _, s := range secrets.Items {
				raw, ok := s.Data["kubeconfig"]
				if !ok {
					continue
				}
				cfg, err := clientcmd.Load(raw)
				if err != nil {
					continue
				}
				for _, cluster := range cfg.Clusters {
					ep := identityEndpoint{secret: ns + "/" + s.Name, server: cluster.Server}
					for _, auth := range cfg.AuthInfos {
						if exp, ok := certExpiry(auth.ClientCertificateData); ok {
							ep.certExp, ep.hasCert = exp, true
						}
					}
					out = append(out, ep)
				}
			}
		}
		return out, nil
	})
}

func certExpiry(pemData []byte) (time.Time, bool) {
	if len(pemData) == 0 {
		return time.Time{}, false
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return time.Time{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, false
	}
	return cert.NotAfter, true
}

// dialTLS tests TCP+TLS reachability of an https endpoint without verifying
// the certificate chain (we test the path, not the identity).
func dialTLS(ctx context.Context, server string) error {
	u, err := url.Parse(server)
	if err != nil {
		return err
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return err
	}
	return conn.Close()
}
