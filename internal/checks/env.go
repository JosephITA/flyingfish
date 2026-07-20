package checks

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/kube"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var liqoGroups = []string{groupCore, groupNet, groupIPAM, groupAuth, groupOffload}

func envChecks() []engine.Check {
	return []engine.Check{
		{
			ID: "ENV-01", Name: "Liqo core components healthy", Layer: "env",
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				deps, err := k.Clientset.AppsV1().Deployments(liqoNS).List(ctx, metav1.ListOptions{})
				if err != nil {
					return fail("cannot list deployments in namespace 'liqo': "+err.Error(),
						"verify Liqo is installed (helm list -n liqo) and the kubeconfig has read access")
				}
				if len(deps.Items) == 0 {
					return fail("no deployments found in namespace 'liqo'",
						"install Liqo: https://docs.liqo.io/en/v1.2.0/installation/install.html")
				}
				var unhealthy []string
				for _, d := range deps.Items {
					want := int32(1)
					if d.Spec.Replicas != nil {
						want = *d.Spec.Replicas
					}
					if d.Status.ReadyReplicas < want {
						unhealthy = append(unhealthy, fmt.Sprintf("deployment %s: %d/%d ready", d.Name, d.Status.ReadyReplicas, want))
					}
				}
				dss, err := k.Clientset.AppsV1().DaemonSets(liqoNS).List(ctx, metav1.ListOptions{})
				if err == nil {
					for _, ds := range dss.Items {
						if ds.Status.NumberReady < ds.Status.DesiredNumberScheduled {
							unhealthy = append(unhealthy, fmt.Sprintf("daemonset %s: %d/%d ready",
								ds.Name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled))
						}
					}
				}
				if len(unhealthy) > 0 {
					return fail("Liqo workloads are not fully ready",
						"kubectl -n liqo get pods; inspect the failing pods' logs (crd-replicator down silently stalls peering negotiation)",
						unhealthy...)
				}
				return pass(fmt.Sprintf("%d deployments and %d daemonsets ready in namespace 'liqo'", len(deps.Items), len(dss.Items)))
			},
		},
		{
			ID: "ENV-02", Name: "Liqo versions match between clusters", Layer: "env", NeedsDual: true,
			DependsOn: []string{"ENV-01"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				vLocal, err1 := liqoVersion(ctx, cl(c.Local))
				vRemote, err2 := liqoVersion(ctx, cl(c.Remote))
				if err1 != nil || err2 != nil {
					return warn("could not determine the Liqo version on both clusters", "",
						fmt.Sprintf("local: %v %v / remote: %v %v", vLocal, err1, vRemote, err2))
				}
				if vLocal != vRemote {
					return fail(fmt.Sprintf("version mismatch: local=%s remote=%s (unsupported by Liqo)", vLocal, vRemote),
						"align both clusters to the same Liqo version (upgrade requires unpeer + reinstall)")
				}
				return pass("both clusters run Liqo " + vLocal)
			},
		},
		{
			ID: "ENV-03", Name: "Liqo CRD groups served", Layer: "env",
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				var missing []string
				for _, g := range liqoGroups {
					if !k.HasGroup(g) {
						missing = append(missing, g)
					}
				}
				if len(missing) > 0 {
					return fail("Liqo API groups missing: "+strings.Join(missing, ", "),
						"broken or partial install; reinstall Liqo CRDs (helm upgrade --install)")
				}
				return pass("all Liqo API groups served", liqoGroups...)
			},
		},
		{
			ID: "ENV-04", Name: "No stale peering debris", Layer: "env", DependsOn: []string{"ENV-03"},
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				var debris []string
				nss, err := k.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
				if err == nil {
					for _, ns := range nss.Items {
						if strings.HasPrefix(ns.Name, "liqo-tenant-") && ns.DeletionTimestamp != nil {
							debris = append(debris, "namespace "+ns.Name+" stuck terminating")
						}
					}
				}
				if fcs, err := listCR(ctx, c, k, groupCore, "foreignclusters"); err == nil {
					for _, fc := range fcs {
						if fc.GetDeletionTimestamp() != nil {
							debris = append(debris, "foreigncluster "+fc.GetName()+" stuck terminating")
						}
					}
				}
				if len(debris) > 0 {
					return warn("leftover resources from a previous peering detected",
						"clean up with `liqoctl network reset` / force-unpeer procedure (Liqo FAQ) before re-peering",
						debris...)
				}
				return pass("no terminating tenant namespaces or foreignclusters")
			},
		},
		{
			ID: "ENV-05", Name: "Node kernels support nftables (>= 5.10)", Layer: "env",
			Run: func(ctx context.Context, c *engine.Ctx) engine.Result {
				k := cl(c.Local)
				nodes, err := k.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
				if err != nil {
					return warn("cannot list nodes: "+err.Error(), "")
				}
				var old []string
				physical := 0
				for _, n := range nodes.Items {
					if n.Labels["liqo.io/type"] == "virtual-node" {
						continue
					}
					physical++
					if kv := n.Status.NodeInfo.KernelVersion; kernelTooOld(kv) {
						old = append(old, fmt.Sprintf("%s: kernel %s", n.Name, kv))
					}
				}
				if len(old) > 0 {
					return warn("nodes below Liqo's minimum kernel 5.10 (nftables features)",
						"upgrade the node OS/kernel; Liqo's firewall rules may silently fail on these nodes", old...)
				}
				return pass(fmt.Sprintf("all %d physical nodes at kernel >= 5.10", physical))
			},
		},
	}
}

var kernelRe = regexp.MustCompile(`^(\d+)\.(\d+)`)

func kernelTooOld(v string) bool {
	m := kernelRe.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major < 5 || (major == 5 && minor < 10)
}

// liqoVersion extracts the controller-manager image tag as the install version.
func liqoVersion(ctx context.Context, kc *kube.Cluster) (string, error) {
	dep, err := kc.Clientset.AppsV1().Deployments(liqoNS).Get(ctx, "liqo-controller-manager", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	for _, ctr := range dep.Spec.Template.Spec.Containers {
		if tag, ok := imageTag(ctr.Image); ok {
			return tag, nil
		}
	}
	return "", fmt.Errorf("no tagged image on liqo-controller-manager (digest-pinned or untagged)")
}

// imageTag extracts the tag from a container image reference. A tag colon only
// counts after the last slash (the registry host may carry a port), and a
// digest suffix (img@sha256:…) is stripped first. Reports false when no usable
// tag is present — a digest fragment is not a version.
func imageTag(image string) (string, bool) {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[i+1:], true
	}
	return "", false
}
