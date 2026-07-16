// Package kube wraps access to one cluster. Liqo CRDs are read through the
// dynamic client with discovery-based GVR resolution (spec §4: no compile-time
// dependency on Liqo's Go types, so the tool tolerates version drift).
package kube

import (
	"context"
	"fmt"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Cluster struct {
	Name       string
	Config     *rest.Config
	Clientset  kubernetes.Interface
	Dynamic    dynamic.Interface
	Discovery  discovery.DiscoveryInterface

	mu   sync.Mutex
	gvrs map[string]schema.GroupVersionResource
}

func (c *Cluster) DisplayName() string { return c.Name }
func (c *Cluster) IsNil() bool         { return c == nil }

// Connect builds a Cluster from a kubeconfig path and optional context name.
func Connect(kubeconfig, contextName, label string) (*Cluster, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	cfg, err := loader.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig for %s cluster: %w", label, err)
	}
	name := contextName
	if name == "" {
		if raw, err := loader.RawConfig(); err == nil {
			name = raw.CurrentContext
		}
	}
	if name == "" {
		name = label
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Cluster{
		Name:      name,
		Config:    cfg,
		Clientset: cs,
		Dynamic:   dyn,
		Discovery: cs.Discovery(),
		gvrs:      map[string]schema.GroupVersionResource{},
	}, nil
}

// GVR resolves a group+resource pair to its preferred served version via
// discovery, caching the result. Returns an error if the CRD is not installed.
func (c *Cluster) GVR(group, resource string) (schema.GroupVersionResource, error) {
	key := group + "/" + resource
	c.mu.Lock()
	if gvr, ok := c.gvrs[key]; ok {
		c.mu.Unlock()
		return gvr, nil
	}
	c.mu.Unlock()

	lists, err := c.Discovery.ServerPreferredResources()
	// Partial discovery failures are common (broken aggregated APIs); use what we got.
	if lists == nil && err != nil {
		return schema.GroupVersionResource{}, err
	}
	for _, list := range lists {
		gv, gvErr := schema.ParseGroupVersion(list.GroupVersion)
		if gvErr != nil || gv.Group != group {
			continue
		}
		for _, r := range list.APIResources {
			if r.Name == resource {
				gvr := schema.GroupVersionResource{Group: group, Version: gv.Version, Resource: resource}
				c.mu.Lock()
				c.gvrs[key] = gvr
				c.mu.Unlock()
				return gvr, nil
			}
		}
	}
	return schema.GroupVersionResource{}, fmt.Errorf("resource %s.%s not served by the cluster (CRD missing?)", resource, group)
}

// HasGroup reports whether any API group with the given name is served.
func (c *Cluster) HasGroup(group string) bool {
	groups, err := c.Discovery.ServerGroups()
	if err != nil || groups == nil {
		return false
	}
	for _, g := range groups.Groups {
		if g.Name == group {
			return true
		}
	}
	return false
}

// List lists a Liqo custom resource across all namespaces (or one, if ns != "").
func (c *Cluster) List(ctx context.Context, group, resource, ns string) ([]unstructured.Unstructured, error) {
	gvr, err := c.GVR(group, resource)
	if err != nil {
		return nil, err
	}
	var list *unstructured.UnstructuredList
	if ns == "" {
		list, err = c.Dynamic.Resource(gvr).List(ctx, metav1.ListOptions{})
	} else {
		list, err = c.Dynamic.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// TenantNamespaces returns the liqo tenant namespaces (one per peer).
func (c *Cluster) TenantNamespaces(ctx context.Context) ([]string, error) {
	nss, err := c.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ns := range nss.Items {
		if _, ok := ns.Labels["liqo.io/tenant-namespace"]; ok || strings.HasPrefix(ns.Name, "liqo-tenant-") {
			out = append(out, ns.Name)
		}
	}
	return out, nil
}
