package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func findCheck(t *testing.T, all []engine.Check, id string) engine.Check {
	t.Helper()
	for _, chk := range all {
		if chk.ID == id {
			return chk
		}
	}
	t.Fatalf("check %s not found", id)
	return engine.Check{}
}

func kernelNode(name, kernel string, virtual bool) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if virtual {
		n.Labels = map[string]string{"liqo.io/type": "virtual-node"}
	}
	n.Status.NodeInfo.KernelVersion = kernel
	return n
}

func TestENV05CountsOnlyPhysicalNodes(t *testing.T) {
	k := &kube.Cluster{Name: "test", Clientset: fake.NewSimpleClientset(
		kernelNode("p1", "6.1.0", false),
		kernelNode("p2", "5.15.0", false),
		// Old kernel, but virtual: excluded from both the check and the count.
		kernelNode("vk-milan", "5.4.0", true),
	)}
	c := engine.NewCtx(k, nil, "", 5*time.Second)
	res := findCheck(t, envChecks(), "ENV-05").Run(context.Background(), c)
	if res.Status != engine.Pass {
		t.Fatalf("expected Pass, got %s: %s", res.Status, res.Detail)
	}
	if !strings.Contains(res.Detail, "all 2 physical nodes") {
		t.Errorf("pass message should count only physical nodes, got %q", res.Detail)
	}
}

func TestImageTag(t *testing.T) {
	cases := []struct {
		image, want string
		ok          bool
	}{
		{"liqo/liqo-controller-manager:v1.2.3", "v1.2.3", true},
		{"registry.example.com:5000/liqo:v1", "v1", true},
		{"liqo@sha256:abc123", "", false},     // digest-pinned: a digest is not a version
		{"liqo:v1@sha256:abc123", "v1", true}, // tag + digest: the tag wins
		{"registry:5000/liqo", "", false},     // a registry port is not a tag
		{"liqo", "", false},
	}
	for _, tc := range cases {
		got, ok := imageTag(tc.image)
		if ok != tc.ok || got != tc.want {
			t.Errorf("imageTag(%q) = %q,%v want %q,%v", tc.image, got, ok, tc.want, tc.ok)
		}
	}
}
