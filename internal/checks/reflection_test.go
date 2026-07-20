package checks

import (
	"context"
	"testing"
	"time"

	"github.com/JosephITA/flyingfish/internal/engine"
	"github.com/JosephITA/flyingfish/internal/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func virtualNode(name string, conds ...corev1.NodeCondition) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"liqo.io/type": "virtual-node"}},
		Status:     corev1.NodeStatus{Conditions: conds},
	}
}

func TestREF02Readiness(t *testing.T) {
	ready := corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionTrue}
	notReady := corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionFalse, Message: "vk down"}
	cases := []struct {
		name string
		node *corev1.Node
		want engine.Status
	}{
		{"ready condition", virtualNode("vk-a", ready), engine.Pass},
		{"not ready condition", virtualNode("vk-b", notReady), engine.Fail},
		// Regression: a node with NO NodeReady condition used to pass.
		{"no conditions at all", virtualNode("vk-c"), engine.Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := &kube.Cluster{Name: "test", Clientset: fake.NewSimpleClientset(tc.node)}
			c := engine.NewCtx(k, nil, "", 5*time.Second)
			res := findCheck(t, reflectionChecks(), "REF-02").Run(context.Background(), c)
			if res.Status != tc.want {
				t.Fatalf("got %s (%s), want %s", res.Status, res.Detail, tc.want)
			}
		})
	}
}
