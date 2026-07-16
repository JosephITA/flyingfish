package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JosephITA/flyingfish/internal/engine"
)

func sample() []engine.Result {
	return []engine.Result{
		{ID: "ENV-01", Name: "Liqo core components healthy", Layer: "env", Status: engine.Pass,
			Detail: "12 deployments and 1 daemonsets ready in namespace 'liqo'"},
		{ID: "GW-02", Name: "Gateway server service exposed", Layer: "gateway", Status: engine.Fail,
			Detail:      "gateway server service is not (or not usefully) exposed",
			Remediation: "LoadBalancer pending → no LB controller or your cloud LB cannot do UDP",
			Evidence:    []string{"liqo-tenant-milan/gw-milan: LoadBalancer stuck <pending>"}},
		{ID: "TUN-01", Name: "Connection resources report Connected", Layer: "tunnel", Status: engine.Skip,
			Detail: "skipped: dependency GW-02 failed"},
	}
}

func TestRendererShowsDiagnosisAndRemediation(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf, false, false)
	r.Banner("consumer", "provider", "test")
	for _, res := range sample() {
		r.Emit(res)
	}
	r.Summary(sample())
	out := buf.String()
	for _, want := range []string{"GATEWAY EXPOSURE", "GW-02", "diagnosis", "LoadBalancer pending", "1 passed", "1 failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	t.Log("\n" + out)
}

func TestJSONContract(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample(), "test"); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Results   []engine.Result `json:"results"`
		Diagnosis *engine.Result  `json:"diagnosis"`
		Summary   struct{ Pass, Warn, Fail, Skip int }
	}
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Diagnosis == nil || payload.Diagnosis.ID != "GW-02" {
		t.Fatalf("diagnosis should be GW-02, got %+v", payload.Diagnosis)
	}
	if payload.Summary.Fail != 1 || payload.Summary.Pass != 1 || payload.Summary.Skip != 1 {
		t.Fatalf("bad summary: %+v", payload.Summary)
	}
}

func TestExitCodes(t *testing.T) {
	if ExitCode(sample()) != 2 {
		t.Error("fail should map to exit 2")
	}
	if ExitCode([]engine.Result{{Status: engine.Warn}}) != 1 {
		t.Error("warn should map to exit 1")
	}
	if ExitCode([]engine.Result{{Status: engine.Pass}}) != 0 {
		t.Error("pass should map to exit 0")
	}
}
