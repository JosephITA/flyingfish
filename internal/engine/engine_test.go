package engine

import (
	"context"
	"testing"
	"time"
)

type fakeCluster string

func (f fakeCluster) DisplayName() string { return string(f) }
func (f fakeCluster) IsNil() bool         { return false }

func mk(id, layer string, st Status, deps ...string) Check {
	return Check{
		ID: id, Name: id, Layer: layer, DependsOn: deps,
		Run: func(context.Context, *Ctx) Result { return Result{Status: st} },
	}
}

func TestDependencyFailureSkipsDependents(t *testing.T) {
	c := NewCtx(fakeCluster("local"), nil, "", time.Second)
	checks := []Check{
		mk("A", "env", Fail),
		mk("B", "gateway", Pass, "A"),
		mk("C", "tunnel", Pass),
	}
	results := Run(context.Background(), c, checks, nil)
	got := map[string]Status{}
	for _, r := range results {
		got[r.ID] = r.Status
	}
	if got["A"] != Fail || got["B"] != Skip || got["C"] != Pass {
		t.Fatalf("unexpected statuses: %v", got)
	}
}

func TestDualOnlyChecksSkipInSingleMode(t *testing.T) {
	c := NewCtx(fakeCluster("local"), nil, "", time.Second)
	chk := mk("D", "gateway", Pass)
	chk.NeedsDual = true
	results := Run(context.Background(), c, []Check{chk}, nil)
	if results[0].Status != Skip {
		t.Fatalf("expected Skip in single-cluster mode, got %s", results[0].Status)
	}
}

func TestDiagnosisPicksFirstFailInLayerOrder(t *testing.T) {
	results := []Result{
		{ID: "W", Layer: "env", Status: Warn},
		{ID: "F1", Layer: "gateway", Status: Fail},
		{ID: "F2", Layer: "tunnel", Status: Fail},
	}
	d := Diagnosis(results)
	if d == nil || d.ID != "F1" {
		t.Fatalf("expected F1 as diagnosis, got %+v", d)
	}
}

func TestCheckTimeout(t *testing.T) {
	c := NewCtx(fakeCluster("local"), nil, "", 50*time.Millisecond)
	chk := Check{
		ID: "T", Name: "T", Layer: "env",
		Run: func(ctx context.Context, _ *Ctx) Result {
			<-ctx.Done()
			time.Sleep(time.Hour) // never returns in time
			return Result{Status: Pass}
		},
	}
	results := Run(context.Background(), c, []Check{chk}, nil)
	if results[0].Status != Fail {
		t.Fatalf("expected timeout Fail, got %s", results[0].Status)
	}
}
