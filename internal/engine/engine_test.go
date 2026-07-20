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

func TestMemoSupportsNestedCalls(t *testing.T) {
	c := NewCtx(fakeCluster("local"), nil, "", time.Second)
	done := make(chan string, 1)
	go func() {
		outer, _ := Memo(c, "outer", func() (string, error) {
			inner, _ := Memo(c, "inner", func() (string, error) { return "in", nil })
			return "out-" + inner, nil
		})
		done <- outer
	}()
	select {
	case got := <-done:
		if got != "out-in" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nested Memo deadlocked")
	}
}

func TestCheckTimeout(t *testing.T) {
	c := NewCtx(fakeCluster("local"), nil, "", 50*time.Millisecond)
	chk := Check{
		ID: "T", Name: "T", Layer: "env",
		Run: func(ctx context.Context, _ *Ctx) Result {
			<-ctx.Done()
			return Result{Status: Pass}
		},
	}
	results := Run(context.Background(), c, []Check{chk}, nil)
	// A timeout is inconclusive: Warn, not Fail — and it must not cascade.
	if results[0].Status != Warn {
		t.Fatalf("expected timeout Warn, got %s", results[0].Status)
	}
}

func TestTimeoutDoesNotSkipDependents(t *testing.T) {
	c := NewCtx(fakeCluster("local"), nil, "", 50*time.Millisecond)
	checks := []Check{
		{ID: "SLOW", Name: "SLOW", Layer: "env", Run: func(ctx context.Context, _ *Ctx) Result {
			<-ctx.Done()
			return Result{Status: Pass}
		}},
		mk("DEP", "gateway", Pass, "SLOW"),
	}
	results := Run(context.Background(), c, checks, nil)
	got := map[string]Status{}
	for _, r := range results {
		got[r.ID] = r.Status
	}
	if got["SLOW"] != Warn || got["DEP"] != Pass {
		t.Fatalf("timeout should warn without skipping dependents, got %v", got)
	}
}

func TestUnknownLayerSurfacesAsFailure(t *testing.T) {
	c := NewCtx(fakeCluster("local"), nil, "", time.Second)
	results := Run(context.Background(), c, []Check{mk("X", "tunnelz", Pass)}, nil)
	if len(results) != 1 || results[0].Status != Fail {
		t.Fatalf("unknown-layer check should be reported as Fail, got %+v", results)
	}
}

func TestDanglingDependencySurfacesAsFailure(t *testing.T) {
	c := NewCtx(fakeCluster("local"), nil, "", time.Second)
	results := Run(context.Background(), c, []Check{mk("Y", "env", Pass, "NOPE-99")}, nil)
	if len(results) != 1 || results[0].Status != Fail {
		t.Fatalf("dangling DependsOn should be reported as Fail, got %+v", results)
	}
}
