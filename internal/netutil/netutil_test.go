package netutil

import "testing"

func TestOverlaps(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"10.244.0.0/16", "10.244.128.0/17", true},
		{"10.244.0.0/16", "10.245.0.0/16", false},
		{"10.70.0.0/16", "10.70.0.0/16", true},
		{"not-a-cidr", "10.0.0.0/8", false},
	}
	for _, tc := range cases {
		if got := Overlaps(tc.a, tc.b); got != tc.want {
			t.Errorf("Overlaps(%s,%s)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestExtractCIDRs(t *testing.T) {
	obj := map[string]any{
		"cidr": map[string]any{
			"pod":      []any{map[string]any{"cidr": "10.71.0.0/18"}},
			"external": "10.81.0.0/16",
		},
		"noise": "hello 300.1.1.1/16 world",
	}
	got := ExtractCIDRs(obj)
	want := map[string]bool{"10.71.0.0/18": true, "10.81.0.0/16": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected CIDR %s", g)
		}
	}
}

func TestContains(t *testing.T) {
	if !Contains("10.71.0.0/18", "10.71.1.7") {
		t.Error("10.71.1.7 should be inside 10.71.0.0/18")
	}
	if Contains("10.71.0.0/18", "10.72.0.1") {
		t.Error("10.72.0.1 should be outside 10.71.0.0/18")
	}
}

func TestIsPrivate(t *testing.T) {
	if !IsPrivate("192.168.1.10") || IsPrivate("52.11.22.33") || IsPrivate("my-lb.example.com") {
		t.Error("IsPrivate misclassification")
	}
}
