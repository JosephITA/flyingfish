package checks

import "testing"

func TestSameInts(t *testing.T) {
	cases := []struct {
		name string
		a, b []int
		want bool
	}{
		{"identical", []int{1340}, []int{1340}, true},
		{"same set different order", []int{1340, 1420}, []int{1420, 1340}, true},
		{"duplicates collapse", []int{1340, 1340}, []int{1340}, true},
		{"remote superset", []int{1340}, []int{1340, 1420}, false},
		// The regression: asymmetric subset check used to pass this.
		{"local superset", []int{1340, 1420}, []int{1340}, false},
		{"disjoint", []int{1340}, []int{1420}, false},
		{"empty", nil, []int{1340}, false},
		{"both empty", nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameInts(tc.a, tc.b); got != tc.want {
				t.Errorf("sameInts(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			// Set equality must be symmetric.
			if got := sameInts(tc.b, tc.a); got != tc.want {
				t.Errorf("sameInts(%v, %v) = %v, want %v (symmetry)", tc.b, tc.a, got, tc.want)
			}
		})
	}
}
