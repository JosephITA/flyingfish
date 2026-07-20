package cli

import "testing"

func TestCheckValidatesOutputFormat(t *testing.T) {
	cmd := newCheck()
	if err := cmd.Flags().Set("output", "yaml"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.PreRunE(cmd, nil); err == nil {
		t.Fatal("expected an error for --output yaml")
	}
	for _, ok := range []string{"text", "json"} {
		if err := cmd.Flags().Set("output", ok); err != nil {
			t.Fatal(err)
		}
		if err := cmd.PreRunE(cmd, nil); err != nil {
			t.Fatalf("--output %s should be accepted: %v", ok, err)
		}
	}
}
