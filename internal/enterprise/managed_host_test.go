package enterprise

import (
	"os"
	"path/filepath"
	"testing"
)

// TestManagedHost_AgreesWithCheckDisableAllowed pins ManagedHost to the
// enforcement it describes. The BLOCK hints print "this rule cannot be
// disabled locally" exactly when ManagedHost is true (#4321), so it must say
// "managed" in exactly the states where CheckDisableAllowed refuses. That
// includes a corrupt managed.json, which #3620 reads as managed.
func TestManagedHost_AgreesWithCheckDisableAllowed(t *testing.T) {
	cases := []struct {
		name    string
		content *string // nil: no managed.json at all
		want    bool
	}{
		{"no managed.json", nil, false},
		{"managed: false", strPtr(`{"managed": false}`), false},
		{"managed: true", strPtr(`{"managed": true}`), true},
		{"corrupt file reads as managed (#3620)", strPtr(`{not json`), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			if c.content != nil {
				dir := filepath.Join(home, ".agentshield")
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "managed.json"), []byte(*c.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := ManagedHost(); got != c.want {
				t.Errorf("ManagedHost() = %v, want %v", got, c.want)
			}
			if refused := CheckDisableAllowed() != nil; refused != ManagedHost() {
				t.Errorf("CheckDisableAllowed refused=%v but ManagedHost=%v: the hint and the enforcement disagree", refused, ManagedHost())
			}
		})
	}
}

func strPtr(s string) *string { return &s }
