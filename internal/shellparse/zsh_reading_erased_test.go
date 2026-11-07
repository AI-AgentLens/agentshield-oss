package shellparse

import (
	"reflect"
	"testing"
)

// ZshReadingErased (#4631 review round 1): the reading is exactly
// ZshReading's, and erased is the source text of each statement the reading
// writes `:`. Inert stand-ins only.
func TestZshReadingErased(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		erased   []string
	}{
		{"bash-valid", `: ${HOME}; echo B1`, nil},
		{"rejected by both", `echo "unterminated`, nil},
		{"short for", `for i (1) echo B4`, nil},
		{"translated, nothing erased", `: ${(U)HOME}; echo B1`, nil},
		{"brace group, nothing erased", `{ echo B2 }`, nil},
		{"floating-point statement", `: $((1.5)); echo g`, []string{`: $((1.5))`}},
		{"in a pipeline", `echo g | : $((1.5))`, []string{`: $((1.5))`}},
		{"assignment prefix erases the whole statement", `X=$((1.5)) echo g; echo h`, []string{`X=$((1.5)) echo g`}},
		{"glob qualifier", `echo g nomatch(N); echo h`, []string{`echo g nomatch(N)`}},
		{"two erased statements", `: $((1.5)); echo g; : $((2.5))`, []string{`: $((1.5))`, `: $((2.5))`}},
		{"erased statement keeps its own text only", `X=$((1.5)) echo g > out.txt; echo h`, []string{`X=$((1.5)) echo g > out.txt`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reading, erased := ZshReadingErased(tc.in)
			if want := ZshReading(tc.in); reading != want {
				t.Errorf("ZshReadingErased(%q) reading = %q, want ZshReading's %q", tc.in, reading, want)
			}
			if reading == "" && erased != nil {
				t.Errorf("ZshReadingErased(%q) erased = %q with no reading", tc.in, erased)
			}
			if !reflect.DeepEqual(erased, tc.erased) {
				t.Errorf("ZshReadingErased(%q) erased = %q, want %q", tc.in, erased, tc.erased)
			}
		})
	}
}
