package shellparse

import (
	"reflect"
	"testing"
)

// TestZshOperandWordsRecorded pins what unwrapping a zsh construct sets aside
// (#4597, Codex pass 1 on #4627): repeat's count and the assignments skipped
// after it are kept on the segment, so normalize can still read them the way
// main read them as RawWords of an unknown "repeat" executable. Other
// wrappers' operands are not recorded: main never scanned them.
func TestZshOperandWordsRecorded(t *testing.T) {
	tests := []struct {
		cmd  string
		want []string
	}{
		{"repeat 3 echo M", []string{"3"}},
		{"repeat ~/.aws/credentials true", []string{"~/.aws/credentials"}},
		{"repeat 2 FOO=1 echo M", []string{"2", "FOO=1"}},
		{"noglob repeat 2 echo M", []string{"2"}},
		{"noglob echo M", nil},
		{"- echo M", nil},
		{"=echo M", nil},
		{"env FOO=1 echo M", nil},
		{"sudo -u root echo M", nil},
		{"nohup repeat 4 echo M", []string{"4"}},
		// Codex pass 2: main stopped at the zsh word or =word, so it also
		// scanned the operands of wrappers further in.
		{"noglob env -u ~/.aws/credentials true", []string{"-u", "~/.aws/credentials"}},
		{"repeat 1 env -u X true", []string{"1", "-u", "X"}},
		{"=env -u ~/.aws/credentials true", []string{"-u", "~/.aws/credentials"}},
		{"nohup noglob env -u X true", []string{"-u", "X"}},
		{"nohup env -u X true", nil},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			pc := Parse(tt.cmd, 2)
			if pc == nil || len(pc.Segments) == 0 {
				t.Fatalf("Parse(%q) produced %v", tt.cmd, pc)
			}
			if got := pc.Segments[0].ZshOperandWords; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse(%q).ZshOperandWords = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}
