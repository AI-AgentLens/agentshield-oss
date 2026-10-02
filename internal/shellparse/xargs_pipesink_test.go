package shellparse

import (
	"reflect"
	"testing"
)

// TestXargsPipeSinkTargets pins #3992: xargs's own trailing command-line —
// its real target program and its own written flags — must be recoverable as
// a regex-match candidate, whether xargs is a pipe sink or the statement's
// leading word, without ever naming the dynamic stdin items xargs appends.
func TestXargsPipeSinkTargets(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		// The reported bypass (#3992): tar named only on xargs's own
		// command line, behind a pipe.
		{
			"pipe-sink-tar-to-command",
			`echo a.tar | xargs tar --to-command=sh -xf`,
			[]string{`tar --to-command=sh -xf`},
		},
		{
			"pipe-sink-with-find",
			`find . -name '*.tar' | xargs tar --to-command=sh -xf`,
			[]string{`tar --to-command=sh -xf`},
		},

		// xargs's own flags, value-taking and not, must be skipped without
		// swallowing the real target.
		{
			"value-flag-n",
			`find . | xargs -n1 tar --to-command=sh -xf`,
			[]string{`tar --to-command=sh -xf`},
		},
		{
			"value-flag-P-separate-token",
			`find . | xargs -P 4 tar --to-command=sh -xf`,
			[]string{`tar --to-command=sh -xf`},
		},
		{
			"flag-only-r",
			`find . | xargs -r tar --to-command=sh -xf`,
			[]string{`tar --to-command=sh -xf`},
		},
		{
			"attached-replace-str",
			`find . | xargs -I{} tar --to-command=sh -xf {}`,
			[]string{`tar --to-command=sh -xf {}`},
		},

		// xargs is not the statement's leading word only when it appears
		// after a pipe — a redirect-fed invocation with no pipe at all is
		// the same shape, and must resolve identically.
		{
			"no-pipe-redirect-fed",
			`xargs tar --to-command=sh -xf a.tar < list.txt`,
			[]string{`tar --to-command=sh -xf a.tar < list.txt`},
		},

		// A privilege wrapper before xargs must not hide it.
		{
			"sudo-xargs",
			`find . | sudo xargs tar --to-command=sh -xf`,
			[]string{`tar --to-command=sh -xf`},
		},

		// Must-NOT: when the token after xargs's own flags is a benign
		// program and "tar" is merely ITS argument, the extracted target
		// must name that program, not tar — so an anchored `^tar\b` rule
		// still correctly does not fire against it.
		{
			"tar-is-an-argument-not-the-target",
			`find . | xargs echo tar --to-command=sh`,
			[]string{`echo tar --to-command=sh`},
		},

		// Benign xargs usage still produces a (harmless) candidate — this
		// function makes no safety judgment, it only recovers text.
		{
			"benign-xargs-curl",
			`cat urls.txt | xargs -P4 curl -O`,
			[]string{`curl -O`},
		},

		// No xargs anywhere — no candidates.
		{"no-xargs", `echo a.tar | cat`, nil},
		{"plain-tar", `tar -czf out.tar.gz dist/`, nil},

		// Bare xargs with no target: nothing to recover.
		{"bare-xargs", `find . | xargs`, nil},
		{"xargs-flags-only", `find . | xargs -0 -r`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := XargsPipeSinkTargets(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("XargsPipeSinkTargets(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}
