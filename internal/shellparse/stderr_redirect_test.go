package shellparse

import "testing"

// StripStderrRedirects (#4610) removes only redirects that leave stdout where
// it was. The "kept" rows are load-bearing: a redirect that MOVES stdout
// means the pipe downstream no longer receives the data, so removing it
// would invent an adjacency the shell does not perform.
func TestStripStderrRedirects(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// stripped: stderr to a file, every spelling
		{`zzsrc a 2>/dev/null | zzsink b`, `zzsrc a | zzsink b`},
		{`zzsrc a 2>>err.log | zzsink b`, `zzsrc a | zzsink b`},
		{`zzsrc a 2>|err.log | zzsink b`, `zzsrc a | zzsink b`},
		{`zzsrc a 2>/dev/null|zzsink b`, `zzsrc a|zzsink b`},
		// stripped: fd duplication
		{`zzsrc a 2>&1 | zzsink b`, `zzsrc a | zzsink b`},
		{`zzsrc a >&2 | zzsink b`, `zzsrc a | zzsink b`},
		{`zzsrc a 1>&2 | zzsink b`, `zzsrc a | zzsink b`},
		{`zzsrc a 3>&- | zzsink b`, `zzsrc a | zzsink b`},
		{`zzsrc a 0<&3 | zzsink b`, `zzsrc a | zzsink b`},
		// |& is 2>&1 | in bash and zsh
		{`zzsrc a |& zzsink b`, `zzsrc a | zzsink b`},
		// position: a leading redirect takes the blank after it
		{`2>/dev/null zzsrc a | zzsink b`, `zzsrc a | zzsink b`},
		{`zzsrc 2>/dev/null a | zzsink b`, `zzsrc a | zzsink b`},
		// several, and inside a compound command and a substitution
		{`zzsrc a 2>/dev/null 2>&1 | zzsink b 2>/dev/null`, `zzsrc a | zzsink b`},
		{`{ zzsrc a 2>/dev/null; } | zzsink b`, `{ zzsrc a; } | zzsink b`},
		{`x=$(zzsrc a 2>&1 | zzsink b)`, `x=$(zzsrc a | zzsink b)`},
		// separators stay exactly as written
		{`cd /tmp && zzsrc a 2>/dev/null | zzsink b; echo done`, `cd /tmp && zzsrc a | zzsink b; echo done`},

		// kept: these move stdout, nothing to do
		{`zzsrc a | zzsink b`, ``},
		{`zzsrc a >out.txt | zzsink b`, ``},
		{`zzsrc a 1>out.txt | zzsink b`, ``},
		{`zzsrc a &>/dev/null | zzsink b`, ``},
		{`zzsrc a &>>log | zzsink b`, ``},
		{`zzsrc a < in.txt | zzsink b`, ``},
		{`zzsrc a <<'EOF' | zzsink b
body 2>/dev/null
EOF`, ``},
		// kept: quoted text is not a redirect
		{`echo "zzsrc a 2>/dev/null | zzsink b"`, ``},
		{`git commit -m 'run zzsrc 2>&1 | zzsink'`, ``},
		// does not parse: nothing
		{`zzsrc a 2>/dev/null | (`, ``},
	} {
		if got := StripStderrRedirects(tc.in); got != tc.want {
			t.Errorf("StripStderrRedirects(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
		}
	}
}
