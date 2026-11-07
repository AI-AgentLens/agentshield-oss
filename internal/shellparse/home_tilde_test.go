package shellparse

import "testing"

// HomeTildeReading (#4596) rewrites only the tilde prefixes bash and zsh
// expand: word-initial, unquoted, the prefix up to the first `/`.
func TestHomeTildeReading(t *testing.T) {
	const login, cwd = "zzme", "/zzhome/zzme"
	for _, tc := range []struct{ in, home, want string }{
		// ~<login>, written as the packs spell it
		{`cat ~zzme/.zzcred`, "~", `cat ~/.zzcred`},
		{`ls ~zzme`, "~", `ls ~`},
		{`cp ~zzme/.zzcred /tmp/x`, "~", `cp ~/.zzcred /tmp/x`},
		{`X=~zzme/.zzcred; cat $X`, "~", `X=~/.zzcred; cat $X`},
		{`cat < ~zzme/.zzcred`, "~", `cat < ~/.zzcred`},
		{`echo $(cat ~zzme/.zzcred)`, "~", `echo $(cat ~/.zzcred)`},
		// ~<login> when the account home is not $HOME: the absolute home
		{`cat ~zzme/.zzcred`, "/zzacct/zzme", `cat /zzacct/zzme/.zzcred`},
		// ~+ is $PWD
		{`cat ~+/.zzcred`, "~", `cat /zzhome/zzme/.zzcred`},
		{`ls ~+`, "~", `ls /zzhome/zzme`},

		// not expanded by the shell: left alone
		{`cat ~/.zzcred`, "~", ``},
		{`cat ~other/.zzcred`, "~", ``},
		{`cat ~-/.zzcred`, "~", ``},
		{`cat "~zzme/.zzcred"`, "~", ``},
		{`cat '~zzme'/.zzcred`, "~", ``},
		{`cat ~zz"me"/.zzcred`, "~", ``},
		{`cat x~zzme/.zzcred`, "~", ``},
		{`echo "see ~+/notes"`, "~", ``},
		{"cat <<EOF\n~zzme/.zzcred\nEOF", "~", ``},
		{`cat ~zzme/.zzcred | (`, "~", ``},
	} {
		if got := HomeTildeReading(tc.in, login, tc.home, cwd); got != tc.want {
			t.Errorf("HomeTildeReading(%q, home=%q)\n got: %q\nwant: %q", tc.in, tc.home, got, tc.want)
		}
	}
	if got := HomeTildeReading(`cat ~+/.zzcred`, login, "~", "rel/dir"); got != "" {
		t.Errorf("relative cwd: got %q, want no rewrite of ~+", got)
	}
	if got := HomeTildeReading(`cat ~zzme/.zzcred`, "", "", cwd); got != "" {
		t.Errorf("unknown account: got %q, want no rewrite of ~<login>", got)
	}
}
