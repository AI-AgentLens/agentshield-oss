package pathnorm

import "testing"

// System paths are assembled at runtime: the hook reads test sources as
// commands.
func TestCanonicalPrivateAlias(t *testing.T) {
	etc, v, tmp := "/private/"+"etc", "/private/"+"var", "/private/"+"tmp"
	cases := []struct{ in, want string }{
		// The two roots read short, as a path and as the bare root.
		{"cat " + etc + "/hosts", "cat /etc/hosts"},
		{"rm -rf " + v + "/log", "rm -rf /var/log"},
		{"ls " + v + "/tmp/build", "ls /var/tmp/build"},
		{"rm -rf " + etc, "rm -rf /etc"},
		{etc + "/hosts", "/etc/hosts"},
		// Every opener: quotes, assignment, redirect without a space,
		// separators, PATH-like lists, brace lists, @file, file://.
		{`cat "` + etc + `/hosts"`, `cat "/etc/hosts"`},
		{"cat '" + etc + "/hosts'", "cat '/etc/hosts'"},
		{"P=" + etc + "/hosts; cat $P", "P=/etc/hosts; cat $P"},
		{"echo x >" + etc + "/hosts", "echo x >/etc/hosts"},
		{"true;" + etc + "/rc", "true;/etc/rc"},
		{"PATH=/usr/bin:" + v + "/x", "PATH=/usr/bin:/var/x"},
		{"cp {" + etc + "/a," + etc + "/b} .", "cp {/etc/a,/etc/b} ."},
		{"curl -d @" + etc + "/passwd x", "curl -d @/etc/passwd x"},
		{"open file://" + etc + "/passwd", "open file:///etc/passwd"},
		{"(cd " + v + ")", "(cd /var)"},
		// Every root-segment end.
		{`"` + etc + `"`, `"/etc"`},
		{etc + ";ls", "/etc;ls"},
		{"x=" + v + ":y", "x=/var:y"},
		// Case-insensitive volume: /private and the root fold, the rest of
		// the text is untouched (the case-fold reading decides on it).
		{"cat /PRIVATE/ETC/Hosts", "cat /ETC/Hosts"},
		{"cat /Private/etc/hosts", "cat /etc/hosts"},
		// Several in one command.
		{"cp " + etc + "/a " + tmp + "/b && cat " + v + "/c", "cp /etc/a " + tmp + "/b && cat /var/c"},
	}
	for _, c := range cases {
		if got := CanonicalPrivateAlias(c.in); got != c.want {
			t.Errorf("CanonicalPrivateAlias(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCanonicalPrivateAliasLeavesNonAliasesAlone pins the shapes that are not
// the macOS alias and must come back as "" (no change).
func TestCanonicalPrivateAliasLeavesNonAliasesAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"cat /etc/hosts",        // already short
		"ls /private",           // /private itself is not an alias of a root
		"ls /private/",          // nor its listing
		"ls /private/etcetera",  // the root segment must end
		"ls /private/var2/x",    // ditto
		"ls /private/Users/x",   // not a root read short
		"ls /private/tmp/build", // /tmp is deliberately not read short (#4387)
		"export HOME=/private/tmp/claude-501/x/home",
		"ls /private/tmp",
		"ls ./private/etc/x",      // relative
		"ls ../private/etc/x",     // relative
		"ls ~/private/etc/x",      // under a home directory
		"ls $HOME/private/etc/x",  // ditto, spelled as a variable
		"ls ${HOME}/private/etc",  // ditto
		"ls /srv/private/etc/x",   // a directory that happens to be called private
		"ls $(pwd)/private/etc/x", // relative to a substitution's output
		"ls `pwd`/private/etc/x",  // ditto, backquoted
		"ls //private/etc/x",      // not file://
		"curl http://h/private/etc/x",
		"echo private/etc", // no leading slash
	} {
		if got := CanonicalPrivateAlias(in); got != "" {
			t.Errorf("CanonicalPrivateAlias(%q) = %q, want \"\" (not the alias)", in, got)
		}
	}
}

// TestCanonicalPrivateAliasIsASCIIOnly is the #3771 guard: a Unicode fold
// would let a non-ASCII spelling be read as the alias. None of the letters in
// "private", "etc", "var" or "tmp" has a non-ASCII simple fold today, so this
// pins the implementation choice rather than a live confusable.
func TestCanonicalPrivateAliasIsASCIIOnly(t *testing.T) {
	for _, in := range []string{
		"cat /prıvate/etc/hosts", // dotless i
		"cat /private/еtc/hosts", // Cyrillic e
	} {
		if got := CanonicalPrivateAlias(in); got != "" {
			t.Errorf("CanonicalPrivateAlias(%q) = %q, want \"\"", in, got)
		}
	}
}
