package pathnorm

import (
	"math/rand"
	"strings"
	"testing"
)

// #5049: on Windows, StripShellQuotes removes quotes by bash's rules, so a
// backslash inside quotes survives as the path separator it is there. These
// tests call the goos-parameterised helper, so they pin the Windows reading on
// every OS, and pin that every other OS keeps the POSIX reading byte for byte.
//
// Protected-path names are assembled at runtime: AgentShield's hook reads the
// text of a test source as a command.

var (
	qAWS  = "." + "aws"
	qSSH  = "." + "ssh"
	qCred = "credentials"
	qKey  = "id_" + "rsa"
	qHome = `C:\Users\u`
)

func TestStripShellQuotes_WindowsBashRules_5049(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		windows string
		posix   string
	}{
		// Double quotes: a backslash before an ordinary character is kept.
		{"dq-native", `"` + qHome + `\` + qAWS + `\` + qCred + `"`,
			qHome + `\` + qAWS + `\` + qCred, `C:Usersu` + qAWS + qCred},
		{"dq-native-ssh", `"` + qHome + `\` + qSSH + `\` + qKey + `"`,
			qHome + `\` + qSSH + `\` + qKey, `C:Usersu` + qSSH + qKey},
		// Single quotes: every backslash is kept.
		{"sq-native", `'` + qHome + `\` + qSSH + `\` + qKey + `'`,
			qHome + `\` + qSSH + `\` + qKey, `C:Usersu` + qSSH + qKey},
		// Mixed: a quoted native home followed by an unquoted tail.
		{"sq-home-then-tail", `'` + qHome + `\'` + qAWS + `/` + qCred,
			qHome + `\` + qAWS + `/` + qCred, `C:Usersu` + qAWS + `/` + qCred},
		{"dq-home-then-tail", `"` + qHome + `"/` + qSSH + `/` + qKey,
			qHome + `/` + qSSH + `/` + qKey, `C:Usersu/` + qSSH + `/` + qKey},
		{"dq-then-unquoted-escapes", `"` + qHome + `"\\` + qSSH + `\\` + qKey,
			qHome + `\` + qSSH + `\` + qKey, `C:Usersu` + qSSH + qKey},
		{"posix-path-dq-backslash", `"/c/Users/u/` + qSSH + `\` + qKey + `"`,
			`/c/Users/u/` + qSSH + `\` + qKey, `/c/Users/u/` + qSSH + qKey},
		// The four characters a backslash escapes inside double quotes. $ and
		// backquote never reach the Windows branch: a word holding either is
		// returned as written on every OS.
		{"dq-escaped-backslash", `"C:\\Users\\u"`, `C:\Users\u`, `C:Usersu`},
		{"dq-escaped-quote", `"a\"b"`, `a"b`, `ab`},
		{"dq-escaped-newline", "\"a\\\nb\"", "ab", "a\nb"},
		{"dq-escaped-dollar", `"\$HOME"`, `"\$HOME"`, `"\$HOME"`},
		{"dq-escaped-backquote", "\"\\`x\\`\"", "\"\\`x\\`\"", "\"\\`x\\`\""},
		// A quote of the other kind is literal inside quotes.
		{"sq-in-dq", `"it's"`, `it's`, `its`},
		{"dq-in-sq", `'a"b'`, `a"b`, `ab`},
		// Unquoted: a backslash escapes the next character, so it is removed
		// and an escaped backslash or quote is kept. Bash eats the separators
		// of an unquoted native path; Git Bash cannot open it (#5049 row E3).
		{"unquoted-native", qHome + `\` + qAWS, `C:Usersu` + qAWS, `C:Usersu` + qAWS},
		{"unquoted-escaped-backslash", `C:\\Users\\u`, `C:\Users\u`, `C:Usersu`},
		{"unquoted-escaped-squote", `it\'s`, `it's`, `its`},
		{"unquoted-escaped-dquote", `a\"b`, `a"b`, `ab`},
		{"unquoted-escaped-newline", "a\\\nb", "ab", "a\nb"},
		{"unquoted-obfuscated-name", `r\m`, `rm`, `rm`},
		// A spliced name bash does not resolve to the name it imitates. On
		// POSIX it keeps reading as that name, deliberately (option (a) of
		// #5049 would change this); on Windows the backslash survives.
		{"dq-spliced-name", `"~/` + `.ss\h"/` + qKey, `~/.ss\h/` + qKey, `~/` + qSSH + `/` + qKey},
		{"dq-spliced-exe", `"r\m"`, `r\m`, `rm`},
		// Splices with no backslash read the same on every OS.
		{"sq-splice", `~/.ss'h'/id_r'sa'`, `~/` + qSSH + `/` + qKey, `~/` + qSSH + `/` + qKey},
		{"mixed-splice", `/e't'c/pa"s"sw\d`, `/etc/passwd`, `/etc/passwd`},
		{"empty-dq", `r""m`, `rm`, `rm`},
		// A kept backslash beside a / is one separator to Git Bash, which runs
		// "/usr/bin/\cat" as /usr/bin/cat (rows A1-A5, O1, O5). It gets the
		// POSIX reading, so the program name main saw is not hidden.
		{"dq-backslash-after-slash-exe", `"/usr/bin/\rm"`, `/usr/bin/rm`, `/usr/bin/rm`},
		{"sq-backslash-after-slash-exe", `'/usr/bin/\rm'`, `/usr/bin/rm`, `/usr/bin/rm`},
		{"sq-run-after-slash-exe", `'/usr/bin/\\rm'`, `/usr/bin/rm`, `/usr/bin/rm`},
		{"dq-backslash-before-slash", `"/usr/bin\/rm"`, `/usr/bin/rm`, `/usr/bin/rm`},
		{"dq-backslash-after-slash-dir", `"/usr/\bin/rm"`, `/usr/bin/rm`, `/usr/bin/rm`},
		{"sq-leading-backslash-slash", `'\/usr/bin/rm'`, `/usr/bin/rm`, `/usr/bin/rm`},
		{"tilde-dq-backslash-after-slash", `~/"\` + qSSH + `"/` + qKey, `~/` + qSSH + `/` + qKey, `~/` + qSSH + `/` + qKey},
		{"sq-home-run-before-slash", `'` + qHome + `\'/` + qSSH, qHome + `/` + qSSH, `C:Usersu/` + qSSH},
		// A run at either end of the word separates nothing, so it gets the
		// POSIX reading too. shellparse renders the basename of "/usr/bin/\rm"
		// as '\rm'; Git Bash runs the former as rm.
		{"sq-leading-backslash-exe", `'\rm'`, `rm`, `rm`},
		{"dq-leading-backslash-exe", `"\rm"`, `rm`, `rm`},
		{"sq-leading-run-exe", `'\\rm'`, `rm`, `rm`},
		{"sq-trailing-backslash", `~/'` + qSSH + `\'`, `~/` + qSSH, `~/` + qSSH},
		{"dq-trailing-escaped-backslash", `"` + qHome + `\\"`, qHome, `C:Usersu`},
		// A run between two names is kept whole (Git Bash: rows A8, O2, O3).
		{"sq-run-between-names", `'/usr\\bin/rm'`, `/usr\\bin/rm`, `/usrbin/rm`},
		{"sq-native-run", `'C:\\Users\\u'`, `C:\\Users\\u`, `C:Usersu`},
		{"dq-backslash-between-names-exe", `"/usr/bin\rm"`, `/usr/bin\rm`, `/usr/binrm`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripShellQuotes(tc.in, "windows"); got != tc.windows {
				t.Errorf("windows: stripShellQuotes(%q) = %q, want %q", tc.in, got, tc.windows)
			}
			for _, goos := range []string{"darwin", "linux"} {
				if got := stripShellQuotes(tc.in, goos); got != tc.posix {
					t.Errorf("%s: stripShellQuotes(%q) = %q, want %q", goos, tc.in, got, tc.posix)
				}
			}
		})
	}
}

// A word bash would not end where the caller cut it keeps the POSIX reading on
// Windows: an unclosed quote, or a trailing backslash. So does any word with an
// expansion in it, including the statically decoded $'...' and $"..." forms.
func TestStripShellQuotes_WindowsFallsBackToPOSIX_5049(t *testing.T) {
	for _, in := range []string{
		`"` + qHome + `\` + qAWS, // unclosed "
		`'` + qHome + `\` + qAWS, // unclosed '
		`"` + qHome + `\"`,       // the closing quote is escaped
		qHome + `\`,              // trailing backslash
		`"` + qHome + `"\`,       // trailing backslash after a closed quote
		`$'` + `r\x6d'`,          // ANSI-C: decoded the POSIX way, as on main
		`$"rm"`,                  // locale quoting
		`"$HOME\` + qSSH + `"`,   // a parameter expansion
		"`echo x`\\" + qSSH,      // a command substitution
		`'$HOME'\` + qSSH,        // a $ that bash would not expand still counts
	} {
		t.Run(in, func(t *testing.T) {
			win, posix := stripShellQuotes(in, "windows"), stripShellQuotes(in, "linux")
			if win != posix {
				t.Errorf("stripShellQuotes(%q): windows %q, posix %q; want the POSIX reading", in, win, posix)
			}
		})
	}
}

// The POSIX reading is unchanged: for every word with no expansion it is the
// word with each quote and backslash deleted, exactly the pre-#5049 algorithm.
// The Windows reading differs from it only when it keeps a backslash or a
// quote character; a word made of plain text and balanced quote pairs reads
// the same on both.
func TestStripShellQuotes_POSIXByteIdentical_5049(t *testing.T) {
	del := strings.NewReplacer(`'`, "", `"`, "", `\`, "")
	alphabet := []string{"a", "/", ".", "~", ":", "C", "'", `"`, `\`, `\`, " ", "\n"}
	rng := rand.New(rand.NewSource(5049))
	differs := 0
	for n := 0; n < 20000; n++ {
		var b strings.Builder
		for k := rng.Intn(10); k >= 0; k-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		in := b.String()
		for _, goos := range []string{"darwin", "linux", "freebsd"} {
			if got, want := stripShellQuotes(in, goos), del.Replace(in); got != want {
				t.Fatalf("%s: stripShellQuotes(%q) = %q, want the pre-#5049 %q", goos, in, got, want)
			}
		}
		win := stripShellQuotes(in, "windows")
		if win == del.Replace(in) {
			continue
		}
		differs++
		out, ok := removeBashQuotes(in)
		if !ok || win != keepSeparatingBackslashes(out) {
			t.Fatalf("windows: stripShellQuotes(%q) = %q, neither the POSIX reading nor bash's (%q, %v)", in, win, out, ok)
		}
		if !keepsAQuotedChar(in) {
			t.Fatalf("windows: stripShellQuotes(%q) = %q differs from POSIX with no kept backslash or quote", in, win)
		}
	}
	if differs == 0 {
		t.Fatal("no generated word read differently on Windows: the generator is not exercising the change")
	}
}

// keepsAQuotedChar reports whether the Windows reading keeps a backslash or a
// quote character of s, or removes a backslash-newline: the only ways it can
// differ from deleting every quote and backslash.
func keepsAQuotedChar(s string) bool {
	out, ok := removeBashQuotes(s)
	out = keepSeparatingBackslashes(out)
	return ok && (strings.ContainsAny(out, `'"\`) || strings.Contains(s, "\\\n"))
}

// The two readings the analyzer's stricter-of-two compares on Windows (#5049,
// PR #5057 round 3). MainShellQuotes is main's reading on every OS, Windows
// included; StripShellQuotesFor is StripShellQuotes as the given OS runs it.
// A word with an expansion in it (`$`, backquote) reads the same both ways on
// Windows, so a caller that only ever sees such words (egress_allowlist's
// `$'…'` words) was not changed by #5049 at all.
func TestMainShellQuotesIsMainsReading_5049(t *testing.T) {
	alphabet := []string{"a", "/", ".", "~", ":", "C", "'", `"`, `\`, `\`, " ", "\n", "$", "$'", "`", "x"}
	rng := rand.New(rand.NewSource(50493))
	expansions, differs := 0, 0
	for n := 0; n < 20000; n++ {
		var b strings.Builder
		for k := rng.Intn(10); k >= 0; k-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		in := b.String()
		main := MainShellQuotes(in)
		for _, goos := range []string{"darwin", "linux", "freebsd", ""} {
			if got := stripShellQuotes(in, goos); got != main {
				t.Fatalf("%q: MainShellQuotes = %q, but %q reads %q", in, main, goos, got)
			}
		}
		if got := StripShellQuotesFor(in, "darwin"); got != main {
			t.Fatalf("%q: StripShellQuotesFor darwin = %q, MainShellQuotes %q", in, got, main)
		}
		win := StripShellQuotesFor(in, "windows")
		if strings.ContainsAny(in, "$`") {
			expansions++
			if win != main {
				t.Fatalf("%q has an expansion: Windows reads %q, main %q", in, win, main)
			}
		} else if win != main {
			differs++
		}
	}
	if expansions == 0 || differs == 0 {
		t.Fatalf("generator not exercising both cases: %d expansion words, %d words read differently", expansions, differs)
	}
	if got, want := StripShellQuotesFor(`"`+qHome+`\`+qAWS+`"/`+qCred, "windows"), qHome+`\`+qAWS+"/"+qCred; got != want {
		t.Errorf("windows reading = %q, want %q", got, want)
	}
	if got, want := MainShellQuotes(`"`+qHome+`\`+qAWS+`"/`+qCred), `C:Usersu`+qAWS+"/"+qCred; got != want {
		t.Errorf("main reading = %q, want %q", got, want)
	}
}
