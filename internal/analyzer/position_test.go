package analyzer

import (
	"regexp"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// shadowMatcher stands in for a rule whose signal is a literal path — the
// shape command_position_exclude exists for.
func shadowMatcher() func(string) bool {
	re := regexp.MustCompile(`(/etc/shadow|/etc/master\.passwd)`)
	return re.MatchString
}

func TestPositionExcludedLoopWordList(t *testing.T) {
	matches := shadowMatcher()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "grep needle in an inert loop — the #3376 FP",
			command: `for p in ".ssh/" "/etc/shadow"; do n=$(grep -c -- "$p" "$F"); echo "$n <= $p"; done`,
			want:    true,
		},
		{
			name:    "printed only",
			command: `for p in /etc/shadow; do echo "checking $p"; done`,
			want:    true,
		},

		// Attribution: the loop exists and is inert, but the match does not
		// live in it. Without the attribution half, any command containing a
		// harmless loop would qualify.
		{
			name:    "inert loop present, match is elsewhere",
			command: `for f in a b; do echo "$f"; done; cat /etc/shadow`,
			want:    false,
		},
		// Subtraction: the match lives in the loop AND outside it.
		{
			name:    "same path inside the loop and in a real read",
			command: `for p in /etc/shadow; do echo "$p"; done && cat /etc/shadow`,
			want:    false,
		},
		{
			name:    "second occurrence only visible after quote removal",
			command: `for p in /etc/shadow; do echo "$p"; done; cat /etc/sha'dow'`,
			want:    false,
		},
		// Inertness: the loop variable reaches something that acts on it.
		{
			name:    "loop variable is read",
			command: `for p in /etc/shadow; do cat "$p"; done`,
			want:    false,
		},
		{
			name:    "printed value consumed by a pipe",
			command: `for p in /etc/shadow; do echo "$p" | xargs cat; done`,
			want:    false,
		},
		{
			name:    "no loop at all",
			command: `cat /etc/shadow`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A real per-command fold context, matching both production call
			// sites (neither ever passes nil) — see #3725.
			fc := NewStatementFoldContext(tt.command)
			got := PositionExcluded(tt.command, []string{LabelPosLoopWordList}, fc, matches)
			if got != tt.want {
				t.Fatalf("PositionExcluded(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// fridaNameMatcher stands in for ts-block-frida-name-attach — a rule whose
// signal spans two tokens ("frida" then "-n"/"--name") rather than one
// literal path, which is the shape #3382 needs covered.
func fridaNameMatcher() func(string) bool {
	re := regexp.MustCompile(`(?:sudo\s+)?frida\b(?:\s+\S+)*?\s+(?:-n|--name)\s+\S+`)
	return re.MatchString
}

func TestPositionExcludedSearchNeedle(t *testing.T) {
	matches := fridaNameMatcher()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "quoted multi-word needle — the #3382 FP",
			command: `grep -i "frida -n <process>" -r docs/`,
			want:    true,
		},
		{
			name:    "ripgrep, single-quoted needle",
			command: `rg -i 'frida --name chrome' docs/`,
			want:    true,
		},

		// Attribution: a grep needle is present, but it does not itself
		// satisfy the rule's pattern (the "-n" comes from elsewhere).
		{
			name:    "needle present, match spans outside it",
			command: `grep -i frida -r . ; ls -n`,
			want:    false,
		},
		// Subtraction: the same phrase also appears as a real invocation.
		{
			name:    "needle plus a genuine attach elsewhere",
			command: `grep -i "frida -n <process>" -r docs/ && frida -n chrome`,
			want:    false,
		},
		{
			name:    "genuine attach, no search at all",
			command: `frida -n chrome`,
			want:    false,
		},
		// #3725: sibling of #3717's laundering, applied to the SUBTRACTION
		// check. Before this fix, redactedForms tested each split statement's
		// RAW text only — the same gap #3717 closed for command_intent_exclude
		// attribution. An obfuscated real statement therefore did not match
		// during subtraction, and an unrelated needle sibling's excluded
		// position wrongly "explained away" a match a real, executed
		// statement produced. Must NOT be excluded.
		//
		// (An ${IFS}-separator variant is deliberately NOT included here: the
		// pre-fix redactedForms already ran shellparse.NormalizeIFS over the
		// whole redacted command, so that particular obfuscation was an
		// accidental non-reproduction of this bug, not a case this fix closes.
		// Unset-parameter splices and indirect-executable variables were not
		// covered at the whole-command level and are the real regression.)
		{
			name:    "#3725: unset-param-splice real attach + needle-position sibling",
			command: `f${zqx}rida -n chrome; grep -i "frida -n <process>" -r docs/`,
			want:    false,
		},
		{
			name:    "#3725: indirect-executable-variable real attach + needle-position sibling",
			command: `x=frida; $x -n chrome; grep -i "frida -n <process>" -r docs/`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A real per-command fold context, matching both production call
			// sites (neither ever passes nil) — the indirect-executable-
			// variable case below needs the symbol table nil would omit.
			fc := NewStatementFoldContext(tt.command)
			got := PositionExcluded(tt.command, []string{LabelPosSearchNeedle}, fc, matches)
			if got != tt.want {
				t.Fatalf("PositionExcluded(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// keepassDBMatcher and homeRedirectMatcher stand in for
// sec-block-keepassxc-db-read and ts-block-home-redirect, the two shipped
// search_needle rules whose pass-1 (#4400) probes lowered.
func keepassDBMatcher() func(string) bool {
	re := regexp.MustCompile(`(cat|less|more|head|tail|bat|strings|xxd|hexdump|cp|mv|scp|rsync|base64)\s+.*\.kdbx\b`)
	return re.MatchString
}

func homeRedirectMatcher() func(string) bool {
	re := regexp.MustCompile(`(export\s+)?\bHOME=(/tmp|/dev/shm|/var/tmp|/run/user|\./|\.\./)\S*`)
	return re.MatchString
}

// fridaNameAttachMatcher stands in for ts-block-frida-name-attach: a rule
// anchored on its program word, so a payload an echo pipes into a shell
// matches only as the executed text the shell receives.
func fridaNameAttachMatcher() func(string) bool {
	re := regexp.MustCompile(`^(?:sudo\s+)?frida\b(?:\s+\S+)*?\s+(?:-n|--name)\s+\S+`)
	return re.MatchString
}

// TestPositionExcludedSubtractionWholeCommandForms pins the two whole-command
// forms #4400 added to redactedForms. Every "false" row blocked without its
// needle and was excluded with it: the needle was the only match
// subtraction could see, because the real read only matches after
// MaterializeAssignments resolves a variable assigned in a sibling statement,
// or after DecodeEmittedSeparators turns a printf escape into the separator a
// leading \b needs. Every needle here matches the rule on its own, so
// attribution holds and subtraction alone decides the row. The "true" rows
// are the over-reach guards: the new forms must not cancel an exclusion when
// nothing reads the variable or nothing executes the printf.
//
// Each row runs under both fold contexts production passes: the plain one,
// and the restrict-forms one handed to restricting rules (#3991).
func TestPositionExcludedSubtractionWholeCommandForms(t *testing.T) {
	tests := []struct {
		name    string
		matches func(string) bool
		command string
		want    bool
	}{
		{"pickaxe needle alone", keepassDBMatcher(),
			`git log -S'cat a.kdbx' --oneline`, true},
		{"pickaxe needle plus a literal read", keepassDBMatcher(),
			`git log -S'cat a.kdbx' --oneline && cat ~/Passwords.kdbx`, false},
		{"pickaxe needle plus a read of a sibling-assigned variable", keepassDBMatcher(),
			`git log -S'cat a.kdbx' && x=~/Passwords.kdbx && cat "$x"`, false},
		{"assignment first, copy two statements later", keepassDBMatcher(),
			`f=~/Passwords.kdbx; git log --oneline -S'cp a.kdbx b'; cp "$f" /tmp/x`, false},
		{"git diff -G needle plus a sibling-assigned read", keepassDBMatcher(),
			`p=~/Passwords.kdbx; git diff -G'cat a.kdbx' HEAD~1; cat "$p"`, false},
		{"grep needle plus a sibling-assigned read", keepassDBMatcher(),
			`grep -rn 'cat a.kdbx' docs/ && x=~/Passwords.kdbx && cat "$x"`, false},
		{"variable assigned but only echoed", keepassDBMatcher(),
			`x=~/Passwords.kdbx && git log -S'cat a.kdbx' --oneline && echo "$x"`, true},
		{"grep needle plus a sibling-assigned export", homeRedirectMatcher(),
			`h=/tmp/evil && grep -rn 'HOME=/tmp/x' docs/ && export HOME=$h`, false},
		{"grep needle plus a printf-escaped payload piped to sh", homeRedirectMatcher(),
			`grep -rn 'HOME=/tmp/x ssh' docs/; printf 'id\nHOME=/tmp/evil ssh h\n' | sh`, false},
		{"pickaxe needle plus a printf-escaped payload piped to sh", homeRedirectMatcher(),
			`git log -S'HOME=/tmp/x ssh' --oneline; printf 'id\nHOME=/tmp/evil ssh h\n' | sh`, false},
		{"printf-escaped payload that nothing executes", homeRedirectMatcher(),
			`grep -rn 'HOME=/tmp/x ssh' docs/; printf 'id\nHOME=/tmp/evil ssh h\n'`, true},
		// Fix round 2: an anchored rule matches a piped or substituted
		// payload only once it is retried as the command the shell runs.
		{"pickaxe needle plus an echoed payload piped to sh", fridaNameAttachMatcher(),
			`git log -S'frida -n Foo' --oneline; echo 'frida -n Safari' | sh`, false},
		{"grep needle plus an echoed payload piped to bash", fridaNameAttachMatcher(),
			`grep 'frida -n Foo' notes.txt && echo 'frida -n Safari' | bash`, false},
		{"pickaxe needle plus a substitution body", fridaNameAttachMatcher(),
			`git log -S'frida -n Foo' --oneline; sh -c "$(echo frida -n Safari)"`, false},
		{"pickaxe needle plus an interpreter heredoc os.system call", fridaNameAttachMatcher(),
			"git log -S'frida -n Foo' --oneline; python3 - <<'EOF'\nimport os\nos.system(\"frida -n Safari\")\nEOF", false},
		{"echoed payload that nothing executes", fridaNameAttachMatcher(),
			`git log -S'frida -n Foo' --oneline; echo 'frida -n Safari'`, true},
		{"echoed payload written to a file", fridaNameAttachMatcher(),
			`grep 'frida -n Foo' notes.txt; echo 'frida -n Safari' > notes2.txt`, true},
		// Pass 2: a fold, then materialize, in the matcher's order. Only the
		// shared buildWholeCommandForms gives subtraction that composition.
		{"sibling-assigned read through an unset-parameter splice", keepassDBMatcher(),
			`git log -S'cat a.kdbx' --oneline; x=~/Passwords.kdbx; ca${zqx}t "$x"`, false},
		{"sibling-assigned read through an indirect executable", keepassDBMatcher(),
			`git log -S'cat a.kdbx' --oneline; x=~/Passwords.kdbx; $(echo cat) "$x"`, false},
		{"path split across sibling assignments with a splice", shadowMatcher(),
			`git log -S'/etc/shadow' --oneline; a=/etc; b=sha${zqx}dow; cat $a/$b`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := NewStatementFoldContext(tt.command)
			for _, ctx := range []struct {
				label string
				fc    *StatementFoldContext
			}{{"plain", fc}, {"restrict", fc.withRestrictForms()}} {
				got := PositionExcluded(tt.command, []string{LabelPosSearchNeedle}, ctx.fc, tt.matches)
				if got != tt.want {
					t.Errorf("%s fold context: PositionExcluded(%q) = %v, want %v", ctx.label, tt.command, got, tt.want)
				}
			}
		})
	}
}

// sitecustomizeMatcher stands in for ts-block-python-sitecustomize-write — a
// rule whose signal is TWO co-required tokens (an executable word and a
// filename), which stresses attribution differently than the single-region
// shapes above: the exclusion only works when both tokens are co-located
// within the excluded position, since PositionExcluded tests the rule's WHOLE
// pattern against the isolated redacted text (#3397).
func sitecustomizeMatcher() func(string) bool {
	re := regexp.MustCompile(`(echo|printf|tee|cat|cp|mv|install)\b.*\b(site|user)customize\.py`)
	return re.MatchString
}

func TestPositionExcludedHeredocBody(t *testing.T) {
	matches := sitecustomizeMatcher()
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{
			name:    "both trigger tokens co-located in heredoc body prose — the #3397 FP",
			command: "cat > \"$S/notes.md\" <<'EOF'\n- blocks cat/tee writes to sitecustomize.py\nEOF",
			want:    true,
		},

		// Attribution: the filename is in the body, but the required
		// executable-word token never occurs there — the isolated body text
		// alone does not satisfy the rule's own pattern, so this label does
		// not apply (the whole-command match must have come from elsewhere,
		// e.g. the command's own "cat" — a case the rule's DOTALL-less regex
		// can only reach when both tokens share a line, so it is already
		// covered by the co-located case above in practice).
		{
			name:    "filename only, no co-located executable word",
			command: "cat > \"$S/notes.md\" <<'EOF'\nsitecustomize.py\nEOF",
			want:    false,
		},
		// Subtraction: the filename is the ACTUAL write target on the
		// command line — a real attack — and must never be excused just
		// because the invocation also carries a heredoc.
		{
			name:    "filename is the real write target, not body prose",
			command: "cat > sitecustomize.py <<'EOF'\nimport os\nEOF",
			want:    false,
		},
		// Subtraction: heredoc piped into tee, whose own argument is the
		// real write target — outside the body span.
		{
			name:    "filename is a pipe-sink target, not body prose",
			command: "cat <<'EOF' | tee sitecustomize.py\nimport os\nEOF",
			want:    false,
		},
		// Never excused: the consumer interprets the body as code.
		{
			name:    "bash heredoc — body is shell, stays live",
			command: "bash <<'EOF'\ncat sitecustomize.py\nEOF",
			want:    false,
		},
		{
			name:    "no heredoc at all",
			command: "cp backdoor.py sitecustomize.py",
			want:    false,
		},
		// #3730: an UNQUOTED delimiter expands its body before the sink
		// ever runs, so a command substitution that itself performs the
		// write executes live — it must never be excused as inert prose.
		{
			name:    "unquoted delimiter — the write happens via a live command substitution",
			command: "cat > \"$S/notes.md\" <<EOF\n$(cp backdoor.py /usr/lib/python3/dist-packages/sitecustomize.py)\nEOF",
			want:    false,
		},
		// The identical prose, still unquoted but with no expansion at all,
		// stays fully literal and is correctly excused exactly as the quoted
		// case above.
		{
			name:    "unquoted delimiter — genuinely inert prose is still excused",
			command: "cat > \"$S/notes.md\" <<EOF\n- blocks cat/tee writes to sitecustomize.py\nEOF",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PositionExcluded(tt.command, []string{LabelPosHeredocBody}, nil, matches)
			if got != tt.want {
				t.Fatalf("PositionExcluded(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// An empty or unrecognised label list must never suppress anything — the
// mechanism is opt-in, and a rule that did not ask for it must behave exactly
// as before.
func TestPositionExcludedIsOptIn(t *testing.T) {
	cmd := `for p in /etc/shadow; do echo "$p"; done`
	matches := shadowMatcher()
	if PositionExcluded(cmd, nil, nil, matches) {
		t.Error("no labels must never exclude")
	}
	if PositionExcluded(cmd, []string{"not_a_label"}, nil, matches) {
		t.Error("unrecognised label must never exclude")
	}
	if !PositionExcluded(cmd, []string{"not_a_label", LabelPosLoopWordList}, nil, matches) {
		t.Error("a recognised label alongside an unrecognised one must still apply")
	}
}

func TestIsValidPositionLabel(t *testing.T) {
	if !IsValidPositionLabel(LabelPosLoopWordList) {
		t.Errorf("%q must be valid", LabelPosLoopWordList)
	}
	if !IsValidPositionLabel(LabelPosSearchNeedle) {
		t.Errorf("%q must be valid", LabelPosSearchNeedle)
	}
	if !IsValidPositionLabel(LabelPosHeredocBody) {
		t.Errorf("%q must be valid", LabelPosHeredocBody)
	}
	for _, bad := range []string{"", "loop_word_list", "is_doc_text", "loop_wordlists", "search_needles", "grep_needle", "heredoc_bodies", "in_heredoc"} {
		if IsValidPositionLabel(bad) {
			t.Errorf("%q must not be valid", bad)
		}
	}
}

// A rule whose pattern happens to match the placeholder text would be
// suppressed on every inert loop, so the placeholder must be inert itself.
// Cheap guard against someone "simplifying" it to something short.
func TestLoopItemPlaceholderMatchesNoShippedLiteral(t *testing.T) {
	cmd := `for p in /etc/shadow; do echo "$p"; done`
	greedy := func(s string) bool { return strings.Contains(s, "/etc/shadow") }
	if !PositionExcluded(cmd, []string{LabelPosLoopWordList}, nil, greedy) {
		t.Fatal("expected the inert loop to be excluded")
	}
}

// Same guard as above, for the search-needle placeholder.
func TestSearchNeedlePlaceholderMatchesNoShippedLiteral(t *testing.T) {
	cmd := `grep -i "frida -n <process>" -r docs/`
	greedy := func(s string) bool { return strings.Contains(s, "frida") }
	if !PositionExcluded(cmd, []string{LabelPosSearchNeedle}, nil, greedy) {
		t.Fatal("expected the search needle to be excluded")
	}
}

// Same guard as above, for the heredoc-body placeholder.
func TestHeredocBodyPlaceholderMatchesNoShippedLiteral(t *testing.T) {
	cmd := "cat > notes.md <<'EOF'\nsitecustomize.py\nEOF"
	greedy := func(s string) bool { return strings.Contains(s, "sitecustomize.py") }
	if !PositionExcluded(cmd, []string{LabelPosHeredocBody}, nil, greedy) {
		t.Fatal("expected the heredoc body to be excluded")
	}
}

// TestWordPositionsSurviveExecutorReach pins the deliberate NON-withdrawal of
// loop_wordlist in positionAssertsDataText (#3976, from the #3968 adversarial
// review, where a mutation adding loop_wordlist to the withdrawal survived
// every gate). An unused loop word is a word on the invoking command line:
// piping the loop's output into a shell runs that output, not the word.
//
// search_needle used to be pinned here on the same reasoning. #4468 showed
// the reasoning does not hold for grep: piping grep's output into a shell
// runs the matched lines, and every one of them contains the needle. It now
// has its own withdrawal, pinned by TestSearchNeedleWithdrawnWhenOutputExecutes.
func TestWordPositionsSurviveExecutorReach(t *testing.T) {
	matches := func(s string) bool { return strings.Contains(s, "zqword") }
	cases := []struct {
		name     string
		command  string
		position string
	}{
		{"loop word unused, output piped to bash", `for p in 'zqword'; do echo hi; done | bash`, LabelPosLoopWordList},
		{"loop word unused, output run by bash -c", `bash -c "$(for p in 'zqword'; do echo hi; done)"`, LabelPosLoopWordList},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !shellparse.TextReachesExecutor(c.command) && len(shellparse.ExecutedSubstitutionBodies(c.command)) == 0 {
				t.Fatalf("control: %q must reach an executor, or this row tests nothing", c.command)
			}
			fc := NewStatementFoldContext(c.command)
			if !PositionExcluded(c.command, []string{c.position}, fc, matches) {
				t.Errorf("%s no longer excused on executor reach — %s is a command-line word, not executed text", c.command, c.position)
			}
		})
	}
}

// TestSearchNeedleWithdrawnWhenOutputExecutes pins #4468. A grep needle that
// names the rule's literal is excused (searching is not using), until the
// command runs or acts on grep's OUTPUT: every line the needle selects
// contains it. Each route the issue names withdraws the exclusion, and every
// shape that only counts, sorts, prints, stores or suppresses the output keeps
// it, so the fix raises a decision only where the lines are executed.
func TestSearchNeedleWithdrawnWhenOutputExecutes(t *testing.T) {
	matches := shadowMatcher()
	cases := []struct {
		name     string
		command  string
		excluded bool
	}{
		// --- withdrawn: the selected lines are run or acted on ---
		{"piped to bash", `grep -F '/etc/shadow' cmds.txt | bash`, false},
		{"piped through sed to sh", `grep -F '/etc/shadow' cmds.txt | sed 's/^ *//' | sh`, false},
		{"eval of a command substitution", `eval "$(grep -F '/etc/shadow' cmds.txt)"`, false},
		{"captured, then eval", `x=$(grep -F '/etc/shadow' cmds.txt); eval "$x"`, false},
		{"process substitution run by bash", `bash <(grep -F '/etc/shadow' cmds.txt)`, false},
		{"process substitution sourced", `source <(grep -F '/etc/shadow' cmds.txt)`, false},
		{"xargs cat", `grep -F '/etc/shadow' list.txt | xargs cat`, false},
		{"xargs runs each line", `grep -F '/etc/shadow' cmds.txt | xargs -L1 env`, false},
		{"read loop evals the line", `grep -F '/etc/shadow' cmds.txt | while read -r l; do eval "$l"; done`, false},
		{"read loop opens the line", `grep -F '/etc/shadow' list.txt | while read -r f; do cat "$f"; done`, false},
		{"read loop fed by a process substitution", `while read -r l; do $l; done < <(grep -F /etc/shadow cmds.txt)`, false},
		{"written, then run", `grep -F '/etc/shadow' cmds.txt > /tmp/x.sh; bash /tmp/x.sh`, false},

		// --- kept: nothing runs the selected lines ---
		{"plain grep", `grep -rn "/etc/shadow" docs/`, true},
		{"counted", `grep -F '/etc/shadow' cmds.txt | wc -l`, true},
		{"sorted and truncated", `grep -F '/etc/shadow' cmds.txt | sort | head -5`, true},
		{"written to a file nothing runs", `grep -F '/etc/shadow' cmds.txt > out.txt`, true},
		{"count captured", `n=$(grep -c '/etc/shadow' cmds.txt); echo "$n"`, true},
		{"captured, never executed", `x=$(grep -F '/etc/shadow' cmds.txt); echo done`, true},
		{"printed by a substitution", `echo "$(grep -F '/etc/shadow' cmds.txt)"`, true},
		{"read loop prints the line", `grep -F '/etc/shadow' cmds.txt | while read -r l; do echo "$l"; done`, true},
		{"bare xargs runs echo", `grep -F '/etc/shadow' cmds.txt | xargs`, true},
		{"xargs echo", `grep -F '/etc/shadow' cmds.txt | xargs echo`, true},
		{"filenames only, to xargs", `grep -rl '/etc/shadow' docs/ | xargs wc -l`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !matches(c.command) {
				t.Fatalf("control: %q must contain the rule's literal, or this row tests nothing", c.command)
			}
			fc := NewStatementFoldContext(c.command)
			if got := PositionExcluded(c.command, []string{LabelPosSearchNeedle}, fc, matches); got != c.excluded {
				t.Errorf("PositionExcluded(%q) = %v, want %v", c.command, got, c.excluded)
			}
		})
	}
}
