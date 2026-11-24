package enterprise

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests pin the two halves of #3620 that live in this package: the
// default-deny config-touch rule, and the fail-closed reading of a corrupt
// managed.json.

func selfProtectVerdict(t *testing.T, cmd string) (blocked bool, msg string) {
	t.Helper()
	mw := SelfProtect()
	ctx := &EvalContext{Command: cmd}
	mw(ctx, func() {})
	return ctx.Blocked, ctx.BlockMsg
}

// TestSelfProtect_ConfigTouch_BlocksEveryWriterNotJustTheEnumeratedOnes is
// the reproduction: the Python one-liner passed as AUDIT on a managed host
// while `echo … >` was blocked. Every row here is a way to write the policy
// that sp-block-policy-write's verb list does not name.
func TestSelfProtect_ConfigTouch_BlocksEveryWriterNotJustTheEnumeratedOnes(t *testing.T) {
	cases := []string{
		`python3 -c "open('/Users/dev/.agentshield/policy.yaml','w').write('disable_rules: [x]')"`,
		`python3 -c "open('` + "~" + `/.agentshield/policy.yaml','w').write('rules: []')"`,
		`perl -e 'open(F,">","$ENV{HOME}/.agentshield/policy.yaml"); print F "rules: []"'`,
		`node -e "require('fs').writeFileSync(process.env.HOME+'/.agentshield/policy.yaml','rules: []')"`,
		`sed -i 's/BLOCK/AUDIT/' ~/.agentshield/policy.yaml`,
		`cp /tmp/loose.yaml ~/.agentshield/policy.yaml`,
		`mv /tmp/loose.yaml ~/.agentshield/policy.yaml`,
		`dd if=/dev/null of=~/.agentshield/managed.json`,
		`printf '{not json' > ~/.agentshield/managed.json`,
		`truncate -s 0 ~/.agentshield/managed.json`,
		`rsync /tmp/packs/ ~/.agentshield/packs/`,
		`vim ~/.agentshield/policy.yaml`,
		// Adversarial review 2026-09-02: tools that were on the read allowlist
		// but can write or execute through an argument. All were exit 0.
		`yq -i '.disable_rules += ["protected-path"]' ~/.agentshield/policy.yaml`,
		`yq -i e '.mode = "audit"' ~/.agentshield/policy.yaml`,
		`less +':!sh /tmp/w.sh' ~/.agentshield/policy.yaml`,
		`less +v ~/.agentshield/policy.yaml`,
		`more +':!sh /tmp/w.sh' ~/.agentshield/policy.yaml`,
		`bat --pager 'sh /tmp/w.sh' ~/.agentshield/policy.yaml`,
		`sudo less +':!sh /tmp/w.sh' ~/.agentshield/policy.yaml`,
		`less ~/.agentshield/policy.yaml`, // a pager is not a reader: it can always escape to a shell
		`cat ~/.agentshield/policy.yaml | sed 's/BLOCK/AUDIT/' > /tmp/p && cp /tmp/p ~/.agentshield/policy.yaml`,
		// a reader first does not launder a compound command
		`cat ~/.agentshield/policy.yaml; python3 -c "open('/Users/dev/.agentshield/policy.yaml','w')"`,
		// subshell/backtick in a "read" is not a plain read
		"cat $(echo ~/.agentshield/policy.yaml)",
		"cat `echo ~/.agentshield/managed.json`",
		// #4840: a bare read word, then a newline, then a write. plainReadRe's
		// `\s+` matched the newline, so the write passed as a plain read. A
		// newline separates statements as `;` does.
		"cat\nsed -i 's/BLOCK/AUDIT/' ~/.agentshield/policy.yaml",
		"wc\nsed -i 's/BLOCK/AUDIT/' ~/.agentshield/policy.yaml",
		"ls\ndd if=/dev/null of=~/.agentshield/policy.yaml",
		"cat \nsed -i 's/BLOCK/AUDIT/' ~/.agentshield/policy.yaml",
		"cat\r\nsed -i 's/BLOCK/AUDIT/' ~/.agentshield/policy.yaml",
		"sudo\nsed -i 's/BLOCK/AUDIT/' ~/.agentshield/policy.yaml",
		"agentshield\nyq -i '.mode = \"audit\"' ~/.agentshield/policy.yaml",
	}
	for _, cmd := range cases {
		blocked, msg := selfProtectVerdict(t, cmd)
		if !blocked {
			t.Errorf("not blocked on a managed host: %s", cmd)
			continue
		}
		// Which self-protect rule claims the block is attribution, not
		// protection: cp/mv land on sp-block-binary-replace first, tee/> on
		// sp-block-policy-write. Any sp-block-* id is the contract here.
		if !strings.Contains(msg, "rule: sp-block-") {
			t.Errorf("blocked by an unexpected rule (%s): %s", msg, cmd)
		}
	}
}

// TestSelfProtect_ConfigTouch_PlainReadsStillPass is the false-positive
// guard: an operator or agent inspecting the config must not be blocked.
func TestSelfProtect_ConfigTouch_PlainReadsStillPass(t *testing.T) {
	cases := []string{
		`cat ~/.agentshield/policy.yaml`,
		`cat $HOME/.agentshield/managed.json`,
		`head -n 20 ~/.agentshield/policy.yaml`,
		`grep -n disable_rules ~/.agentshield/policy.yaml`,
		`rg BLOCK ~/.agentshield/packs/`,
		`ls -la ~/.agentshield/packs`,
		`stat ~/.agentshield/managed.json`,
		`jq . ~/.agentshield/managed.json`,
		`diff ~/.agentshield/policy.yaml /tmp/policy.yaml`,
		`sudo cat /Users/dev/.agentshield/policy.yaml`,
		`agentshield rule list`,
		// #4840: a plain read stays one line, but blanks around it and a tab
		// between words are still a plain read.
		"cat\t~/.agentshield/policy.yaml",
		"\n  cat ~/.agentshield/policy.yaml",
		"cat ~/.agentshield/policy.yaml  ",
		"sudo\tcat ~/.agentshield/policy.yaml",
		// unrelated commands that mention nothing under the config dir
		`python3 -c "print('hello')"`,
		`echo 'rules: []' > /tmp/policy.yaml`,
	}
	for _, cmd := range cases {
		if blocked, msg := selfProtectVerdict(t, cmd); blocked {
			t.Errorf("plain read blocked (%s): %s", msg, cmd)
		}
	}
}

// TestSelfProtect_ConfigTouch_SurvivesQuoteSplice checks the new rule rides
// the same dequote/unset-param fallbacks as the older six.
func TestSelfProtect_ConfigTouch_SurvivesQuoteSplice(t *testing.T) {
	cases := []string{
		`python3 -c "x=1" ~/.agentshi'e'ld/policy.yaml`,
		`cp /tmp/p ~/.agentshi${zqx}eld/policy.yaml`,
	}
	for _, cmd := range cases {
		if blocked, _ := selfProtectVerdict(t, cmd); !blocked {
			t.Errorf("spliced path not blocked: %s", cmd)
		}
	}
}

// TestLoadManagedConfigFrom_CorruptFailsClosed pins the loader half of
// #3620 on this package's loader (config.LoadManaged has its own test, and
// internal/cli pins the two to agree).
func TestLoadManagedConfigFrom_CorruptFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "managed.json")

	if cfg := LoadManagedConfigFrom(path); cfg != nil {
		t.Fatalf("absent file → %+v; want nil (absent is genuinely unmanaged)", cfg)
	}

	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadManagedConfigFrom(path)
	if cfg == nil || !cfg.Managed || !cfg.FailClosed {
		t.Fatalf("corrupt file → %+v; want Managed=true FailClosed=true — nil meant 'not managed' and re-enabled pause and bypass", cfg)
	}

	if err := os.WriteFile(path, []byte(`{"managed": true, "fail_closed": false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = LoadManagedConfigFrom(path)
	if cfg == nil || !cfg.Managed || cfg.FailClosed {
		t.Fatalf("valid file → %+v; want the parsed values, not the corrupt fallback", cfg)
	}
}

// TestSelfProtect_NewlineAttributesAsSemicolon_4840: a bare read word, a
// newline and a statement are attributed exactly as the same two statements
// joined by `;`, the separator a newline is. On main the first row differed:
// the raw text passed as a plain read (the #4840 bypass), so a quote-spliced
// delete reached the dequoted reading and was claimed by
// sp-block-delete-config, while its `;` spelling, and the same delete with no
// read before it, are claimed on the raw text by sp-block-config-touch (#4840
// Codex pass 1). That the catch-all pre-empts a specific rule a normalized
// reading would match is pre-existing and tracked on its own; when it is
// fixed, both spellings move together.
func TestSelfProtect_NewlineAttributesAsSemicolon_4840(t *testing.T) {
	cfg := "~/.agent" + "shield/policy.yaml"
	dir := "~/.agent" + "shield"
	for _, r := range [][2]string{
		{"ls", "r'm' " + cfg},
		{"cat", "sed -i s/x/y/ " + cfg},
		{"wc", "rm " + cfg},
		{"ls", "r'm' -rf " + dir},
		{"head", "cp /tmp/p " + cfg},
	} {
		nl, nlOK := matchesSelfProtectRule(r[0] + "\n" + r[1])
		semi, semiOK := matchesSelfProtectRule(r[0] + "; " + r[1])
		if !nlOK || !semiOK || nl != semi {
			t.Errorf("%q then %q: newline %v %s, semicolon %v %s; want the same BLOCK", r[0], r[1], nlOK, nl, semiOK, semi)
		}
	}
}

// TestSelfProtect_SplicedAfterARead_PinnedReceipt_4840 pins the receipt Codex
// pass 2 found (#4844): a read word, then a statement whose specific rule
// only a normalized reading reaches (a quote-spliced path plus an unset
// expansion in the variable name). On main both the newline and the `;`
// spelling were claimed by sp-block-bypass-env, each only through the #4840
// bug: DequoteCommand prints `;` as a newline, and the old plainReadRe read
// that as one plain read, which let the folded reading run. Here the raw or
// dequoted text is no plain read, so the catch-all sp-block-config-touch
// claims it first, with no node (#4666). The decision is BLOCK either way.
// The statement alone is claimed by the catch-all on main too, so all three
// now agree. Codex's own standalone row kept sp-block-bypass-env on main only
// because it began `agentshield mcp-proxy --`, which plainReadRe wrongly
// exempts as a read (a separate issue). Trying the catch-all last (#4666)
// would give all three the specific rule; change these rows then.
func TestSelfProtect_SplicedAfterARead_PinnedReceipt_4840(t *testing.T) {
	stmt := "env AGENTSHIELD_BYPA${zqx}SS=1 sed -i.bak s/BLOCK/AUDIT/ ~/.agentshi'e'ld/policy.yaml"
	for _, r := range []struct{ cmd, rule string }{
		{"ls\n" + stmt, "sp-block-config-touch"},
		{"ls; " + stmt, "sp-block-config-touch"},
		{stmt, "sp-block-config-touch"},
	} {
		id, ok := matchesSelfProtectRule(r.cmd)
		if !ok || id != r.rule {
			t.Errorf("%q: %v %s, want BLOCK by %s", r.cmd, ok, id, r.rule)
		}
	}
}
