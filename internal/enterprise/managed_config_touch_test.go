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
