package enterprise

import (
	"regexp"
	"testing"
)

const binaryReplaceRule = "sp-block-binary-replace"

// binaryReplaceShape4637 are the commands #4637 reported, and the spellings of
// the same shape the exclusion recognises. None may match any self-protection
// rule. On main every one of them matches sp-block-binary-replace through the
// `cp` inside `mcp`.
var binaryReplaceShape4637 = []string{
	"agentshield setup mcp && agentshield status",
	"echo mcp agentshield",
	"agentshield setup mcp ; agentshield status",
	"agentshield setup mcp &&agentshield status",
	"agentshield setup mcp --mode=enforce && agentshield status",
	"agentshield setup mcp --mode audit-only && agentshield status",
	"agentshield setup mcp --target cursor && agentshield status",
	"agentshield setup mcp --target=claude-desktop --mode=enforce; agentshield status",
	"\tagentshield setup mcp  &&  agentshield status ",
	"echo setup mcp then agentshield status",
}

// binaryReplaceKeepsMain are commands main BLOCKs with sp-block-binary-replace
// that sit next to the #4637 shape but outside it. Each must keep main's
// BLOCK and rule id. The first group can replace the binary; the second is
// harmless but out of the shape, kept on main's decision on purpose (the
// exclusion is a recogniser, not a judgement of everything benign).
var binaryReplaceKeepsMain = []string{
	// A second command reached through a separator the shape does not admit.
	"agentshield setup mcp\ncp /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp && agentshield status\ncp /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp & cp /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp || cp /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp | cp /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp && cp /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp && agentshield status; cp /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp && 'cp' /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp && c${zqx}p /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp && $(cp /tmp/x /usr/local/bin/agentshield)",
	"agentshield setup mcp && `cp /tmp/x /usr/local/bin/agentshield`",
	"agentshield setup mcp # cp /tmp/x /usr/local/bin/agentshield",
	// agentshield as a forwarder: mcp-proxy runs the command after `--`.
	"agentshield setup mcp && agentshield mcp-proxy -- cp /tmp/x /usr/local/bin/agentshield",
	"agentshield setup mcp && agentshield mcp-proxy -- rsync /tmp/x /usr/local/bin/agentshield",
	// Flags the shape does not admit: they take a path.
	"agentshield setup mcp --policy /usr/local/bin/agentshield && agentshield status",
	"agentshield setup mcp --log /usr/local/bin/agentshield && agentshield status",
	// echo writing somewhere.
	"echo mcp agentshield > /usr/local/bin/agentshield",
	"echo mcp agentshield >> /opt/homebrew/bin/agentshield",
	"echo mcp agentshield | tee /usr/local/bin/agentshield",
	"echo mcp agentshield | sh",
	"echo mcp agentshield; cp /tmp/x /usr/local/bin/agentshield",
	"echo $(cp /tmp/x /usr/local/bin/agentshield) mcp agentshield",
	// A newline is a statement separator, not a space: read as a space, the
	// echo branch would swallow a move in the current directory.
	"echo mcp\nmv agentshield.new agentshield",
	"echo mcp agentshield\ncp x agentshield",
	// Harmless, but not the shape #4637 reported: main's decision stands.
	"kiln agentshield",
	"sudo kiln agentshield",
	"my-mv agentshield",
	"x_ln agentshield",
	"agentshield setup mcp && agentshield version",
	"agentshield setup mcp || agentshield status",
	"agentshield setup mcp | agentshield status",
	"agentshield setup mcp --target cursor && agentshield status | head",
	"sudo agentshield setup mcp && agentshield status",
	"X=1 agentshield setup mcp && agentshield status",
	"/usr/local/bin/agentshield setup mcp && agentshield status",
	"printf mcp agentshield",
}

// binaryReplaceStillBlocked are spellings of a real copy, move, link or
// install onto the binary. The first 18 are the pass-1 rows; the rest are the
// rows #4642 review pass 1 found dropping under a left boundary on the verb.
// Each must keep sp-block-binary-replace.
var binaryReplaceStillBlocked = []string{
	"cp /tmp/x /usr/local/bin/agentshield",
	"sudo cp /tmp/x /usr/local/bin/agentshield",
	"/bin/cp /tmp/x /usr/local/bin/agentshield",
	`\cp /tmp/x /usr/local/bin/agentshield`,
	"command cp /tmp/x /usr/local/bin/agentshield",
	"env cp /tmp/x /usr/local/bin/agentshield",
	"X=1 cp /tmp/x /usr/local/bin/agentshield",
	"true;cp /tmp/x /usr/local/bin/agentshield",
	"true&&mv /tmp/x /usr/local/bin/agentshield",
	"true|ln -sf /tmp/x /usr/local/bin/agentshield",
	"(cp /tmp/x /usr/local/bin/agentshield)",
	"$(cp /tmp/x /usr/local/bin/agentshield)",
	"`cp /tmp/x /usr/local/bin/agentshield`",
	"{ cp /tmp/x /usr/local/bin/agentshield; }",
	"bash -c 'cp /tmp/x /usr/local/bin/agentshield'",
	`sh -c "install /tmp/x /usr/local/bin/agentshield"`,
	"cp /tmp/x /usr/local/bin/agentshi'e'ld",
	"c${zqx}p /tmp/x /usr/local/bin/agentshield",
}

// binaryReplacePass1Drops are the rows pass 1 confirmed or listed: under the
// pass-1 head's boundary `(?:^|[^A-Za-z0-9_-])` each matched no rule.
var binaryReplacePass1Drops = []string{
	// OpenSSH scp copies between two local paths (stock macOS /usr/bin/scp).
	"scp /tmp/x /usr/local/bin/agentshield",
	"scp build.example:/x /opt/homebrew/bin/agentshield",
	// A positional parameter that expands to nothing: bash and zsh run cp/mv.
	"$1cp /tmp/x /usr/local/bin/agentshield",
	"$9mv /tmp/x /opt/homebrew/bin/agentshield",
	// A digit before the verb with no expansion at all.
	"x2cp /tmp/x /usr/local/bin/agentshield",
	// Homebrew coreutils' g-prefixed tools.
	"gcp /tmp/x /usr/local/bin/agentshield",
	"gmv /tmp/x /usr/local/bin/agentshield",
	"gln -sf /tmp/x /opt/homebrew/bin/agentshield",
	"ginstall -m 755 /tmp/x /opt/homebrew/bin/agentshield",
}

// binaryReplaceFoldedReadings are the rows the Codex pass on #4642 found (pass
// 3, reproduced through the managed hook). The raw text is not the #4637 shape,
// but NormalizeUnsetParamExp folds the whole expansion away, leaving
// `echo mcp agentshield`, which the exclusion recognises. zsh runs the quoted
// move inside the expansion. main BLOCKs each through the folded reading, so
// each must keep sp-block-binary-replace: the exclusion applies only when the
// raw command itself is the shape.
var binaryReplaceFoldedReadings = []string{
	"echo mc${zqx#$('mv' /tmp/agentshield.new /usr/local/bin/agentshield)}p agentshield",
	`echo mc${zqx#$("mv" /tmp/agentshield.new /usr/local/bin/agentshield)}p agentshield`,
	"echo mc${zqx%$('cp' /tmp/agentshield.new /opt/homebrew/bin/agentshield)}p agentshield",
	"echo mc${zqx}p agentshield",
}

func TestBinaryReplace_MCPShapeExcluded_4637(t *testing.T) {
	// Control first: the plain TP must match, or the rows below prove nothing.
	if id, ok := matchesSelfProtectRule("cp /tmp/x /usr/local/bin/agentshield"); !ok || id != binaryReplaceRule {
		t.Fatalf("positive control: got (%q, %v), want (%q, true)", id, ok, binaryReplaceRule)
	}

	t.Run("the #4637 shape matches no rule", func(t *testing.T) {
		for _, cmd := range binaryReplaceShape4637 {
			// Each row must be one the pattern matches, or excluding it
			// proves nothing about the exclusion.
			if !selfProtectPattern(t, binaryReplaceRule).MatchString(cmd) {
				t.Errorf("%q does not match the pattern; the row is vacuous", cmd)
			}
			if id, ok := matchesSelfProtectRule(cmd); ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want no match", cmd, id)
			}
		}
	})

	t.Run("next to the shape keeps main's BLOCK", func(t *testing.T) {
		for _, cmd := range binaryReplaceKeepsMain {
			if id, ok := matchesSelfProtectRule(cmd); !ok || id != binaryReplaceRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s", cmd, id, ok, binaryReplaceRule)
			}
		}
	})

	t.Run("real replacements stay blocked", func(t *testing.T) {
		for _, cmd := range binaryReplaceStillBlocked {
			if id, ok := matchesSelfProtectRule(cmd); !ok || id != binaryReplaceRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s", cmd, id, ok, binaryReplaceRule)
			}
		}
	})

	t.Run("pass-1 drops stay blocked", func(t *testing.T) {
		for _, cmd := range binaryReplacePass1Drops {
			if id, ok := matchesSelfProtectRule(cmd); !ok || id != binaryReplaceRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s", cmd, id, ok, binaryReplaceRule)
			}
		}
	})

	t.Run("a folded reading never earns the exclusion", func(t *testing.T) {
		for _, cmd := range binaryReplaceFoldedReadings {
			if id, ok := matchesSelfProtectRule(cmd); !ok || id != binaryReplaceRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s", cmd, id, ok, binaryReplaceRule)
			}
		}
	})

	// main BLOCKs these only because `install` sits inside `uninstall` and
	// `reinstall`. #4662 gives them a rule of their own; until then, and
	// after, they must stay blocked (the id is #4662's business).
	t.Run("brew removal of agentshield stays blocked", func(t *testing.T) {
		for _, cmd := range []string{
			"brew uninstall --cask agentshield",
			"brew reinstall --cask agentshield",
		} {
			if id, ok := matchesSelfProtectRule(cmd); !ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, false), want a self-protection block", cmd, id)
			}
		}
	})
}

func selfProtectPattern(t *testing.T, id string) *regexp.Regexp {
	t.Helper()
	for _, rule := range selfProtectRules {
		if rule.ID == id {
			return rule.Pattern
		}
	}
	t.Fatalf("no self-protection rule %q", id)
	return nil
}
