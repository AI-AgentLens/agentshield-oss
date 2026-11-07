package enterprise

import "testing"

const brewUninstallRule = "sp-block-brew-uninstall"

// brewUninstallTPs builds the #4662 TP table: every removal verb Homebrew
// accepts, crossed with the flag spellings and the names the AgentShield
// package goes by. Each row must be attributed to sp-block-brew-uninstall, so
// every row fails on main: `remove`, `rm` and `uninstal` matched no rule
// there, and `uninstall` / `reinstall` matched sp-block-binary-replace only by
// accident (the `install` inside the verb).
func brewUninstallTPs() []string {
	verbs := []string{"uninstall", "remove", "rm", "reinstall", "uninstal"}
	flags := []string{
		"",
		"--cask ",
		"--zap ",
		"--zap --cask ",
		"--cask --zap ",
		"--force ",
		"-f ",
		"--cask --zap --force ",
		"--formula ",
		"--ignore-dependencies ",
	}
	var rows []string
	for _, verb := range verbs {
		for _, flag := range flags {
			rows = append(rows, "brew "+verb+" "+flag+"agentshield")
		}
		// Flags after the name, and the name among others.
		rows = append(rows,
			"brew "+verb+" agentshield --cask",
			"brew "+verb+" agentshield --zap --force",
			"brew "+verb+" --cask other agentshield",
			"brew "+verb+" --cask agentshield other",
		)
	}
	// Tap-qualified names (README: AI-AgentLens/tap and AI-AgentLens/oss;
	// docs/agent-integration.md: the legacy AI-AgentLens/oss), and
	// case, which Homebrew folds (cli/named_args.rb downcased_unique_named).
	rows = append(rows,
		"brew uninstall --cask ai-agentlens/tap/agentshield",
		"brew uninstall --cask AI-AgentLens/tap/agentshield",
		"brew uninstall AI-AgentLens/oss/agentshield",
		"brew uninstall --zap --cask AI-AgentLens/oss/agentshield",
		"brew rm ai-agentlens/tap/agentshield",
		"brew reinstall --cask ai-agentlens/tap/agentshield",
		"brew uninstall --cask AgentShield",
		"brew uninstall --cask AGENTSHIELD",
	)
	return rows
}

// brewUninstallWrapped are spellings with something in front of brew, after
// the name, or around the statement. The family's readings (dequoted,
// unset-param-folded) carry the quote and parameter splices.
var brewUninstallWrapped = []string{
	"sudo brew uninstall --cask agentshield",
	"sudo -u admin brew uninstall --cask agentshield",
	"env brew uninstall --cask agentshield",
	"env -i PATH=/opt/homebrew/bin brew uninstall --cask agentshield",
	"command brew uninstall --cask agentshield",
	"VAR=1 brew uninstall --cask agentshield",
	"HOMEBREW_NO_AUTO_UPDATE=1 brew remove --cask agentshield",
	"/opt/homebrew/bin/brew uninstall --cask agentshield",
	"/usr/local/bin/brew rm --cask agentshield",
	"./brew uninstall agentshield",
	"\\brew uninstall --cask agentshield",
	"$1brew uninstall --cask agentshield",
	"true; brew uninstall --cask agentshield",
	"true;brew rm agentshield",
	"brew update && brew uninstall --zap --cask agentshield",
	"true || brew reinstall --cask agentshield",
	"echo y | brew uninstall --cask agentshield",
	"brew uninstall --cask agentshield; echo done",
	"brew uninstall --cask agentshield && echo done",
	"brew uninstall --cask agentshield\necho done",
	"brew uninstall --cask agentshield 2>/dev/null",
	"(brew uninstall --cask agentshield)",
	"$(brew uninstall --cask agentshield)",
	"`brew uninstall --cask agentshield`",
	"{ brew uninstall --cask agentshield; }",
	"bash -c 'brew uninstall --cask agentshield'",
	"sh -c \"brew rm --cask agentshield\"",
	"brew uninstall --cask 'agentshield'",
	"brew uninstall --cask \"agentshield\"",
	"brew uninstall --cask agentshi'e'ld",
	"brew uninstall --cask agentshi${zqx}eld",
	"b'r'ew remove --cask agentshield",
	"b'r'ew rm --cask agentshield",
	"brew un'install' --cask agentshield",
	"brew uninstall\t--cask\tagentshield",
	"brew uninstall --cask \\\nagentshield",
	"brew uninstall \\\n  --zap --cask \\\n  agentshield",
	"brew \\\nrm agentshield\\\n --force",
}

func TestSelfProtect_BrewUninstall_4662(t *testing.T) {
	t.Run("TP", func(t *testing.T) {
		rows := append(brewUninstallTPs(), brewUninstallWrapped...)
		for _, cmd := range rows {
			if id, ok := matchesSelfProtectRule(cmd); !ok || id != brewUninstallRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s", cmd, id, ok, brewUninstallRule)
			}
		}
		t.Logf("%d TP rows", len(rows))
	})

	// TNs: another package, a read-only brew command, or agentshield in a
	// different statement from the removal. The assertion is that this rule
	// does not claim them (it precedes sp-block-binary-replace, so a match
	// would report its id). Some still match sp-block-binary-replace, whose
	// `install\s+.*agentshield` spans statements; that is #4637/#4642's
	// business, and the decision there is main's.
	t.Run("TN", func(t *testing.T) {
		for _, cmd := range []string{
			"brew uninstall --cask other",
			"brew uninstall other-formula",
			"brew info agentshield",
			"brew info --cask agentshield",
			"brew list",
			"brew list --cask agentshield",
			"brew search agentshield",
			"brew outdated --cask agentshield",
			"brew uninstall --cask agentshield-beta",
			"brew uninstall --cask other && agentshield status",
			"brew uninstall --cask other; agentshield status",
			"brew uninstall --cask other | grep agentshield",
			"brew uninstall --cask other\nagentshield status",
			"brew uninstall\nagentshield status",
			"brew uninstall",
			"agentshield status",
		} {
			if id, ok := matchesSelfProtectRule(cmd); ok && id == brewUninstallRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want not %s", cmd, id, brewUninstallRule)
			}
		}
	})

	// A splice that hides `brew` from the raw text but not `install` from
	// sp-block-binary-replace still BLOCKs, attributed to that rule: the raw
	// reading is tried against every rule before the dequoted one
	// (matchSelfProtectReadings). The decision is what matters here; the id
	// follows the family's reading order.
	t.Run("spliced uninstall blocks by reading order", func(t *testing.T) {
		for _, cmd := range []string{
			"b'r'ew uninstall --cask agentshield",
			"b${zqx}rew reinstall --cask agentshield",
		} {
			if id, ok := matchesSelfProtectRule(cmd); !ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, false), want a self-protection block", cmd, id)
			}
		}
	})

	// Allowed (Gary, 2026-10-30, #4664): `brew upgrade` runs the cask's
	// uninstall stanza too (#4535), but an upgrade reinstalls the guard
	// rather than removing it. Pinned unmatched, including through the
	// leading `-v` and the quoted verb that fix round 1 accepts, so that
	// changing it is a deliberate change, not a side effect of editing the
	// verb list.
	t.Run("upgrade is allowed and unmatched", func(t *testing.T) {
		for _, cmd := range []string{
			"brew upgrade agentshield",
			"brew upgrade --cask agentshield",
			"brew upgrade --cask ai-agentlens/tap/agentshield",
			"brew -v upgrade --cask agentshield",
			"brew \"upgrade\" agentshield",
			"brew upgrade agentshield>/dev/null",
		} {
			if id, ok := matchesSelfProtectRule(cmd); ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true); brew upgrade is allowed (Gary, 2026-10-30), keep it unmatched", cmd, id)
			}
		}
	})
}

// brewFixRound1Verbs are the rule's verbs after fix round 1 (#4664): the
// pass-1 set plus unlink (Gary, 2026-10-30).
var brewFixRound1Verbs = []string{"uninstall", "remove", "rm", "reinstall", "uninstal", "unlink"}

// brewFixRound1TPs are the #4664 pass-1 findings and the unlink addition.
// Every row is attributed to sp-block-brew-uninstall, and every row fails
// on the pass-1 head 3b786282: there it matched no rule, or (for a verb
// containing `install`) only sp-block-binary-replace by accident.
func brewFixRound1TPs() map[string][]string {
	rows := map[string][]string{}
	for _, v := range brewFixRound1Verbs {
		// Finding 1: a redirect directly after the name.
		rows["redirect after the name"] = append(rows["redirect after the name"],
			"brew "+v+" --cask agentshield>/dev/null",
			"brew "+v+" agentshield</dev/null",
			"brew "+v+" --cask agentshield>&2",
			"brew "+v+" agentshield>>/tmp/brew.log",
			"brew "+v+" --zap --cask ai-agentlens/tap/agentshield>/dev/null 2>&1",
			"brew "+v+" AgentShield<<<y",
		)
		// Finding 2: Homebrew's one leading `-v` (brew.sh shifts it to the
		// end of the arguments).
		rows["leading -v"] = append(rows["leading -v"],
			"brew -v "+v+" agentshield",
			"brew -v "+v+" --cask agentshield",
			"brew -v "+v+" --zap --force --cask agentshield",
			"brew -v "+v+" ai-agentlens/tap/agentshield",
			"brew -v "+v+" AGENTSHIELD",
			"brew -v \\\n"+v+" agentshield",
		)
		// Finding 3: the verb (and the `-v`) as one whole quoted word.
		rows["quoted verb"] = append(rows["quoted verb"],
			"brew \""+v+"\" agentshield",
			"brew '"+v+"' --cask agentshield",
			"brew \""+v+"\" --zap --cask ai-agentlens/tap/agentshield",
			"brew -v '"+v+"' agentshield",
			"brew '-v' '"+v+"' agentshield",
			"brew \"-v\" \""+v+"\" --cask agentshield",
		)
	}
	// unlink (Gary, 2026-10-30): unlink's own flags, the names, flags after
	// the name, and the name among others, as the pass-1 table has for the
	// other verbs.
	for _, flag := range []string{"", "--cask ", "--casks ", "--formula ", "--formulae "} {
		for _, name := range []string{
			"agentshield",
			"ai-agentlens/tap/agentshield",
			"AI-AgentLens/oss/agentshield",
			"AI-AgentLens/oss/agentshield",
			"AgentShield",
		} {
			rows["unlink"] = append(rows["unlink"], "brew unlink "+flag+name)
		}
	}
	rows["unlink"] = append(rows["unlink"],
		"brew unlink agentshield --cask",
		"brew unlink --formula other agentshield",
		"brew unlink agentshield other",
		"brew unlink 'agentshield'",
		"brew unlink \"ai-agentlens/tap/agentshield\"",
	)
	// Wrapped and chained, across the new forms.
	rows["wrapped"] = []string{
		"sudo brew unlink agentshield",
		"sudo -u admin brew -v rm --cask agentshield",
		"env brew -v remove agentshield",
		"env -i PATH=/opt/homebrew/bin brew unlink --cask agentshield",
		"command brew \"rm\" agentshield",
		"HOMEBREW_NO_AUTO_UPDATE=1 brew rm --cask agentshield>/dev/null",
		"/opt/homebrew/bin/brew unlink agentshield",
		"/usr/local/bin/brew -v rm --cask agentshield",
		"\\brew unlink agentshield",
		"true && brew unlink --cask agentshield",
		"brew update; brew -v remove --cask agentshield",
		"true || brew 'rm' agentshield",
		"echo y | brew \"remove\" --cask agentshield",
		"brew rm --cask agentshield>/dev/null; echo done",
		"brew -v rm agentshield && echo done",
		"(brew -v rm agentshield)",
		"$(brew unlink agentshield)",
		"`brew 'rm' agentshield`",
		"{ brew unlink agentshield; }",
		"bash -c 'brew -v rm --cask agentshield'",
		"sh -c \"brew unlink agentshield\"",
		"brew unlink agentshi'e'ld",
		"brew unlink agentshi${zqx}eld",
		"b'r'ew unlink agentshield",
		"brew un'link' agentshield",
		"brew -v r'm' agentshield",
		"brew unlink\t--cask\tagentshield",
		"brew unlink \\\n  --cask \\\n  agentshield",
		"brew \\\n-v \\\nrm agentshield",
	}
	return rows
}

// brewFixRound1TNs are the TNs for fix round 1's new parts (#4664). Each
// asserts that this rule does not claim the command, as the pass-1 TN table
// does.
var brewFixRound1TNs = []string{
	// A read-only command behind the leading -v or as a quoted word.
	"brew -v info agentshield",
	"brew -v list",
	"brew -v list --cask agentshield",
	"brew \"info\" agentshield",
	"brew 'list' --cask agentshield",
	// Only `-v` may stand before the verb, and only once. brew.sh takes any
	// other first word as the command: `--verbose`, `-d` and `-h` print
	// usage or help, `-v -v` prints the version, and `info` reads. Measured
	// on Homebrew 7.0.11.
	"brew info rm agentshield",
	"brew list remove agentshield",
	"brew --verbose rm agentshield",
	"brew -d rm --cask agentshield",
	"brew -h rm agentshield",
	"brew -v -v rm agentshield",
	// A quote pair must hold exactly the verb.
	"brew \"rm x\" agentshield",
	"brew 'rm\" agentshield",
	// unlink is a verb; link is not.
	"brew unlink other",
	"brew unlink --cask other",
	"brew unlink agentshield-beta",
	"brew link agentshield",
	"brew link --overwrite agentshield",
	// The name as a redirect target, not an operand. The pass-1 head
	// claimed the rm and remove rows here and the next row; it had no
	// unlink and no leading -v.
	"brew rm --cask other >/tmp/agentshield",
	"brew rm --cask other > agentshield",
	"brew remove other 2>/tmp/agentshield",
	"brew unlink other >>/tmp/agentshield",
	"brew rm --cask other </tmp/agentshield",
	"brew rm --cask other >\"/tmp/agentshield\"",
	"brew -v rm other <<<agentshield",
	// A redirect right after another package's name.
	"brew rm --cask other>/tmp/agentshield",
}

func TestSelfProtect_BrewUninstall_FixRound1_4664(t *testing.T) {
	t.Run("TP", func(t *testing.T) {
		n := 0
		for group, cmds := range brewFixRound1TPs() {
			for _, cmd := range cmds {
				n++
				if id, ok := matchesSelfProtectRule(cmd); !ok || id != brewUninstallRule {
					t.Errorf("%s: matchesSelfProtectRule(%q) = (%q, %v), want %s", group, cmd, id, ok, brewUninstallRule)
				}
			}
		}
		t.Logf("%d TP rows", n)
	})

	t.Run("TN", func(t *testing.T) {
		for _, cmd := range brewFixRound1TNs {
			if id, ok := matchesSelfProtectRule(cmd); ok && id == brewUninstallRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want not %s", cmd, id, brewUninstallRule)
			}
		}
	})
}

// The rule runs only on a managed host, like the rest of the family: the
// SelfProtect middleware is what blocks, and the hook adds it to the chain
// only when managed.json says managed (buildMiddlewareChain, internal/cli).
func TestSelfProtect_BrewUninstall_MiddlewareBlocks_4662(t *testing.T) {
	ctx := &EvalContext{Command: "brew uninstall --zap --cask agentshield"}
	nextCalled := false
	SelfProtect()(ctx, func() { nextCalled = true })
	if !ctx.Blocked || nextCalled {
		t.Fatalf("Blocked=%v nextCalled=%v, want a block that stops the chain", ctx.Blocked, nextCalled)
	}
	if want := "Blocked: attempt to modify AgentShield configuration (rule: " + brewUninstallRule + ")"; ctx.BlockMsg != want {
		t.Fatalf("BlockMsg = %q, want %q", ctx.BlockMsg, want)
	}
}
