package enterprise

import "testing"

// Fix round 2 on #4664 (Gary, 2026-10-30: "fix all 4; Kai verifies; no pass
// 3"). Every TP row here is attributed to sp-block-brew-uninstall, and every
// one fails on the fix-round-1 head 2ed92c90: there it matched no rule, or
// (for a verb containing `install`) only sp-block-binary-replace.
func brewFixRound2TPs() map[string][]string {
	rows := map[string][]string{}
	for _, v := range brewFixRound1Verbs {
		// Item 1: a word that ends in an escaped `\>` / `\<`, or in a CR, is
		// an operand. Bash reads `x\>` as the word `x>`, and CR as a word
		// character, so the name after it is the next operand. Fix round 1
		// read the word as ending in a redirect (pass 2). Reading escapes
		// pair by pair makes an escaped `\;` a literal too.
		rows["escaped character or CR ends the word before the name"] = append(rows["escaped character or CR ends the word before the name"],
			"brew "+v+" x\\> agentshield",
			"brew "+v+" --cask \\> agentshield",
			"brew "+v+" --force x\\< agentshield",
			"brew "+v+" x\r agentshield",
			"brew "+v+" --cask other\r agentshield",
			"brew -v '"+v+"' --zap x\\> agentshield",
			"sudo brew "+v+" x\\> \"agentshield\"",
			"brew "+v+" x\\> \\\n  agentshield",
			"brew "+v+" --cask x\\; agentshield",
		)
		// Item 2: `.rb` on the name. A formula: cmd/uninstall.rb resolves
		// kegs through Formulary.to_rack (cli/named_args.rb:527), which takes
		// HOMEBREW_CELLAR/File.basename(ref, ".rb") (formulary.rb:1164), so
		// the bare name needs no file at all. A path loads the formula file
		// first (formulary.rb:1158, FromPathLoader :620, name = basename
		// ".rb" :653), as the tap's own Formula/agentshield.rb does. A cask
		// path loads by token_from_path, which drops the extension
		// (cask/cask_loader.rb:129, :815). unlink resolves default kegs the
		// same way (cmd/unlink.rb:31, cli/named_args.rb:567).
		rows[".rb name"] = append(rows[".rb name"],
			"brew "+v+" agentshield.rb",
			"brew "+v+" --formula --force agentshield.rb",
			"brew "+v+" AgentShield.RB",
			"brew "+v+" ./agentshield.rb",
			"brew "+v+" --cask /opt/homebrew/Library/Taps/ai-agentlens/homebrew-tap/Casks/agentshield.rb",
			"brew "+v+" $HOMEBREW_PREFIX/Library/Taps/ai-agentlens/homebrew-oss/Formula/agentshield.rb",
			"brew -v \""+v+"\" 'agentshield.rb'",
			"env HOMEBREW_NO_AUTO_UPDATE=1 brew "+v+" agentshield.rb>/dev/null",
		)
		// Item 3: a descriptor redirect before the name. Its `&` belongs to
		// the redirect (`N>&M`, `>&N`, `N<&M`, `&>file`), not a separator.
		rows["descriptor redirect before the name"] = append(rows["descriptor redirect before the name"],
			"brew "+v+" --cask 2>&1 agentshield",
			"brew "+v+" 2>&1 --force agentshield",
			"brew "+v+" >&2 agentshield",
			"brew "+v+" --cask <&0 agentshield",
			"brew "+v+" &>/dev/null agentshield",
			"brew "+v+" --zap &>>/tmp/brew.log --cask agentshield",
			"brew "+v+" 2>&- agentshield",
			"brew "+v+" >/dev/null 2>&1 agentshield",
			"brew -v '"+v+"' 2>&1 'agentshield'",
			"sudo -u admin brew "+v+" --cask 2>&1 agentshield",
		)
	}
	return rows
}

// brewCommandPosition are spellings with brew as the command word behind a
// prefix: wrappers, keywords, assignments, redirects, a path, or a string a
// shell runs. Item 4 anchors brew to command position, so these pin that the
// anchor keeps them. They match on 2ed92c90 too.
var brewCommandPosition = []string{
	"nohup brew rm agentshield",
	"time brew rm agentshield",
	"exec brew rm agentshield",
	"nice -n 10 brew rm agentshield",
	"timeout 60 brew remove --cask agentshield",
	"caffeinate -i brew rm agentshield",
	"arch -arm64 brew unlink agentshield",
	"arch -x86_64 /usr/local/bin/brew rm agentshield",
	"doas brew rm agentshield",
	"command -p brew rm agentshield",
	"noglob brew rm agentshield",
	"xargs brew rm agentshield </dev/null",
	"find . -maxdepth 0 -exec brew rm agentshield \\;",
	"eval brew rm agentshield",
	"eval \"brew rm agentshield\"",
	"if true; then brew rm agentshield; fi",
	"for i in 1; do brew rm agentshield; done",
	"true\nbrew rm agentshield",
	"! brew rm agentshield",
	">/dev/null brew rm agentshield",
	"2>&1 brew rm agentshield",
	"> /tmp/brew.log brew rm agentshield",
	"X=1 Y=2 brew rm agentshield",
	"sudo -E env PATH=/opt/homebrew/bin brew rm agentshield",
	"$HOMEBREW_PREFIX/bin/brew rm agentshield",
	"${HOMEBREW_PREFIX}/bin/brew rm agentshield",
	"\"$HOMEBREW_PREFIX\"/bin/brew rm agentshield",
	"$(brew --prefix)/bin/brew rm agentshield",
	"~/homebrew/bin/brew rm agentshield",
	"../bin/brew rm agentshield",
	"=brew rm agentshield",
	"case x in x) brew rm agentshield;; esac",
	"python3 -c \"import os; os.system('brew rm agentshield')\"",
	"zsh -c 'brew rm agentshield'",
	"sudo sh -c \"brew rm agentshield\"",
	"/usr/bin/env brew rm agentshield",
	"/usr/bin/sudo -u admin brew remove agentshield",
	"watch brew rm agentshield",
	"parallel brew rm ::: agentshield",
	"ssh localhost brew rm agentshield",
	"uv run brew unlink agentshield",
}

func TestSelfProtect_BrewUninstall_FixRound2_4664(t *testing.T) {
	t.Run("TP", func(t *testing.T) {
		n := 0
		for group, cmds := range brewFixRound2TPs() {
			for _, cmd := range cmds {
				n++
				if id, ok := matchesSelfProtectRule(cmd); !ok || id != brewUninstallRule {
					t.Errorf("%s: matchesSelfProtectRule(%q) = (%q, %v), want %s", group, cmd, id, ok, brewUninstallRule)
				}
			}
		}
		t.Logf("%d TP rows", n)
	})

	t.Run("command position kept", func(t *testing.T) {
		for _, cmd := range brewCommandPosition {
			if id, ok := matchesSelfProtectRule(cmd); !ok || id != brewUninstallRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s", cmd, id, ok, brewUninstallRule)
			}
		}
	})

	// Item 4: brew must be the command word. A word that only ends in brew,
	// or brew as an argument of a command that is not an exec wrapper, is
	// not Homebrew. Each row keeps main's result: sp-block-binary-replace
	// for a cp / mv / ln / install line, and no self-protection rule for the
	// rest. On 2ed92c90 every row was attributed to sp-block-brew-uninstall
	// (#4664, the Codex pass: `brew` matched as the suffix of `homebrew`).
	t.Run("brew not the command word keeps main's attribution", func(t *testing.T) {
		for _, tc := range []struct{ cmd, want string }{
			{"cp /tmp/homebrew rm agentshield", "sp-block-binary-replace"},
			{"cp homebrew rm agentshield", "sp-block-binary-replace"},
			{"cp -r /usr/local/Homebrew remove --cask agentshield", "sp-block-binary-replace"},
			{"mv /opt/homebrew rm agentshield", "sp-block-binary-replace"},
			{"mv old-brew remove --cask agentshield", "sp-block-binary-replace"},
			{"cp xbrew uninstall agentshield", "sp-block-binary-replace"},
			{"cp ~/homebrew -v rm agentshield", "sp-block-binary-replace"},
			{"ln -s /tmp/homebrew unlink agentshield", "sp-block-binary-replace"},
			{"install -m 755 /tmp/mybrew rm agentshield", "sp-block-binary-replace"},
			{"cp /tmp/brew rm agentshield", "sp-block-binary-replace"},
			{"cp brew rm agentshield", "sp-block-binary-replace"},
			{"echo homebrew rm agentshield", ""},
			{"echo brew rm agentshield", ""},
			{"ls /opt/homebrew rm agentshield", ""},
			{"which brew rm agentshield", ""},
			{"grep -r homebrew remove agentshield", ""},
			{"cat ~/notes/homebrew unlink agentshield", ""},
			{"PATH=/opt/homebrew/bin/brew rm agentshield", ""},
			{"> brew rm agentshield", ""},
			// A command word that only ends in brew is another program.
			{"homebrew rm agentshield", ""},
			{"/tmp/homebrew rm agentshield", ""},
			{"sudo xbrew remove agentshield", ""},
			{"true; mybrew unlink agentshield", ""},
		} {
			id, ok := matchesSelfProtectRule(tc.cmd)
			if tc.want == "" && ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want no self-protection rule (as on main)", tc.cmd, id)
			}
			if tc.want != "" && id != tc.want {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, %v), want %s (as on main)", tc.cmd, id, ok, tc.want)
			}
		}
	})

	// TNs for items 1 to 3: this rule must not claim them.
	t.Run("TN", func(t *testing.T) {
		for _, cmd := range []string{
			// The name as a redirect target after a descriptor operator.
			"brew rm --cask other >& agentshield",
			"brew rm --cask other &> agentshield",
			"brew rm --cask other 2>& agentshield",
			"brew rm --cask other &>agentshield",
			// A lone `&` (or `&&`) still ends the statement.
			"brew rm --cask other & agentshield status",
			"brew rm --cask other 2>&1 & agentshield status",
			"brew rm --cask other &>/dev/null & agentshield status",
			"brew rm --cask other & echo agentshield",
			"brew rm other 2>&1 & ls agentshield",
			"brew rm other && echo agentshield",
			// An escaped `>` before a real `&`: `x>` is a word, `&` ends the
			// statement.
			"brew rm --cask x\\>& agentshield status",
			// An escaped backslash before a real `>`: `x\` is a word and the
			// name is the redirect target.
			"brew rm --cask x\\\\> agentshield",
			"brew rm --cask \\\\> agentshield",
			// A newline or CRLF still ends the statement, with or without a
			// blank after it.
			"brew rm --cask other\n agentshield status",
			"brew rm --cask other\r\nagentshield status",
			"brew rm --cask other\t\n\tagentshield status",
			// `.rb` is the only suffix.
			"brew rm agentshield.rbx",
			"brew rm agentshield-beta.rb",
			"brew rm agentshield.rb.bak",
			"brew rm other.rb >/tmp/agentshield.rb",
		} {
			if id, ok := matchesSelfProtectRule(cmd); ok && id == brewUninstallRule {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true), want not %s", cmd, id, brewUninstallRule)
			}
		}
	})

	// brew upgrade stays allowed (Gary, 2026-10-30) in every new spelling.
	t.Run("upgrade is allowed and unmatched", func(t *testing.T) {
		for _, cmd := range []string{
			"brew upgrade agentshield.rb",
			"brew upgrade --cask x\\> agentshield",
			"brew upgrade x\r agentshield",
			"brew upgrade --cask 2>&1 agentshield",
			"brew upgrade &>/dev/null agentshield",
			"nohup brew upgrade agentshield",
			"brew -v 'upgrade' 2>&1 agentshield.rb",
			"/opt/homebrew/bin/brew upgrade --cask agentshield.rb",
		} {
			if id, ok := matchesSelfProtectRule(cmd); ok {
				t.Errorf("matchesSelfProtectRule(%q) = (%q, true); brew upgrade is allowed (Gary, 2026-10-30), keep it unmatched", cmd, id)
			}
		}
	})
}
