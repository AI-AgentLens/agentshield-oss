package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// TestPermissionBypassFlagShape pins the "split by shape" resolution of #3918
// (Gary, 2026-09-22) for the Claude Code permission-bypass flag family.
//
// The flag (`--dangerously-skip-permissions`, `dangerously_skip_permissions`,
// and spellings of the same decision) is detected on three surfaces — Shield
// shell, Shield MCP, and Comply static — and until #3918 the two Shield shell
// rules resolved to a different KINGDOM than Comply's eight static rules for
// the identical flag. check-surface-agreement cannot see that pair: it reads
// packs/ only, by design (workspace CLAUDE.md, invariant 3). This test is the
// Shield half of the contract that keeps the split from silently coming back.
//
// The rule, by the shape of the MATCH rather than by surface:
//
//   - a match whose tool- or command-naming field contains a spawn/launch verb
//     observes the delegation itself (an agent creating another agent with the
//     gate off) and resolves to
//     privilege-escalation/agent-containment/agent-delegation-escalation;
//   - a match that observes the flag and nothing else is one configuration
//     decision at one invocation site and resolves to
//     unauthorized-execution/agentic-attacks/agent-approval-gate-disabled —
//     the node Comply's static rules already use for the same flag;
//   - a match in which the flag is one step of a stateful chain or an MCP
//     sequence (an artifact entering the workspace, then an ungated agent) is
//     a third shape. Its node must describe the chain, not the flag, so the
//     only assertion made here is the half of the shape rule that applies: no
//     spawn verb, no delegation.
//
// Both alternatives were rejected: keeping everything on delegation leaves the
// cross-repo disagreement in place; moving everything to approval-gate would
// strip the delegation observation out of mcp-agentic-block-agent-spawn-dsp-flag,
// whose tool_name_regex requires the spawn verb.
//
// What the classifier reads, and what it does not (hardened after a Codex
// adversarial review of the first cut, PR #3961):
//
//   - The FLAG is looked for in every positive scalar and key of match:, so an
//     argument KEY (`dangerously_skip_permissions:`), a chain step's
//     `flags_any`, and a sequence step all count. `*_exclude`, `*_downgrade`
//     and `*_not_*` predicates name what a rule ignores and are skipped.
//   - The SPAWN VERB is looked for only in the fields that name the tool or
//     the command (`tool_name*`, `tool_pattern`, `command_*`, `executable*`,
//     `binary`/`binaries`), at any depth. The first cut scanned the whole
//     flattened match with `\b` boundaries, so `^spawn_agent$` read as NO verb
//     (`_` is a word character) while `argument_regex_patterns: {task: ^run$}`
//     read as a spawn. TestPermissionBypassClassifier pins both directions.
//
// Denominator, stated honestly: the walker sees every mapping carrying id:,
// taxonomy: AND a match: mapping. On 2026-09-22 that is 3436 of 3608
// id+taxonomy mappings; the other 172 (sentinels and engine-backed rules with
// no match: block) are invisible to it, and the test logs the count so a
// change in that gap is visible. The five rules known on 2026-09-22 are
// asserted present as a positive control, so a walker or regex regression
// cannot pass vacuously.
func TestPermissionBypassFlagShape(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	packs := filepath.Join("..", "..", "packs")
	if _, err := os.Stat(packs); err != nil {
		t.Fatalf("packs dir: %v", err)
	}

	rules, noMatch, err := scanRulesWithMatch(packs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 1000 {
		t.Fatalf("walked only %d rules under %s — the scan is not seeing the corpus", len(rules), packs)
	}

	var found []flagRule
	for _, r := range rules {
		if r.shape.flag {
			found = append(found, r)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].id < found[j].id })
	t.Logf("scanned %d rules with a match: block (%d id+taxonomy mappings have none and are invisible here); %d match the permission-bypass flag family",
		len(rules), noMatch, len(found))

	// Positive control: the rules the decision was made over must all be seen.
	// If one of them disappears, the assertion below is silently weaker.
	known := []string{
		"ts-block-claude-dangerous-skip-permissions",                      // bare flag  → approval-gate
		"ts-block-npx-claude-dangerous-skip",                              // bare flag  → approval-gate
		"mcp-agentic-block-agent-spawn-dsp-flag",                          // spawn verb → delegation
		"ts-block-untrusted-clone-agent-review-privilege-inversion",       // chain
		"ts-block-untrusted-pr-checkout-agent-review-privilege-inversion", // chain
	}
	seen := map[string]bool{}
	for _, r := range found {
		seen[r.id] = true
	}
	for _, id := range known {
		if !seen[id] {
			t.Errorf("positive control: %s not found among flag-matching rules — the walker or the flag regex regressed", id)
		}
	}

	for _, r := range found {
		switch {
		case r.shape.spawn:
			if r.taxonomy != delegationNode {
				t.Errorf("%s (%s): tool/command field contains a spawn verb, so the delegation is observed; want %s, got %s",
					r.id, r.file, delegationNode, r.taxonomy)
			}
			t.Logf("  %-64s spawn-verb  → delegation      (%s)", r.id, ok(r.taxonomy == delegationNode))
		case r.shape.compound:
			if r.taxonomy == delegationNode {
				t.Errorf("%s (%s): chain/sequence with no spawn verb in a tool/command field cannot claim %s — delegation requires the spawn to be in the match",
					r.id, r.file, delegationNode)
			}
			t.Logf("  %-64s chain       → %s", r.id, r.taxonomy)
		default:
			if r.taxonomy != approvalGateNode {
				t.Errorf("%s (%s): match observes the flag and nothing else; want %s (the node Comply's static rules use for this flag), got %s",
					r.id, r.file, approvalGateNode, r.taxonomy)
			}
			t.Logf("  %-64s bare-flag   → approval-gate   (%s)", r.id, ok(r.taxonomy == approvalGateNode))
		}
	}
}

// TestPermissionBypassClassifier tests the classifier on synthetic match:
// fragments, independent of the live corpus. Each row is the exact case the
// Codex review of PR #3961 showed the first cut getting wrong, plus the
// controls around it.
func TestPermissionBypassClassifier(t *testing.T) {
	rows := []struct {
		name  string
		match string
		want  ruleShape
	}{
		{"mcp spawn verb + flag key (the live rule shape)",
			"tool_name_regex: \"(?i)(spawn|create|launch)[_-]?(agent|worker)s?\"\nargument_regex_patterns:\n  dangerously_skip_permissions: \"^(1|true)$\"\n",
			ruleShape{flag: true, spawn: true}},
		{"anchored snake_case tool name is a spawn",
			"tool_name_regex: \"^spawn_agent$\"\nargument_regex_patterns:\n  dangerously_skip_permissions: \"^true$\"\n",
			ruleShape{flag: true, spawn: true}},
		{"anchored kebab-case tool name is a spawn",
			"tool_name_regex: \"^spawn-agent$\"\nargument_regex_patterns:\n  dangerously_skip_permissions: \"^true$\"\n",
			ruleShape{flag: true, spawn: true}},
		{"exact tool_name is a spawn",
			"tool_name: run_agent\nargument_regex_patterns:\n  dangerously_skip_permissions: \"^true$\"\n",
			ruleShape{flag: true, spawn: true}},
		{"tool_name_any list is a spawn",
			"tool_name_any: [\"task_*\", \"launch_subagent\"]\nargument_regex_patterns:\n  dangerously_skip_permissions: \"^true$\"\n",
			ruleShape{flag: true, spawn: true}},
		{"a verb in an ARGUMENT pattern is not a spawn",
			"tool_name_regex: \"^configure_session$\"\nargument_regex_patterns:\n  task: \"^run$\"\n  dangerously_skip_permissions: \"^true$\"\n",
			ruleShape{flag: true, spawn: false}},
		{"a verb in an exclude predicate is not a spawn",
			"tool_name_regex: \"^configure_session$\"\ntool_name_regex_exclude: \"^spawn_\"\nargument_regex_patterns:\n  dangerously_skip_permissions: \"^true$\"\n",
			ruleShape{flag: true, spawn: false}},
		{"a verb in a tool_name_not_prefix_any predicate is not a spawn",
			"tool_name_regex: \"^configure_session$\"\ntool_name_not_prefix_any: [\"create_\"]\nargument_regex_patterns:\n  dangerously_skip_permissions: \"^true$\"\n",
			ruleShape{flag: true, spawn: false}},
		{"shell bare flag (the live community shape)",
			"command_regex: \\bclaude\\b.*--dangerously-skip-permissions\\b\ncommand_regex_exclude: 'sed .*--dangerously-skip-permissions'\n",
			ruleShape{flag: true, spawn: false}},
		{"shell bare flag with a verb only in the exclude",
			"command_regex: \\bclaude\\b.*--dangerously-skip-permissions\\b\ncommand_regex_exclude: '(?:^|&&\\s*)run-tests .*--dangerously-skip-permissions'\n",
			ruleShape{flag: true, spawn: false}},
		{"shell command_regex naming a launcher verb is a spawn",
			"command_regex: \\bspawn-agent\\b.*--dangerously-skip-permissions\\b\n",
			ruleShape{flag: true, spawn: true}},
		{"permission-mode with the bypass value is the flag",
			"command_regex: \\bclaude\\b.*--permission-mode[= ]bypassPermissions\\b\n",
			ruleShape{flag: true, spawn: false}},
		{"permission-mode=bypass (short spelling) is the flag",
			"command_regex: --permission-mode=bypass\n",
			ruleShape{flag: true, spawn: false}},
		{"bare --permission-mode selector is NOT the flag (see permissionBypassFlag)",
			"command_regex: \\bclaude\\b.*--permission-mode\\b\n",
			ruleShape{}},
		{"permission-mode with a non-bypass value is NOT the flag",
			"command_regex: --permission-mode[= ]plan\\b\n",
			ruleShape{}},
		{"stateful chain step carrying the flag is compound",
			"stateful:\n  chain:\n    - executable_any: [\"git\"]\n      operator: \"&&\"\n    - executable_any: [\"claude\", \"codex\"]\n      flags_any: [\"dangerously-skip-permissions\", \"yolo\"]\n",
			ruleShape{flag: true, compound: true}},
		{"stateful chain whose executable is a launcher verb is compound AND spawn",
			"stateful:\n  chain:\n    - executable_any: [\"git\"]\n      operator: \"&&\"\n    - executable_any: [\"spawn-agent\"]\n      flags_any: [\"dangerously-skip-permissions\"]\n",
			ruleShape{flag: true, spawn: true, compound: true}},
		{"mcp sequence step carrying the flag is compound",
			"sequence:\n  - tool_name_any: [\"read_file\"]\n  - tool_name_regex: \"^configure_session$\"\n    argument_regex_patterns:\n      dangerously_skip_permissions: \"^true$\"\n",
			ruleShape{flag: true, compound: true}},
		{"no flag anywhere",
			"tool_name_regex: \"^spawn_agent$\"\nargument_regex_patterns:\n  model: \"^claude\"\n",
			ruleShape{spawn: true}},
		{"flag only in an exclude is not the flag",
			"command_regex: \\bclaude\\b\ncommand_regex_exclude: --dangerously-skip-permissions\n",
			ruleShape{}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var doc yaml.Node
			if err := yaml.Unmarshal([]byte(row.match), &doc); err != nil {
				t.Fatalf("fragment does not parse: %v", err)
			}
			if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
				t.Fatalf("fragment is not a mapping")
			}
			got := classifyMatch(doc.Content[0])
			if got != row.want {
				t.Errorf("classifyMatch = %+v, want %+v\nfragment:\n%s", got, row.want, row.match)
			}
		})
	}
}

const (
	delegationNode   = "privilege-escalation/agent-containment/agent-delegation-escalation"
	approvalGateNode = "unauthorized-execution/agentic-attacks/agent-approval-gate-disabled"
)

func ok(b bool) string {
	if b {
		return "ok"
	}
	return "WRONG"
}

// permissionBypassFlag covers the CLI flag, the SDK/MCP argument name, the
// generic spellings of the same decision, and `--permission-mode` WITH the
// bypass value (`bypassPermissions`, or a `bypass…` value after the selector).
// Case-insensitive so camelCase argument keys match too.
//
// The bare `--permission-mode` selector is deliberately NOT a member: it also
// selects `default`, `plan` and `acceptEdits`, so a rule that matches the
// selector alone is matching mode changes in general, not the approval gate
// declared off, and forcing such a rule onto agent-approval-gate-disabled
// would be the wrong node for it. Only the value declares the gate off.
var permissionBypassFlag = regexp.MustCompile(`(?i)dangerously[-_]?skip[-_]?permissions|skip[-_]?permissions|bypass[-_]?permissions|permission[-_]?mode\W{0,3}bypass`)

// spawnVerb is the verb alternation mcp-agentic-block-agent-spawn-dsp-flag's
// tool_name_regex is built from. It is matched ONLY against the text of the
// tool- and command-naming fields (namingKeys), never against argument
// patterns or exclusions, and the verb may be preceded by an anchor or
// separator and followed by `_`, `-` or letters — so `^spawn_agent$`,
// `spawn-agent`, `run_agent` and `(spawn|create)[_-]?agent` all count.
var spawnVerb = regexp.MustCompile(`(?i)(?:^|[^a-z])(spawn|create|launch|run|invoke|start|fork|delegate|assign)(?:[_-]?[a-z]+)*`)

// namingKeys are the match: fields (at any depth — chain steps, sequence
// steps) whose value names the tool or the command a rule fires on.
var namingKeys = map[string]bool{
	"tool_name": true, "tool_name_regex": true, "tool_name_any": true, "tool_pattern": true,
	"command_exact": true, "command_prefix": true, "command_regex": true,
	"executable": true, "executable_any": true, "binary": true, "binaries": true,
}

// ignoredKey names a predicate that says what a rule does NOT fire on.
func ignoredKey(k string) bool {
	return strings.Contains(k, "exclude") || strings.Contains(k, "downgrade") || strings.Contains(k, "_not_")
}

type ruleShape struct {
	flag     bool // the permission-bypass flag family appears in the positive match
	spawn    bool // a spawn/launch verb appears in a tool- or command-naming field
	compound bool // match: carries a stateful chain or an MCP sequence
}

type flagRule struct {
	id, taxonomy, file string
	shape              ruleShape
}

// classifyMatch reads a rule's match: mapping and reports its shape.
func classifyMatch(match *yaml.Node) ruleShape {
	var positive, naming strings.Builder
	var s ruleShape
	for i := 0; i+1 < len(match.Content); i += 2 {
		k := match.Content[i].Value
		if k == "stateful" || k == "sequence" {
			s.compound = true
		}
	}
	walkPositive(match, false, &positive, &naming)
	s.flag = permissionBypassFlag.MatchString(positive.String())
	// A regex escape such as `\b` puts a letter directly before the verb
	// (`\bspawn-agent\b`), which the separator guard in spawnVerb would read
	// as part of a longer word. Escapes are separators, not letters.
	s.spawn = spawnVerb.MatchString(regexEscape.ReplaceAllString(naming.String(), " "))
	return s
}

// regexEscape is a backslash escape in regex source (`\b`, `\s`, `\d`, …).
var regexEscape = regexp.MustCompile(`\\[A-Za-z]`)

// walkPositive collects every key and scalar under n that is not beneath an
// ignored predicate into positive, and the scalars beneath a naming key into
// naming. inNaming is true while descending a naming key's value.
func walkPositive(n *yaml.Node, inNaming bool, positive, naming *strings.Builder) {
	switch n.Kind {
	case yaml.ScalarNode:
		positive.WriteString(n.Value)
		positive.WriteByte(' ')
		if inNaming {
			naming.WriteString(n.Value)
			naming.WriteByte(' ')
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if ignoredKey(k) {
				continue
			}
			positive.WriteString(k)
			positive.WriteByte(' ')
			walkPositive(n.Content[i+1], inNaming || namingKeys[k], positive, naming)
		}
	default:
		for _, c := range n.Content {
			walkPositive(c, inNaming, positive, naming)
		}
	}
}

// scanRulesWithMatch walks every YAML under dir and returns each mapping that
// carries id:, taxonomy: and a match: mapping — whatever section it sits in —
// plus the number of id+taxonomy mappings that carry NO match: block and are
// therefore invisible to the shape check.
func scanRulesWithMatch(dir string) ([]flagRule, int, error) {
	var out []flagRule
	noMatch := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		rel, _ := filepath.Rel(dir, path)
		visitRules(&doc, func(id, tax string, match *yaml.Node) {
			if match == nil {
				noMatch++
				return
			}
			out = append(out, flagRule{id: id, taxonomy: tax, file: rel, shape: classifyMatch(match)})
		})
		return nil
	})
	return out, noMatch, err
}

// visitRules calls visit for every mapping carrying id: and taxonomy:; match
// is nil when the mapping has no match: mapping.
func visitRules(n *yaml.Node, visit func(id, tax string, match *yaml.Node)) {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			visitRules(c, visit)
		}
	case yaml.MappingNode:
		var id, tax string
		var match *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			switch n.Content[i].Value {
			case "id":
				id = n.Content[i+1].Value
			case "taxonomy":
				tax = n.Content[i+1].Value
			case "match":
				if n.Content[i+1].Kind == yaml.MappingNode {
					match = n.Content[i+1]
				}
			}
		}
		if id != "" && tax != "" {
			visit(id, tax, match)
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			visitRules(n.Content[i+1], visit)
		}
	}
}
