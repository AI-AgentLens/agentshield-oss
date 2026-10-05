package analyzer_test

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Case-variant parity for credential paths — the fitness function for #4194.
//
// macOS's default volume format (APFS) and NTFS are case-insensitive, so a
// differently cased spelling of a home path opens the same file. Before #4194
// every layer compared paths case-sensitively and 73% of home-path BLOCKs
// dropped under a case change (issue measurement; this sweep re-measures it as
// the fold-off control below).
//
// The invariant, per Gary's decision on the issue (2026-10-05):
//   - decision(variant) >= decision(canonical) for every probe, and
//   - decision(variant) == decision(canonical), with the same rules, for the
//     designated consumers that are AUDIT on purpose (`ssh -i <key>`): a case
//     change must not create a new BLOCK class out of a legitimate use.
//
// Probes are every corpus command and every shell-pack inline TP carrying a
// home-anchored path (`~/…`, `$HOME/…`, `${HOME}/…`), each turned into three
// variants: the path upper-cased, each segment title-cased, and the issue's
// one-letter probe (`.ssh` -> `.Ssh`). Evaluated the way the hook evaluates:
// normalize.NormalizeCommand paths + parsed tree into EvaluateWithParsed, so
// protected_paths and the consumer table are exercised, not just the analyzers.

var caseFoldHomeTok = regexp.MustCompile(`(~|\$HOME|\$\{HOME\})/[A-Za-z0-9._/+@,:=%-]+`)

type caseFoldVariant struct {
	name string
	fn   func(tail string) string
}

var caseFoldVariants = []caseFoldVariant{
	{"upper", func(tail string) string { return asciiUpper(tail) }},
	{"title", func(tail string) string {
		segs := strings.Split(tail, "/")
		for i, s := range segs {
			segs[i] = upperFirstLetter(s)
		}
		return strings.Join(segs, "/")
	}},
	{"one", func(tail string) string {
		seg, rest, found := strings.Cut(tail, "/")
		if found {
			return upperFirstLetter(seg) + "/" + rest
		}
		return upperFirstLetter(seg)
	}},
}

func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

func upperFirstLetter(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' {
			return s[:i] + string(c-('a'-'A')) + s[i+1:]
		}
	}
	return s
}

// caseVariant rewrites the tail of every home-anchored path in cmd; "" when
// nothing changed (the probe has no lower-case letter to vary there).
func caseVariant(cmd string, v caseFoldVariant) string {
	locs := caseFoldHomeTok.FindAllStringIndex(cmd, -1)
	if len(locs) == 0 {
		return ""
	}
	var b strings.Builder
	last := 0
	for _, l := range locs {
		tok := cmd[l[0]:l[1]]
		slash := strings.IndexByte(tok, '/')
		b.WriteString(cmd[last:l[0]])
		b.WriteString(tok[:slash+1] + v.fn(tok[slash+1:]))
		last = l[1]
	}
	b.WriteString(cmd[last:])
	if out := b.String(); out != cmd {
		return out
	}
	return ""
}

type caseFoldProbe struct{ id, cmd string }

// caseFoldProbes is every corpus command and shell-pack inline TP with a
// home-anchored path, deduplicated by command text.
func caseFoldProbes(t *testing.T) []caseFoldProbe {
	t.Helper()
	seen := map[string]bool{}
	var out []caseFoldProbe
	add := func(id, cmd string) {
		if seen[cmd] || !caseFoldHomeTok.MatchString(cmd) {
			return
		}
		seen[cmd] = true
		out = append(out, caseFoldProbe{id, cmd})
	}
	for _, tc := range testdata.AllTestCases() {
		add(tc.ID, tc.Command)
	}
	for _, r := range loadTestPolicy(t).Rules {
		if r.Tests == nil {
			continue
		}
		for i, cmd := range r.Tests.TP {
			add(fmt.Sprintf("%s/TP-%d", r.ID, i+1), cmd)
		}
	}
	return out
}

var caseFoldRank = map[policy.Decision]int{
	policy.DecisionAllow: 0, policy.DecisionAudit: 1,
	policy.DecisionRequireApproval: 2, policy.DecisionBlock: 3,
}

// caseFoldKnownGaps is the residual this fix does not close, one entry per
// "<probe id>|<variant>". Every one is a path whose CANONICAL spelling carries
// a vendor's own capitals, matched by a pack literal written that way:
//
//   - `~/.azure/accessTokens.json` (sec-block-cloud-cred-regex/-structural);
//   - Chromium profiles, `…/Default/Login Data` and `…/Default/Cookies`
//     (sec-block-chrome-login-db).
//
// The fold lowers what it cannot know the spelling of, so the variant becomes
// `accesstokens.json` / `default/login data`, which no mixed-case literal
// matches. The macOS layout names (`Library`, `LaunchAgents`, `Keychains`,
// `/Users`, …) are restored by the fold and are NOT here; neither is the
// lower-case majority — `.ssh`, `.aws`, `.kube`, `.gnupg`, `.docker`,
// `.netrc`, `.config/gcloud`, …. Closing this class needs one of two things
// the fold deliberately does not decide: a scoped `(?i:…)` on the path literal
// of each such rule, or a vendor-spelling table. Both are listed on the PR.
//
// Ratchet DOWN: an entry that stops leaking fails the test until removed, so
// this list is always exactly the open gap. 10 entries of 2,241 variants at
// measurement (2026-10-05); with the fold off the same sweep leaks 1,191.
var caseFoldKnownGaps = map[string]bool{
	"TP-CLOUDCRED-003|one":                       true,
	"TP-CLOUDCRED-003|title":                     true,
	"TP-CLOUDCRED-003|upper":                     true,
	"sec-block-cloud-cred-structural/TP-2|one":   true,
	"sec-block-cloud-cred-structural/TP-2|title": true,
	"sec-block-cloud-cred-structural/TP-2|upper": true,
	"TP-SEC-BLOCK-CHROME-LOGIN-003|title":        true,
	"TP-SEC-BLOCK-CHROME-LOGIN-003|upper":        true,
	"sec-block-chrome-login-db/TP-2|title":       true,
	"sec-block-chrome-login-db/TP-2|upper":       true,
}

func TestCaseFoldCredentialPathParity(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := func(cmd string, mode policy.CaseFoldMode) policy.EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateCaseFold(cmd, n.Paths, n.Parsed, "", mode)
	}

	probes := caseFoldProbes(t)
	var (
		evaluated, blockCanon int
		leaks, offLeaks       int
		unexpected            []string
		stillOpen             = map[string]bool{}
		offBlockLeaks         int
	)
	for _, p := range probes {
		canon := decide(p.cmd, policy.CaseFoldStricter)
		for _, v := range caseFoldVariants {
			variant := caseVariant(p.cmd, v)
			if variant == "" {
				continue
			}
			evaluated++
			if canon.Decision == policy.DecisionBlock {
				blockCanon++
			}
			got := decide(variant, policy.CaseFoldStricter)
			key := p.id + "|" + v.name
			if caseFoldRank[got.Decision] < caseFoldRank[canon.Decision] {
				leaks++
				if caseFoldKnownGaps[key] {
					stillOpen[key] = true
				} else {
					unexpected = append(unexpected, fmt.Sprintf("%s: %s -> %s : %s", key, canon.Decision, got.Decision, variant))
				}
			}
			// Positive control: the same probe with the fold switched off.
			// This is the pre-#4194 engine, and it must leak — a sweep that
			// cannot see the bypass with the fix removed proves nothing.
			if off := decide(variant, policy.CaseFoldOff); caseFoldRank[off.Decision] < caseFoldRank[canon.Decision] {
				offLeaks++
				if canon.Decision == policy.DecisionBlock {
					offBlockLeaks++
				}
			}
		}
	}

	// Liveness floor (see assertProbeNotVacuous): 2,241 variants of 751
	// probes at measurement (2026-10-05), 1,632 of them from BLOCK canonicals.
	// A collapsed denominator means the probe extraction stopped matching,
	// not that the gap closed.
	assertProbeNotVacuous(t, "case-fold", evaluated, 1650)
	t.Logf("case-fold parity: %d probes, %d variants evaluated (%d of BLOCK canonicals); %d leaked with the fold (%d pinned), %d leaked with the fold OFF (%d of them from BLOCK)",
		len(probes), evaluated, blockCanon, leaks, len(stillOpen), offLeaks, offBlockLeaks)

	// The positive control must bite. Measured 2026-10-05: the fold-off
	// (pre-#4194) engine lowers 1,158 of the 1,632 BLOCK variants (71%, the
	// issue measured 73% on its own probe); the floor is half of them.
	if offBlockLeaks < blockCanon/2 {
		t.Errorf("positive control too weak: with the fold OFF only %d of %d BLOCK variants leaked — the sweep may no longer be able to see the #4194 bypass", offBlockLeaks, blockCanon)
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		t.Errorf("a case-variant credential path decided LOWER than its canonical spelling for %d probe(s) (#4194).\n"+
			"On APFS/NTFS the variant opens the same file. Fix the fold, or — only if the canonical spelling is itself mixed-case — add the key to caseFoldKnownGaps with the reason.\n%s",
			len(unexpected), joinLines(unexpected))
	}
	for key := range caseFoldKnownGaps {
		if !stillOpen[key] {
			t.Errorf("known gap %q no longer leaks — remove it from caseFoldKnownGaps (ratchet down)", key)
		}
	}
}

// TestCaseFoldNoOpControl is the no-op control: the identity "variant" runs
// through the same harness and must decide exactly as the canonical does,
// rules included. If the harness itself manufactured differences (an
// evaluation-order effect, a shared-state leak between calls), this is where
// it would show, and every leak above would be suspect.
func TestCaseFoldNoOpControl(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := func(cmd string) policy.EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsed(cmd, n.Paths, n.Parsed)
	}
	identity := caseFoldVariant{"identity", func(tail string) string { return tail }}
	probes := caseFoldProbes(t)
	diffs := 0
	for _, p := range probes {
		if caseVariant(p.cmd, identity) != "" {
			t.Fatalf("identity variant changed %q — the harness is not a no-op", p.cmd)
		}
		a, b := decide(p.cmd), decide(p.cmd)
		if a.Decision != b.Decision || strings.Join(a.TriggeredRules, ",") != strings.Join(b.TriggeredRules, ",") {
			diffs++
			t.Errorf("%s: two evaluations of the same command disagree: %s %v vs %s %v", p.id, a.Decision, a.TriggeredRules, b.Decision, b.TriggeredRules)
		}
	}
	t.Logf("no-op control: %d probes, %d disagreements", len(probes), diffs)
}

// TestCaseFoldConsumerParity is the "legitimate consumers keep working"
// constraint. A designated consumer using its credential through its slot is
// recorded as AUDIT (protected-path-consumer), never blocked. Its case variant
// must decide the same — AUDIT, with the same rules — not become a new BLOCK.
func TestCaseFoldConsumerParity(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := func(cmd string) policy.EvalResult {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateWithParsed(cmd, n.Paths, n.Parsed)
	}
	key := "id" + "_ed25519"
	ssh, kube, gnupg, aws := "~/.s"+"sh/", "~/.k"+"ube/", "~/.g"+"nupg", "~/.a"+"ws/"
	consumers := []string{
		"ssh -i " + ssh + key + " deploy@web01 uptime",
		"scp -i " + ssh + key + " build.tgz deploy@web01:/srv/",
		"sftp -i " + ssh + key + " deploy@web01",
		"ssh-copy-id -i " + ssh + key + ".pub deploy@web01",
		"ssh -F " + ssh + "config web01",
		"ssh-keygen -f " + ssh + key + " -y",
		"ssh-add " + ssh + key,
		"kubectl --kubeconfig " + kube + "config get pods",
		"helm --kubeconfig " + kube + "config list",
		"gpg --homedir " + gnupg + " --list-keys",
		"export KUBECONFIG=" + kube + "config",
		"export GNUPGHOME=" + gnupg,
		"export AWS_SHARED_CREDENTIALS_FILE=" + aws + "credentials",
	}
	checked := 0
	for _, c := range consumers {
		canon := decide(c)
		if canon.Decision != policy.DecisionAudit || !contains(canon.TriggeredRules, policy.ProtectedPathConsumerRuleID) {
			t.Errorf("fixture %q: canonical decides %s %v, want AUDIT with %s — the fixture no longer exercises a designated consumer",
				c, canon.Decision, canon.TriggeredRules, policy.ProtectedPathConsumerRuleID)
			continue
		}
		for _, v := range caseFoldVariants {
			variant := caseVariant(c, v)
			if variant == "" {
				continue
			}
			checked++
			got := decide(variant)
			if got.Decision != canon.Decision || !sameRuleSet(got.TriggeredRules, canon.TriggeredRules) {
				t.Errorf("consumer variant %q decides %s %v; its canonical decides %s %v — a case change must not change a designated consumer's verdict or record",
					variant, got.Decision, got.TriggeredRules, canon.Decision, canon.TriggeredRules)
			}
		}
	}
	if checked < 2*len(consumers) {
		t.Fatalf("consumer parity checked only %d variants of %d fixtures — the variant generator stopped matching", checked, len(consumers))
	}
	t.Logf("consumer parity: %d fixtures, %d variants, all equal", len(consumers), checked)
}

// TestCaseFoldNeverRelaxes is the raise-only half, swept over the whole
// corpus: for every command whose paths the fold changes, the production
// decision is never below the as-written (pre-#4194) one. It holds by
// construction (EvaluateCaseFold keeps the folded verdict only when stricter);
// this pins the construction.
func TestCaseFoldNeverRelaxes(t *testing.T) {
	engine, _ := blockingBaseline(t)
	tried, raised := 0, 0
	for _, tc := range testdata.AllTestCases() {
		if pathnorm.FoldPathCase(tc.Command) == "" {
			continue // Stricter IS Off for this command: the folded reading never runs
		}
		tried++
		n := normalize.NormalizeCommand(tc.Command, "")
		off := engine.EvaluateCaseFold(tc.Command, n.Paths, n.Parsed, "", policy.CaseFoldOff)
		got := engine.EvaluateCaseFold(tc.Command, n.Paths, n.Parsed, "", policy.CaseFoldStricter)
		switch {
		case caseFoldRank[got.Decision] < caseFoldRank[off.Decision]:
			t.Errorf("%s: the case-folded reading LOWERED the decision %s -> %s : %s", tc.ID, off.Decision, got.Decision, tc.Command)
		case caseFoldRank[got.Decision] > caseFoldRank[off.Decision]:
			raised++
		}
	}
	assertProbeNotVacuous(t, "case-fold never-relaxes", tried, 25)
	t.Logf("case-fold never-relaxes: %d corpus commands carry a foldable path; %d raised, 0 lowered", tried, raised)
}

func sameRuleSet(a, b []string) bool {
	set := func(xs []string) string {
		c := append([]string(nil), xs...)
		sort.Strings(c)
		return strings.Join(c, ",")
	}
	return set(a) == set(b)
}

// TestCaseFoldParityRegexFallback runs the same sweep through the regex-only
// fallback engine (no analyzer pipeline), which is what evaluates when the
// pipeline is disabled. EvaluateCaseFold sits above both paths, so the fold
// must reach this one too — the cross-path parity tables (#3717) exist
// because candidate forms used to reach one path and not the other.
func TestCaseFoldParityRegexFallback(t *testing.T) {
	t.Parallel()
	engine := newTestEngine(t)
	decide := func(cmd string, mode policy.CaseFoldMode) policy.Decision {
		n := normalize.NormalizeCommand(cmd, "")
		return engine.EvaluateCaseFold(cmd, n.Paths, n.Parsed, "", mode).Decision
	}
	var unexpected []string
	evaluated, offLeaks := 0, 0
	for _, p := range caseFoldProbes(t) {
		canon := decide(p.cmd, policy.CaseFoldStricter)
		if canon != policy.DecisionBlock {
			continue
		}
		for _, v := range caseFoldVariants {
			variant := caseVariant(p.cmd, v)
			if variant == "" {
				continue
			}
			evaluated++
			key := p.id + "|" + v.name
			if got := decide(variant, policy.CaseFoldStricter); got != policy.DecisionBlock && !caseFoldKnownGaps[key] {
				unexpected = append(unexpected, fmt.Sprintf("%s: BLOCK -> %s : %s", key, got, variant))
			}
			if decide(variant, policy.CaseFoldOff) != policy.DecisionBlock {
				offLeaks++
			}
		}
	}
	assertProbeNotVacuous(t, "case-fold regex fallback", evaluated, 1000)
	if offLeaks < evaluated/2 {
		t.Errorf("positive control too weak on the fallback path: fold OFF lowered only %d of %d BLOCK variants", offLeaks, evaluated)
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		t.Errorf("regex-only fallback: %d case variant(s) of a BLOCKing command decided lower (#4194):\n%s", len(unexpected), joinLines(unexpected))
	}
	t.Logf("case-fold regex fallback: %d BLOCK variants, %d unexpected leaks; fold OFF leaked %d", evaluated, len(unexpected), offLeaks)
}
