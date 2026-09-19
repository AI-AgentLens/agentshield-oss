package mcp

import (
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/policy"

	"github.com/AI-AgentLens/agentshield/internal/unicode"
)

// MCPToolIntent represents a classified intent for an MCP tool call.
type MCPToolIntent string

const (
	IntentFileRead       MCPToolIntent = "file-read"
	IntentFileWrite      MCPToolIntent = "file-write"
	IntentFileDelete     MCPToolIntent = "file-delete"
	IntentCodeExecute    MCPToolIntent = "code-execute"
	IntentShellCommand   MCPToolIntent = "shell-command"
	IntentNetworkRequest MCPToolIntent = "network-request"
	IntentDatabaseRead   MCPToolIntent = "database-read"
	IntentDatabaseWrite  MCPToolIntent = "database-write"
	IntentCredentialRead MCPToolIntent = "credential-read"
	IntentSystemConfig   MCPToolIntent = "system-config"
	IntentProcessManage  MCPToolIntent = "process-manage"
	IntentUnknown        MCPToolIntent = "unknown"
)

// IntentClassification holds a classified intent with its confidence score.
type IntentClassification struct {
	Intent     MCPToolIntent `json:"intent"`
	Confidence float64       `json:"confidence"`
}

// MCPSemanticResult holds the outcome of semantic intent classification.
type MCPSemanticResult struct {
	Intents []IntentClassification `json:"intents"`
}

// MCPSemanticMatch defines YAML-level semantic match criteria for policy rules.
type MCPSemanticMatch struct {
	IntentAny     []string `yaml:"intent_any,omitempty"`     // any of these intents must be present
	IntentAll     []string `yaml:"intent_all,omitempty"`     // all of these intents must be present
	ConfidenceMin float64  `yaml:"confidence_min,omitempty"` // minimum confidence threshold
	// ToolNameRegexExclude carves a verb/name pattern out of a generic
	// intent-based rule without touching the shared classifier weights.
	// If set and the tool name matches, the rule does NOT fire — even if
	// the intent/confidence conditions above are satisfied. Use this when
	// a specific sibling rule already tiers that tool-name pattern to a
	// less restrictive decision (e.g. a BLOCK catch-all for
	// "credential-read" should not swallow a "rotate_*_secret" tool that a
	// dedicated AUDIT rule intentionally tiers down) — see issue #2912.
	ToolNameRegexExclude string `yaml:"tool_name_regex_exclude,omitempty"`
}

// MCPSemanticRule is a complete semantic rule including decision metadata.
type MCPSemanticRule struct {
	ID         string           `yaml:"id"`
	Match      MCPSemanticMatch `yaml:"match"`
	Decision   policy.Decision  `yaml:"decision"`
	Reason     string           `yaml:"reason"`
	Taxonomy   string           `yaml:"taxonomy,omitempty"`   // taxonomy reference (advisory metadata — see issue #2869)
	Tests      *MCPRuleTest     `yaml:"tests,omitempty"`      // inline TP/TN test cases (advisory — no dedicated test harness executes these yet, see issue #2869)
	Confidence float64          `yaml:"confidence,omitempty"` // advisory: author's confidence in this rule's precision
}

// --- Signal keyword maps ---

// intentKeywords maps tool name keywords to intents with base weights.
// Multiple keywords can map to the same intent.
var intentKeywords = map[MCPToolIntent][]keywordEntry{
	IntentFileRead: {
		{keyword: "read", weight: 0.4},
		{keyword: "get", weight: 0.3},
		{keyword: "view", weight: 0.4},
		{keyword: "list", weight: 0.3},
		{keyword: "show", weight: 0.3},
		{keyword: "cat", weight: 0.4},
		{keyword: "open", weight: 0.2},
	},
	IntentFileWrite: {
		{keyword: "write", weight: 0.4},
		{keyword: "save", weight: 0.4},
		{keyword: "create", weight: 0.3},
		{keyword: "update", weight: 0.3},
		{keyword: "put", weight: 0.3},
		{keyword: "set", weight: 0.2},
		{keyword: "edit", weight: 0.4},
		{keyword: "modify", weight: 0.3},
	},
	IntentFileDelete: {
		{keyword: "delete", weight: 0.5},
		{keyword: "remove", weight: 0.5},
		{keyword: "rm", weight: 0.5},
		{keyword: "drop", weight: 0.4},
		{keyword: "truncate", weight: 0.3},
		{keyword: "purge", weight: 0.4},
		{keyword: "erase", weight: 0.4},
		{keyword: "wipe", weight: 0.4},
		{keyword: "cleanup", weight: 0.2},
	},
	IntentCodeExecute: {
		{keyword: "exec", weight: 0.5},
		{keyword: "execute", weight: 0.5},
		{keyword: "eval", weight: 0.5},
		{keyword: "run", weight: 0.4},
		{keyword: "interpret", weight: 0.3},
	},
	IntentShellCommand: {
		{keyword: "shell", weight: 0.5},
		{keyword: "bash", weight: 0.5},
		{keyword: "terminal", weight: 0.5},
		{keyword: "command", weight: 0.4},
		{keyword: "cmd", weight: 0.4},
		{keyword: "console", weight: 0.3},
	},
	IntentNetworkRequest: {
		{keyword: "http", weight: 0.4},
		{keyword: "request", weight: 0.3},
		{keyword: "fetch", weight: 0.3},
		{keyword: "curl", weight: 0.5},
		{keyword: "api", weight: 0.3},
		{keyword: "webhook", weight: 0.4},
		{keyword: "post", weight: 0.3},
		{keyword: "upload", weight: 0.4},
		{keyword: "download", weight: 0.3},
	},
	IntentDatabaseRead: {
		{keyword: "query", weight: 0.4},
		{keyword: "select", weight: 0.3},
		{keyword: "sql", weight: 0.4},
		{keyword: "database", weight: 0.3},
		{keyword: "db", weight: 0.3},
	},
	IntentDatabaseWrite: {
		{keyword: "insert", weight: 0.4},
		{keyword: "upsert", weight: 0.4},
		{keyword: "migrate", weight: 0.3},
	},
	IntentCredentialRead: {
		{keyword: "credential", weight: 0.5},
		// Plural form needed as its own entry: classifyToolName tokenizes
		// "read_credentials" to the token "credentials", which never
		// exact-matches "credential" — it fell back to the discounted
		// substring bonus (0.25), landing under the 0.7 confidence_min most
		// credential-access BLOCK rules use (issue #2869 harness gap).
		{keyword: "credentials", weight: 0.5},
		{keyword: "secret", weight: 0.5},
		{keyword: "key", weight: 0.3},
		{keyword: "token", weight: 0.4},
		{keyword: "password", weight: 0.5},
		{keyword: "auth", weight: 0.3},
		{keyword: "vault", weight: 0.4},
	},
	IntentSystemConfig: {
		{keyword: "config", weight: 0.3},
		{keyword: "setting", weight: 0.3},
		{keyword: "env", weight: 0.3},
		{keyword: "environment", weight: 0.3},
	},
	IntentProcessManage: {
		{keyword: "kill", weight: 0.5},
		// "stop" raised from 0.3 to match "kill": at 0.3 it stayed below the
		// 0.4 substring-bonus threshold, so "stop_service" scored only 0.3 —
		// well under the 0.7 confidence_min mcp-sem-block-process-manage
		// requires — silently letting an agent stop a critical service
		// (sshd, etc.) through unblocked (issue #2869 harness gap).
		{keyword: "stop", weight: 0.5},
		{keyword: "restart", weight: 0.4},
		{keyword: "terminate", weight: 0.4},
		{keyword: "process", weight: 0.3},
		{keyword: "pid", weight: 0.4},
		{keyword: "signal", weight: 0.4},
		{keyword: "daemon", weight: 0.3},
	},
}

// argNameSignals maps argument names to intents they reinforce. Keys are the
// human-readable spelling; classifyArgNames looks up argNameSignalsNormalized
// instead of this map directly — see that var's doc comment (#3691).
var argNameSignals = map[string][]MCPToolIntent{
	"path":        {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"file":        {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"filename":    {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"filepath":    {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"target":      {IntentFileRead, IntentFileWrite, IntentFileDelete},
	"command":     {IntentCodeExecute, IntentShellCommand},
	"cmd":         {IntentCodeExecute, IntentShellCommand},
	"script":      {IntentCodeExecute, IntentShellCommand},
	"code":        {IntentCodeExecute},
	"expression":  {IntentCodeExecute},
	"url":         {IntentNetworkRequest},
	"endpoint":    {IntentNetworkRequest},
	"uri":         {IntentNetworkRequest},
	"host":        {IntentNetworkRequest},
	"query":       {IntentDatabaseRead, IntentDatabaseWrite},
	"sql":         {IntentDatabaseRead, IntentDatabaseWrite},
	"statement":   {IntentDatabaseRead, IntentDatabaseWrite},
	"secret":      {IntentCredentialRead},
	"secret_name": {IntentCredentialRead},
	"token":       {IntentCredentialRead},
	"password":    {IntentCredentialRead},
	"credential":  {IntentCredentialRead},
	"key":         {IntentCredentialRead},
	"api_key":     {IntentCredentialRead},
	"pid":         {IntentProcessManage},
	"signal":      {IntentProcessManage},
	"process_id":  {IntentProcessManage},
}

// argNameSignalsNormalized is argNameSignals keyed by normalizeFieldName
// instead of the literal spelling, built once at package init.
//
// unicode.RecoverRenderedText (what classifyToolName and the old
// classifyArgNames used) folds a Unicode separator to an ASCII SPACE, which is
// correct for prose but wrong for an identifier exact-key lookup: "path" +
// U+00A0 recovers to "path " (trailing space), which still misses
// argNameSignals["path"]. normalizeFieldName recovers the same confusables
// AND strips separators entirely — the transform resolveField already uses to
// resolve an argument key for structural rules — so classifying against this
// table instead closes the residual left by #3594/#3689 (#3691). Measured
// before this fix: 165 of 592 scenarios with a semantic match lost it, and 21
// of 2489 BLOCKing scenarios downgraded to AUDIT, under a trailing U+00A0 on
// every argument key.
var argNameSignalsNormalized = normalizeArgNameSignals(argNameSignals)

func normalizeArgNameSignals(signals map[string][]MCPToolIntent) map[string][]MCPToolIntent {
	out := make(map[string][]MCPToolIntent, len(signals))
	for name, intents := range signals {
		out[normalizeFieldName(name)] = intents
	}
	return out
}

type keywordEntry struct {
	keyword string
	weight  float64
}

// ClassifyToolIntent performs heuristic intent classification on an MCP tool call.
// It combines signals from tool name, tool description, argument names, and
// argument values to produce a list of intents with confidence scores.
//
// This is purely heuristic — no LLM calls, no external APIs. Deterministic and fast.
//
// # Every one of the four signals reads attacker-controlled text
//
// The server declares the tool name, the description and the parameter names in
// `tools/list`, and the model copies them back verbatim — so all four inputs are
// chosen by whoever wants the classification to come out "unknown". Each signal
// therefore normalises before it matches, and the normalisation differs per
// signal because the matchers do:
//
//   - tool name — matched as a tokenised IDENTIFIER (substring keyword scan).
//     It gets unicode.RecoverRenderedText, which folds confusables, fullwidth
//     forms and invisibles as well as separators — a fold-to-SPACE is fine
//     here because the match is a substring scan, not an exact key.
//   - argument names — matched by EXACT-KEY lookup (argNameSignalsNormalized),
//     so a fold-to-SPACE is wrong: "path" + U+00A0 recovers to "path" +
//     U+0020, which still misses argNameSignals["path"]. These get
//     normalizeFieldName instead, which strips separators entirely rather
//     than folding them — the same transform resolveField already uses to
//     resolve an argument key for structural rules (#3691).
//   - description, argument values — matched as PROSE and by regex, both of
//     which are spelled with ASCII spaces and RE2's ASCII-only `\s`. They get
//     unicode.FoldUnicodeSeparators, which is exactly the class those matchers
//     are blind to (#3594).
//
// Measured on the scenario corpus before the fold (2026-09-06): 2 of the 27
// scenarios that reach BLOCK only through their description dropped to AUDIT
// when the ASCII spaces in that description were replaced with U+00A0, and 1 of
// 131 scenarios with a spaced string argument lost its semantic-rule match the
// same way. The two spellings render identically in a host's tool listing.
//
// The argument-NAME residual this left (folding recovers a SPACE, which an
// exact-key lookup still misses) was closed in #3691: see
// argNameSignalsNormalized. Measured before that fix: 165 of 592 scenarios
// with a semantic match lost it, and 21 of 2489 BLOCKing scenarios with
// arguments downgraded to AUDIT, under a trailing U+00A0 on every argument key.
func ClassifyToolIntent(toolName string, arguments map[string]interface{}, toolDescription string) MCPSemanticResult {
	// Accumulate scores per intent from all signals
	scores := make(map[MCPToolIntent]float64)

	// Signal 1: Tool name keywords (highest weight)
	classifyToolName(toolName, scores)

	// Signal 2: Tool description keywords
	classifyDescription(toolDescription, scores)

	// Signal 3: Argument names (reinforcing)
	classifyArgNames(arguments, scores)

	// Signal 4: Argument values (confirming)
	classifyArgValues(arguments, scores)

	// Convert scores to classifications, capping at 1.0
	var result MCPSemanticResult
	for intent, score := range scores {
		conf := math.Min(score, 1.0)
		if conf >= 0.2 { // minimum threshold to report
			result.Intents = append(result.Intents, IntentClassification{
				Intent:     intent,
				Confidence: conf,
			})
		}
	}

	// If no intents classified, mark as unknown
	if len(result.Intents) == 0 {
		result.Intents = append(result.Intents, IntentClassification{
			Intent:     IntentUnknown,
			Confidence: 1.0,
		})
	}

	return result
}

// classifyToolName checks the tool name against keyword patterns.
func classifyToolName(toolName string, scores map[MCPToolIntent]float64) {
	// Classify the RENDERED name. Intent scoring is keyword-based, so a single
	// confusable byte in `<U+0435>xecute_tool` deletes the "execute" token and
	// the tool scores as unclassified — see toolNameForms in namematch.go for
	// why a homoglyph tool name is free for the attacker. Recovery is a byte
	// scan for an ASCII name.
	lower := strings.ToLower(toolName)
	if recovered, changed := unicode.RecoverRenderedText(lower); changed {
		lower = recovered
	}
	// Tokenize on common separators: _, -, camelCase boundaries
	tokens := tokenize(lower)

	for intent, keywords := range intentKeywords {
		for _, kw := range keywords {
			for _, token := range tokens {
				if token == kw.keyword {
					scores[intent] += kw.weight
				}
			}
			// Also check substring match for compound names (e.g., "helpful_assistant" won't match but "run_code" will)
			if strings.Contains(lower, kw.keyword) && kw.weight >= 0.4 {
				// Only give partial credit for substring match to avoid false positives
				scores[intent] += kw.weight * 0.5
			}
		}
	}
}

// foldSeparatorRuns normalises the whitespace of attacker-supplied prose before
// it is matched against the descSignals phrase lists: Unicode separators fold to
// an ASCII space, and every run of whitespace then collapses to exactly one.
//
// The collapse is the half that FoldUnicodeSeparators cannot do on its own,
// because it is cardinality-preserving by design — two U+00A0 become two ASCII
// spaces. Every descSignals phrase is spelled with exactly ONE literal space,
// so `strings.Contains` still missed the doubled spelling, and doubling a
// separator costs an attacker one keystroke.
//
// Measured on the 5627-scenario corpus, over the 27 scenarios that reach BLOCK
// only through their description, with the #3594 fold in place but before this
// collapse: 0 leaked under a single U+00A0, and 3 leaked under two U+00A0 —
// 2 of them (MCP-TP-027, MCP-TP-030) through this signal, and MCP-TP-3434-003
// through ScanToolDescription's separate rendered-text path, which this
// function does not touch. U+2009 followed by U+200A, and two plain ASCII
// spaces, each leaked the same 3. After the collapse the 2 that belong to this
// signal are 0 in all four spellings.
//
// Runs of ASCII whitespace are collapsed too, not only folded ones. "run  code"
// with two ordinary spaces defeats the same substring match, so normalising
// only the Unicode spelling would move the bypass sideways rather than close
// it. That widening is contained: the collapse cannot LOSE a match, since no
// descSignals phrase contains two adjacent whitespace characters, so any phrase
// that matched before the collapse is still contiguous after it.
//
// # Only HORIZONTAL whitespace collapses — line boundaries are preserved
//
// The first revision of this function was `strings.Join(strings.Fields(x), " ")`,
// which also joins across newlines. That manufactured phrases out of ordinary
// hard-wrapped prose: the benign description
//
//	"Formats text only; it does not run\ncode."
//
// became "…does not run code.", which contains the code-execute phrase "run
// code", and with benign `code`/`expression` parameter names the tool went from
// 0.50 to 0.80 — a BLOCK that main does not produce. A normalisation that
// invents a signal absent from every spelling of the input is a verdict, not a
// normalisation.
//
// So a run of horizontal whitespace collapses to one space, per line, and `\n`
// and `\r` are copied through untouched. A phrase split across a line break
// does not match; the same phrase with a doubled separator on one line does.
//
// Boundary worth knowing: U+0085, U+2028 and U+2029 are line breaks in Unicode
// but FoldUnicodeSeparators — whose table is shared with eight other scanners
// and is not this change's to alter — folds them to a space before this function
// sees them, so they behave horizontally here.
//
// The loop is byte-wise, which is safe because ' ' and '\t' are ASCII and every
// continuation byte of a multi-byte rune is >= 0x80.
//
// Not applied to argument VALUES: those detectors are regexps spelled with
// `\s+`, which already matches a run, so they need the fold and not the
// collapse (see classifyArgValues).
func foldSeparatorRuns(s string) string {
	folded, _ := unicode.FoldUnicodeSeparators(s)

	var b strings.Builder
	b.Grow(len(folded))
	inRun := false
	for i := 0; i < len(folded); i++ {
		if c := folded[i]; c == ' ' || c == '\t' {
			if !inRun {
				b.WriteByte(' ')
				inRun = true
			}
			continue
		}
		inRun = false
		b.WriteByte(folded[i])
	}
	return b.String()
}

// descSignals maps an intent to the description phrases that score it. Package
// level, not rebuilt per call: it is immutable, it is read once per tool call on
// the proxy's hot path, and — the reason it moved — the separator contract is
// stated over ALL of it, so the tests parameterise over this table rather than
// naming two intents by hand (#3594 follow-up). Adding a family here therefore
// adds a separator-parity case for free.
//
// Every phrase is pure ASCII, and none contains two adjacent whitespace
// characters. foldSeparatorRuns depends on both.
var descSignals = map[MCPToolIntent][]string{
	IntentFileRead:       {"reads file", "read file", "reads a file", "read a file", "file content", "open file", "view file"},
	IntentFileWrite:      {"writes file", "write file", "writes a file", "write a file", "save file", "create file", "modify file"},
	IntentFileDelete:     {"delete file", "remove file", "removes file", "deletes file", "removes files", "erase file", "wipe file"},
	IntentCodeExecute:    {"execute code", "executes code", "run code", "runs code", "runs user-provided code", "code snippet", "eval", "evaluate code", "interpret code"},
	IntentShellCommand:   {"shell command", "execute command", "run command", "terminal command", "bash command", "executes shell"},
	IntentNetworkRequest: {"http request", "network request", "api call", "sends request", "fetches url", "downloads", "uploads"},
	IntentDatabaseRead:   {"query database", "database query", "select from", "reads from database", "fetch records"},
	IntentDatabaseWrite:  {"insert into", "update database", "write to database", "modify database", "migrate database"},
	IntentCredentialRead: {"read credential", "access secret", "fetch secret", "get password", "read token", "access key", "retrieve key"},
	IntentProcessManage:  {"kill process", "stop process", "restart process", "manage process", "manages system process", "send signal", "terminate process"},
	IntentSystemConfig:   {"system config", "modify config", "change setting", "environment variable", "update config"},
}

// classifyDescription checks the tool description for intent signals.
//
// It scores the whitespace-normalised description. Every descSignals entry is a
// multi-word English phrase matched with strings.Contains, so a single U+00A0
// between two words — or simply two spaces — deletes the phrase: the
// description then contributes no score at all and the intent lands under every
// rule's confidence_min (#3594).
//
// The normalisation cannot lose an existing match. The fold only ever rewrites
// a non-ASCII rune to a space, the phrases are pure ASCII, and no phrase
// contains adjacent whitespace, so any run that matched before still matches
// after. It can only add.
func classifyDescription(description string, scores map[MCPToolIntent]float64) {
	if description == "" {
		return
	}
	lower := foldSeparatorRuns(strings.ToLower(description))

	for intent, phrases := range descSignals {
		for _, phrase := range phrases {
			if strings.Contains(lower, phrase) {
				scores[intent] += 0.3
			}
		}
	}
}

// classifyArgNames checks argument names for intent reinforcement.
func classifyArgNames(arguments map[string]interface{}, scores map[MCPToolIntent]float64) {
	if arguments == nil {
		return
	}

	for argName := range arguments {
		// normalizeFieldName (see argNameSignalsNormalized) rather than a raw
		// lowercase + unicode.RecoverRenderedText: this is still an exact-key
		// lookup, and RecoverRenderedText alone leaves a recovered separator as
		// an ASCII space that the lookup below would still miss (#3691).
		if intents, ok := argNameSignalsNormalized[normalizeFieldName(argName)]; ok {
			for _, intent := range intents {
				scores[intent] += 0.25
			}
		}
	}
}

// classifyArgValues examines argument values for confirming signals.
//
// Every detector below is a regexp whose inter-token separator is RE2's `\s`,
// which is ASCII-only — so `import os` spelled with U+00A0 matches none of them
// while running identically once the tool interprets it. Each value is
// therefore tested in both spellings (#3594).
//
// It is an OR over forms rather than a fold in place, so the fold is strictly
// additive: unlike classifyDescription's plain substring match, these detectors
// are not monotone under the fold — looksLikeURL runs url.Parse, and turning a
// separator inside a host into a space can make a URL stop parsing. Scoring the
// wire form as well means no signal that fires today can be folded away.
func classifyArgValues(arguments map[string]interface{}, scores map[MCPToolIntent]float64) {
	if arguments == nil {
		return
	}

	for _, val := range arguments {
		strVal, ok := val.(string)
		if !ok {
			continue
		}
		folded, refolded := unicode.FoldUnicodeSeparators(strVal)
		matches := func(pred func(string) bool) bool {
			return pred(strVal) || (refolded && pred(folded))
		}

		// Check if value looks like a file path
		if matches(looksLikeFilePath) {
			scores[IntentFileRead] += 0.15
			scores[IntentFileWrite] += 0.15
			scores[IntentFileDelete] += 0.15
		}

		// Check if value looks like a URL
		if matches(looksLikeURL) {
			scores[IntentNetworkRequest] += 0.2
		}

		// Check if value looks like SQL
		if matches(looksLikeSQL) {
			scores[IntentDatabaseRead] += 0.2
			scores[IntentDatabaseWrite] += 0.1
		}

		// Check if value looks like shell command or code
		if matches(looksLikeCode) {
			scores[IntentCodeExecute] += 0.2
		}

		// Check if value looks like it references credentials
		if matches(looksLikeCredentialRef) {
			scores[IntentCredentialRead] += 0.2
		}
	}
}

// --- Value pattern detectors ---

var filePathRe = regexp.MustCompile(`^[~./]?/[\w./-]+$`)

func looksLikeFilePath(s string) bool {
	if len(s) < 2 || len(s) > 500 {
		return false
	}
	return filePathRe.MatchString(s)
}

func looksLikeURL(s string) bool {
	if len(s) < 8 {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

var sqlKeywordRe = regexp.MustCompile(`(?i)^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE)\s+`)

func looksLikeSQL(s string) bool {
	return sqlKeywordRe.MatchString(s)
}

// looksLikeCode checks if a string looks like executable code or a shell command.
// We look for common code patterns but exclude simple math expressions.
//
// # `import` needs lexical context, not a regex anchor (#3696)
//
// Every other alternative here is a token ordinary English prose does not
// contain — `subprocess.`, `eval(`, `#!/bin/sh`, `rm -rf`. `import` is the
// exception: it is also an English word, so "how to fix python import error"
// (MCP-TP-720) and "The answer should explain import os as an example."
// classified as code-execute under the old unanchored `import\s+\w+` — a real
// false positive present in the ASCII spelling on main, not introduced by
// #3594's separator fold.
//
// An earlier revision tried anchoring the keyword to statement position
// (`(?im)(^|;)[ \t]*import…`). Adversarial review showed a single regex anchor
// is unsound in BOTH directions: it lost `if True: import os` (colon suite), a
// CR-only line boundary, a form-feed prefix, and `python3 -c "import os"`
// payloads, while STILL firing on "For example; import os is shown below." —
// because `;` is ordinary punctuation as often as it is a statement separator,
// and a regex anchor cannot tell which.
//
// importInStatementPosition (below) is the tokenizer that replaces the single
// anchor. It resolves the `;` ambiguity the anchor could not: a semicolon is
// only a statement separator when the text immediately before it ALSO looks
// like a code statement (an assignment or a bare identifier) — not merely
// present. "x = 1; import socket" qualifies; "For example; import os is shown
// below." does not, because "For example" is not a code-shaped prefix. Comment
// lines (`#...`) are excluded outright, so "# disabled example; import os"
// never reaches the semicolon check at all.
var codePatterns = regexp.MustCompile(`(?i)(os\.(system|popen|exec)|subprocess\.|eval\(|exec\(|` +
	`\bsudo\s|;\s*(rm|curl|wget|bash|sh)\b|` +
	`\brm\s+-[rf]|\bcurl\s+|` +
	`#!/bin/(ba)?sh)`)

// simpleMathRe matches expressions that are pure arithmetic (not code).
var simpleMathRe = regexp.MustCompile(`^[\d\s+\-*/().,%^=<>]+$`)

func looksLikeCode(s string) bool {
	if simpleMathRe.MatchString(s) {
		return false
	}
	return codePatterns.MatchString(s) || importInStatementPosition(s)
}

// --- Statement-position tokenizer for the `import` keyword (#3696) ---

// fromImportRe matches Python's "from <module> import <name>" idiom
// unconditionally, regardless of position. Two Python-specific keywords in
// this exact order is not a shape ordinary English prose produces, so it
// needs no statement-position check the way the bare `import` keyword does.
var fromImportRe = regexp.MustCompile(`(?i)\bfrom\s+[\w.]+\s+import\s+\w+`)

// lineStartImportRe recognizes "import <name>" at the start of whatever
// segment it is tested against (a line, or the text right after a statement
// separator). Kept as a literal `\s+` (not `\b`) deliberately: it mirrors the
// pre-#3696 candidate shape and lets the existing wire-form/folded-form retry
// in classifyArgValues (and its test-only mirror, classifiesAsCode) do the
// Unicode-separator work, rather than this regex trying to.
var lineStartImportRe = regexp.MustCompile(`(?i)^import\s+\w+`)

// compoundHeaderColonRe recognizes a Python compound-statement opener whose
// trailing colon puts the next token in statement position — `if True:`,
// `else:`, `try:`, `for x in y:`. Scoped to this fixed keyword list so it
// cannot be satisfied by an arbitrary prose colon ("Note: ...").
var compoundHeaderColonRe = regexp.MustCompile(`(?i)^\s*(if|elif|else|while|for|try|except|finally|with|def|class)\b.*:$`)

// codeLikeSemicolonPrefixRe recognizes a segment that itself looks like a
// simple code statement: an assignment/augmented-assignment, or a bare
// identifier/attribute chain with no spaces. This is what lets "x = 1; import
// socket" count the semicolon as a statement separator while "For example;
// import os is shown below." does not — the prefix before the `;` is prose,
// not code, in the second case.
var codeLikeSemicolonPrefixRe = regexp.MustCompile(`^[\w.\[\]'"()]+\s*[-+*/]?=[^=].*$|^[\w.]+$`)

// interpCPrefixRe matches an interpreter one-liner invocation up to (but not
// including) its quoted payload — `python3 -c `, `node -e`, etc. RE2 has no
// backreferences, so the matching closing quote is found by hand in
// extractInterpPayloads rather than in the pattern.
var interpCPrefixRe = regexp.MustCompile(`(?i)\b(?:python3?|perl|ruby|node)\s+-[ce]\s*`)

// extractInterpPayloads returns the quoted script bodies passed to a `-c`/`-e`
// flag of a common interpreter. The payload is code by construction — it is
// the thing the interpreter executes — so statement-position rules are
// RE-APPLIED inside it, not skipped, which is what keeps prose smuggled inside
// a real payload from getting a free pass.
func extractInterpPayloads(s string) []string {
	var payloads []string
	for _, loc := range interpCPrefixRe.FindAllStringIndex(s, -1) {
		rest := s[loc[1]:]
		if rest == "" {
			continue
		}
		quote := rest[0]
		if quote != '"' && quote != '\'' {
			continue
		}
		closeIdx := strings.IndexByte(rest[1:], quote)
		if closeIdx < 0 {
			continue
		}
		payloads = append(payloads, rest[1:1+closeIdx])
	}
	return payloads
}

// splitCodeLines splits on every line-boundary character a shell/editor can
// produce — not just `\n`. Go's regexp `(?m)^` anchor only recognizes `\n`,
// which is what let a CR-only line boundary or a form-feed prefix defeat the
// earlier anchored-regex attempt at this fix.
func splitCodeLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '\f'
	})
}

func lineIsComment(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

// colonHeaderImportPosition reports whether line contains a recognized
// compound-statement header whose colon is immediately followed by "import".
func colonHeaderImportPosition(line string) bool {
	for i := 0; i < len(line); i++ {
		if line[i] != ':' {
			continue
		}
		prefix := line[:i+1]
		suffix := strings.TrimSpace(line[i+1:])
		if compoundHeaderColonRe.MatchString(prefix) && lineStartImportRe.MatchString(suffix) {
			return true
		}
	}
	return false
}

// semicolonImportPosition reports whether line contains a `;`-separated
// segment starting with "import" whose PRECEDING segment looks like a code
// statement — the check that tells "x = 1; import socket" (code) apart from
// "For example; import os is shown below." (prose using `;` as punctuation).
func semicolonImportPosition(line string) bool {
	segments := strings.Split(line, ";")
	for i := 1; i < len(segments); i++ {
		suffix := strings.TrimSpace(segments[i])
		if !lineStartImportRe.MatchString(suffix) {
			continue
		}
		prefix := strings.TrimSpace(segments[i-1])
		if codeLikeSemicolonPrefixRe.MatchString(prefix) {
			return true
		}
	}
	return false
}

// importAppearsInCode scans s for an "import <name>" occurrence sitting in
// statement position: start of a line, right after the colon that closes a
// recognized compound-statement header, or right after a semicolon whose
// preceding segment itself looks like code. Comment lines are excluded
// entirely, before any of those checks run.
func importAppearsInCode(s string) bool {
	for _, line := range splitCodeLines(s) {
		if lineIsComment(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if lineStartImportRe.MatchString(trimmed) {
			return true
		}
		if colonHeaderImportPosition(line) {
			return true
		}
		if semicolonImportPosition(line) {
			return true
		}
	}
	return false
}

// importInStatementPosition is the #3696 tokenizer: it decides whether s
// contains an `import` used as a keyword (code) rather than as an ordinary
// English noun (prose), by checking statement position instead of matching
// the bare word anywhere in the string.
func importInStatementPosition(s string) bool {
	if fromImportRe.MatchString(s) {
		return true
	}
	if importAppearsInCode(s) {
		return true
	}
	for _, payload := range extractInterpPayloads(s) {
		if importAppearsInCode(payload) {
			return true
		}
	}
	return false
}

var credentialRefRe = regexp.MustCompile(`(?i)(aws_access_key|aws_secret|api[_-]?key|password|secret[_-]?key|token|credential|private[_-]?key)`)

func looksLikeCredentialRef(s string) bool {
	return credentialRefRe.MatchString(s)
}

// tokenize splits a lowercase string on underscores, hyphens, and camelCase boundaries.
func tokenize(s string) []string {
	// First split on _ and -
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' '
	})
	return parts
}

// --- Semantic rule matching ---

// matchSemanticRule checks if a set of classified intents matches a semantic rule.
func matchSemanticRule(toolName string, intents []IntentClassification, rule MCPSemanticRule) bool {
	m := rule.Match

	// tool_name_regex_exclude: carve-out checked first — if the tool name
	// matches, this rule never fires regardless of intent/confidence.
	//
	// Gated on asciiOnlyWireName for the same reason as the structural clause:
	// `(?i)` is a Unicode fold, so a U+017F/U+212A spelling could satisfy the
	// carve-out while the positive side (classifyToolName, which tokenises the
	// wire name) does not fold and so scores it differently (#3771).
	//
	// Measured on this rule (mcp-sem-block-credential-access) the pairing is
	// NOT currently exploitable — the classifier gates the rule first and fails
	// on the same non-ASCII byte, so ASCII and folded spellings decide alike on
	// all 9 probes. This is hardening against the shape, not a live bypass; the
	// structural instance in #3771 was live because its carve-out deferred to
	// dedicated rules that DID fire on the ASCII spelling.
	if m.ToolNameRegexExclude != "" && asciiOnlyWireName(toolName) {
		if re, err := cachedRegexp(m.ToolNameRegexExclude); err == nil && re.MatchString(toolName) {
			return false
		}
	}

	minConf := m.ConfidenceMin
	if minConf == 0 {
		minConf = 0.5 // default threshold
	}

	// intent_any: at least one of the specified intents must be present above threshold
	if len(m.IntentAny) > 0 {
		anyMatch := false
		for _, wantIntent := range m.IntentAny {
			for _, ic := range intents {
				if string(ic.Intent) == wantIntent && ic.Confidence >= minConf {
					anyMatch = true
					break
				}
			}
			if anyMatch {
				break
			}
		}
		if !anyMatch {
			return false
		}
	}

	// intent_all: all specified intents must be present above threshold
	if len(m.IntentAll) > 0 {
		for _, wantIntent := range m.IntentAll {
			found := false
			for _, ic := range intents {
				if string(ic.Intent) == wantIntent && ic.Confidence >= minConf {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	// Must have specified at least one matcher
	return len(m.IntentAny) > 0 || len(m.IntentAll) > 0
}

// evaluateSemanticRules classifies tool call intent and evaluates against semantic rules.
func evaluateSemanticRules(toolName string, arguments map[string]interface{}, toolDescription string, rules []MCPSemanticRule) (MCPSemanticResult, []MCPSemanticRule) {
	classification := ClassifyToolIntent(toolName, arguments, toolDescription)

	var matched []MCPSemanticRule
	for _, rule := range rules {
		if matchSemanticRule(toolName, classification.Intents, rule) {
			matched = append(matched, rule)
		}
	}

	return classification, matched
}
