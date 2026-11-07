package enterprise

import (
	"path"
	"regexp"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
)

// Every table input must keep any match the original token scan made.
func TestNamesAgentshieldSetup_Additive_4638(t *testing.T) {
	rows := allSetupDisableRows(t)
	rows = append(rows, setupDisableNoReadingRows...)
	rows = append(rows, setupDisableErasedStatementRows...)
	for _, tw := range zshTwins(t) {
		rows = append(rows, setupDisableRow{tw.name, tw.cmd, tw.row.want})
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if legacyNamesAgentshieldSetup(row.cmd) && !namesAgentshieldSetup(row.cmd) {
				t.Errorf("namesAgentshieldSetup(%q) lost a legacy match", row.cmd)
			}
		})
	}
}

var (
	legacySetupScanParamRe       = regexp.MustCompile(`\$\{[^{}]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)
	legacySetupScanQuotePrefixRe = regexp.MustCompile(`\$(['"])`)
)

// legacyNamesAgentshieldSetup is main's scan, including its original regexes.
func legacyNamesAgentshieldSetup(cmd string) bool {
	// ANSI-C spans are decoded first, with the decoder StripShellQuotes uses
	// on the argv path, so `$'se\x74up'` reads as setup (review round 1 on
	// #4634); the strip below would otherwise leave `sex74up`.
	s, _ := pathnorm.DecodeDollarQuotedSpans(cmd)
	s = strings.ReplaceAll(s, "\\\n", "")
	s = legacySetupScanParamRe.ReplaceAllString(s, "")
	s = legacySetupScanQuotePrefixRe.ReplaceAllString(s, "$1")
	s = strings.NewReplacer(`'`, "", `"`, "", `\`, "").Replace(s)
	words := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f', ';', '&', '|', '(', ')', '<', '>', '`', '{', '}', ',':
			return true
		}
		return false
	})
	seenAgentshield := false
	for _, w := range words {
		w = strings.TrimPrefix(w, "=")
		if !seenAgentshield {
			seenAgentshield = path.Base(w) == "agentshield" && !strings.HasSuffix(w, "/")
			continue
		}
		if w == "setup" {
			return true
		}
	}
	return false
}
