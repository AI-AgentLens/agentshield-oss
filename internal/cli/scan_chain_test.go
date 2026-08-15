package cli

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// TestAuditChainStatus is the stage-1 fitness function for issue #3112.
//
// The bug it locks down: `scan` rendered a green tick and counted a pass
// whenever VerifyChain "found nothing", which included a log with no hash chain
// at all. Only a genuinely verified chain may render as a pass — everything
// else must be visibly not-a-pass, because on this trust surface a confident
// wrong answer is worse than an honest gap.
func TestAuditChainStatus(t *testing.T) {
	tests := []struct {
		name        string
		result      logger.ChainVerifyResult
		wantPassed  bool
		wantCounted bool
		wantSubstr  string
		wantNoTick  bool
	}{
		{
			name:        "verified chain is the only pass",
			result:      logger.ChainVerifyResult{State: logger.ChainStateVerified, Entries: 42, BrokenAt: -1, Message: "chain verified"},
			wantPassed:  true,
			wantCounted: true,
			wantSubstr:  "verified (42 entries)",
		},
		{
			name: "verified chain reports the rotation link",
			result: logger.ChainVerifyResult{
				State: logger.ChainStateVerified, Entries: 7, BrokenAt: -1,
				Message: "chain verified", Note: "linked to audit.jsonl.1",
			},
			wantPassed:  true,
			wantCounted: true,
			wantSubstr:  "linked to audit.jsonl.1",
		},
		{
			name: "unprotected log is not a pass",
			result: logger.ChainVerifyResult{
				State: logger.ChainStateUnprotected, Entries: 128, LegacyEntries: 128,
				BrokenAt: -1, Message: "no chain fields written",
			},
			wantPassed:  false,
			wantCounted: true,
			wantSubstr:  "unprotected",
			wantNoTick:  true,
		},
		{
			name: "partially protected log is not a pass",
			result: logger.ChainVerifyResult{
				State: logger.ChainStatePartial, Entries: 20, LegacyEntries: 12,
				BrokenAt: -1, Message: "12 of 20 entries predate the chain",
			},
			wantPassed:  false,
			wantCounted: true,
			wantSubstr:  "partially protected",
			wantNoTick:  true,
		},
		{
			name: "broken chain is a failure",
			result: logger.ChainVerifyResult{
				State: logger.ChainStateBroken, Entries: 5, BrokenAt: 3,
				Message: "entry 3: entry hash mismatch",
			},
			wantPassed:  false,
			wantCounted: true,
			wantSubstr:  "broken at entry 3",
			wantNoTick:  true,
		},
		{
			name:        "unreadable log is not a tampering claim, and not a pass",
			result:      logger.ChainVerifyResult{State: logger.ChainStateUnreadable, BrokenAt: -1, Message: "cannot open file: permission denied"},
			wantPassed:  false,
			wantCounted: true,
			wantSubstr:  "cannot verify",
			wantNoTick:  true,
		},
		{
			name:        "fresh install with no entries asserts nothing either way",
			result:      logger.ChainVerifyResult{State: logger.ChainStateEmpty, BrokenAt: -1, Message: "no audit log yet"},
			wantPassed:  false,
			wantCounted: false,
			wantSubstr:  "no entries yet",
			wantNoTick:  true,
		},
		{
			name:        "unknown state is never vouched for",
			result:      logger.ChainVerifyResult{State: logger.ChainState("something-new"), BrokenAt: -1},
			wantPassed:  false,
			wantCounted: true,
			wantNoTick:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line, passed, counted := auditChainStatus(tc.result)

			if passed != tc.wantPassed {
				t.Errorf("passed = %v, want %v (line: %s)", passed, tc.wantPassed, line)
			}
			if counted != tc.wantCounted {
				t.Errorf("counted = %v, want %v (line: %s)", counted, tc.wantCounted, line)
			}
			if tc.wantSubstr != "" && !strings.Contains(line, tc.wantSubstr) {
				t.Errorf("line %q does not contain %q", line, tc.wantSubstr)
			}
			if tc.wantNoTick && strings.Contains(line, "✅") {
				t.Errorf("line %q renders a green tick for a non-passing state %q", line, tc.result.State)
			}
			if !strings.Contains(line, "Audit chain:") {
				t.Errorf("line %q lost its label", line)
			}
		})
	}
}

// TestAuditChainStatus_OnlyVerifiedPasses guards the invariant directly, so a
// future state added to ChainState cannot quietly inherit a pass.
func TestAuditChainStatus_OnlyVerifiedPasses(t *testing.T) {
	states := []logger.ChainState{
		logger.ChainStateEmpty,
		logger.ChainStateUnprotected,
		logger.ChainStatePartial,
		logger.ChainStateVerified,
		logger.ChainStateBroken,
		logger.ChainStateUnreadable,
	}
	for _, state := range states {
		_, passed, _ := auditChainStatus(logger.ChainVerifyResult{State: state, BrokenAt: -1})
		if want := state == logger.ChainStateVerified; passed != want {
			t.Errorf("state %q: passed = %v, want %v", state, passed, want)
		}
	}
}
