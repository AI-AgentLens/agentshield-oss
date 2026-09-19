package cli

import (
	"strings"
	"testing"
)

// The scan footer used to print "Review your policy configuration." for
// every failure, including tamper-protection checks that no policy edit can
// fix (#3140). The advice must follow WHICH section failed.
func TestScanSummaryAdvice(t *testing.T) {
	cases := []struct {
		name                       string
		policyFailed, tamperFailed int
		wantPolicy, wantTamper     bool
	}{
		{"nothing failed", 0, 0, false, false},
		{"policy cases only", 2, 0, true, false},
		{"tamper checks only", 0, 1, false, true},
		{"both", 1, 1, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(scanSummaryAdvice(tc.policyFailed, tc.tamperFailed), "\n")
			hasPolicy := strings.Contains(got, "Review your policy configuration.")
			hasTamper := strings.Contains(got, "Tamper protection:")
			if hasPolicy != tc.wantPolicy {
				t.Errorf("policy advice present=%v, want %v; got %q", hasPolicy, tc.wantPolicy, got)
			}
			if hasTamper != tc.wantTamper {
				t.Errorf("tamper advice present=%v, want %v; got %q", hasTamper, tc.wantTamper, got)
			}
			if tc.wantTamper && !strings.Contains(got, "agentshield setup") {
				t.Errorf("tamper advice must name the repair command; got %q", got)
			}
			if !tc.wantPolicy && !tc.wantTamper && got != "" {
				t.Errorf("expected no advice, got %q", got)
			}
		})
	}
}
