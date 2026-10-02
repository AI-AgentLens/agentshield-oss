package mcp

import "testing"

// The A2A auth check tested only len(schemes)==0, so a forged card downgrading
// ["Bearer"] to ["none"] — a non-empty list that still means no credentials —
// passed. And the hostname-match check compares only the host, so a cleartext
// http:// url slips past it. These tests pin both downgrade signals (AUDIT).

func baseCard() *A2AAgentCard {
	return &A2AAgentCard{
		Name:           "Task Agent",
		URL:            "https://agent.company.com/api",
		Version:        "1.0.0",
		Authentication: A2AAuthentication{Schemes: []string{"Bearer"}},
	}
}

// --- Vacuous auth scheme (auth downgrade past a presence-only check) ---

func TestA2AAuthNoop_SchemesDowngraded_Audit(t *testing.T) {
	for _, noop := range [][]string{
		{"none"},
		{"None"},
		{"anonymous"},
		{"public"},
		{" none "}, // whitespace-padded
		{""},        // empty-string element padding the list to "non-empty"
		{"none", "anonymous"},
	} {
		card := baseCard()
		card.Authentication.Schemes = noop
		res := ScanA2AAgentCard(card, "agent.company.com")
		if res.Decision != "AUDIT" {
			t.Errorf("schemes=%v: expected AUDIT, got %s (%v)", noop, res.Decision, res.Findings)
			continue
		}
		if !hasA2ASignal(res.Findings, SignalA2AAuthNoop) {
			t.Errorf("schemes=%v: expected a2a_auth_noop, got %v", noop, res.Findings)
		}
	}
}

// A real scheme alongside a no-op token means auth IS available — not flagged.
func TestA2AAuthNoop_MixedWithRealScheme_Allow(t *testing.T) {
	card := baseCard()
	card.Authentication.Schemes = []string{"none", "Bearer"}
	res := ScanA2AAgentCard(card, "agent.company.com")
	if res.Decision != "ALLOW" {
		t.Errorf("expected ALLOW when a real scheme is present, got %s (%v)", res.Decision, res.Findings)
	}
}

// Real schemes must not trip the no-op check.
func TestA2AAuthNoop_RealSchemes_Allow(t *testing.T) {
	for _, s := range [][]string{{"Bearer"}, {"OAuth2"}, {"ApiKey"}, {"Basic"}, {"mTLS"}, {"Bearer", "ApiKey"}} {
		card := baseCard()
		card.Authentication.Schemes = s
		if res := ScanA2AAgentCard(card, "agent.company.com"); res.Decision != "ALLOW" {
			t.Errorf("schemes=%v: expected ALLOW, got %s (%v)", s, res.Decision, res.Findings)
		}
	}
}

// The empty case remains the existing auth_missing signal, not auth_noop.
func TestA2AAuthNoop_EmptyStaysAuthMissing(t *testing.T) {
	card := baseCard()
	card.Authentication.Schemes = nil
	res := ScanA2AAgentCard(card, "agent.company.com")
	if !hasA2ASignal(res.Findings, SignalA2AAuthMissing) {
		t.Errorf("expected auth_missing for empty schemes, got %v", res.Findings)
	}
	if hasA2ASignal(res.Findings, SignalA2AAuthNoop) {
		t.Errorf("empty schemes must not report auth_noop")
	}
}

// --- Transport downgrade (cleartext http to a non-loopback host) ---

func TestA2ATransportDowngrade_CleartextHTTP_Audit(t *testing.T) {
	card := baseCard()
	card.URL = "http://agent.company.com/api"
	// Scan with no origin so the hostname-match check is skipped — isolates the
	// transport signal from the url-mismatch one.
	res := ScanA2AAgentCard(card, "")
	if res.Decision != "AUDIT" {
		t.Fatalf("expected AUDIT for cleartext http url, got %s (%v)", res.Decision, res.Findings)
	}
	if !hasA2ASignal(res.Findings, SignalA2ATransportDowngrade) {
		t.Errorf("expected a2a_transport_downgrade, got %v", res.Findings)
	}
}

// https must not trip the transport check.
func TestA2ATransportDowngrade_HTTPS_Allow(t *testing.T) {
	card := baseCard()
	res := ScanA2AAgentCard(card, "")
	if res.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for https url with real scheme, got %s (%v)", res.Decision, res.Findings)
	}
}

// Loopback http is ordinary local development — not flagged.
func TestA2ATransportDowngrade_LoopbackHTTP_Allow(t *testing.T) {
	for _, host := range []string{"http://localhost:8080/api", "http://127.0.0.1:9000/", "http://dev.localhost/api"} {
		card := baseCard()
		card.URL = host
		if res := ScanA2AAgentCard(card, ""); hasA2ASignal(res.Findings, SignalA2ATransportDowngrade) {
			t.Errorf("url=%s: loopback http must not be a downgrade finding", host)
		}
	}
}

// A downgrade signal alone stays AUDIT — it must never escalate to BLOCK.
func TestA2ADowngrade_NeverBlocks(t *testing.T) {
	card := baseCard()
	card.URL = "http://agent.company.com/api"
	card.Authentication.Schemes = []string{"none"}
	res := ScanA2AAgentCard(card, "") // no origin → no url-mismatch BLOCK
	if res.Decision != "AUDIT" {
		t.Errorf("expected AUDIT (downgrades are never BLOCK), got %s (%v)", res.Decision, res.Findings)
	}
}
