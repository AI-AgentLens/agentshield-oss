package mcp

import "testing"

// Coverage for the OAuth 2.1 flow-downgrade signals.
//
// MCP mandates OAuth 2.1, which REMOVES the implicit grant and the resource
// owner password credentials (ROPC) grant. `grant_types_supported` and
// `response_types_supported` were parsed into OAuthASMetadata and read by
// nothing, so an AS could advertise either and the metadata scan stayed
// silent while reporting on PKCE, transport and domain.

func hasOAuthSignal(r OAuthScanResult, want OAuthScanSignal) bool {
	for _, f := range r.Findings {
		if f.Signal == want {
			return true
		}
	}
	return false
}

func oauthSignals(r OAuthScanResult) []OAuthScanSignal {
	out := make([]OAuthScanSignal, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Signal)
	}
	return out
}

// compliantMeta is a well-formed OAuth 2.1 AS metadata document. Every case
// below mutates exactly one field of it, so a finding is attributable to that
// mutation rather than to an incidental defect in the fixture.
func compliantMeta() *OAuthASMetadata {
	return &OAuthASMetadata{
		Issuer:                        "https://auth.example.com",
		AuthorizationEndpoint:         "https://auth.example.com/authorize",
		TokenEndpoint:                 "https://auth.example.com/token",
		CodeChallengeMethodsSupported: []string{"S256"},
		GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
		ResponseTypesSupported:        []string{"code"},
	}
}

func TestOAuthFlowDowngrade_CompliantMetadataIsClean(t *testing.T) {
	r := ScanOAuthASMetadata(compliantMeta(), "auth.example.com")
	if r.Decision != "ALLOW" {
		t.Fatalf("compliant OAuth 2.1 metadata must be ALLOW, got %s %v", r.Decision, oauthSignals(r))
	}
}

func TestOAuthFlowDowngrade_ROPCAdvertisedAlongsideCode(t *testing.T) {
	m := compliantMeta()
	m.GrantTypesSupported = []string{"authorization_code", "refresh_token", "password"}
	r := ScanOAuthASMetadata(m, "auth.example.com")
	if !hasOAuthSignal(r, SignalOAuthLegacyGrantAdvertised) {
		t.Fatalf("ROPC must be flagged, got %v", oauthSignals(r))
	}
	// A legacy AS that also serves non-MCP clients is a real deployment, so
	// the offer is recorded, not enforced.
	if r.Decision != "AUDIT" {
		t.Errorf("decision = %s, want AUDIT while authorization_code is still offered", r.Decision)
	}
	if hasOAuthSignal(r, SignalOAuthCodeFlowUnavailable) {
		t.Error("authorization_code IS advertised — the escalation must not fire")
	}
}

func TestOAuthFlowDowngrade_ROPCOnlyBlocks(t *testing.T) {
	m := compliantMeta()
	m.GrantTypesSupported = []string{"password", "refresh_token"}
	r := ScanOAuthASMetadata(m, "auth.example.com")
	if !hasOAuthSignal(r, SignalOAuthCodeFlowUnavailable) {
		t.Fatalf("a removed flow with no authorization_code must escalate, got %v", oauthSignals(r))
	}
	if r.Decision != "BLOCK" {
		t.Errorf("decision = %s, want BLOCK", r.Decision)
	}
}

func TestOAuthFlowDowngrade_ImplicitResponseType(t *testing.T) {
	cases := []struct {
		name        string
		responses   []string
		wantImplied bool
		wantBlock   bool
	}{
		{"bare token, no code", []string{"token"}, true, true},
		{"token alongside code", []string{"code", "token"}, true, false},
		// The hybrid spelling is a space-delimited SET. Comparing the value
		// whole would miss it, which is the commonest real spelling of the
		// implicit flow in published metadata.
		{"hybrid set containing token", []string{"code", "id_token token"}, true, false},
		{"hybrid set, token only", []string{"id_token token"}, true, true},
		{"id_token alone is not token-bearing", []string{"code", "id_token"}, false, false},
		{"code only", []string{"code"}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := compliantMeta()
			m.ResponseTypesSupported = tc.responses
			r := ScanOAuthASMetadata(m, "auth.example.com")
			if got := hasOAuthSignal(r, SignalOAuthImplicitResponseType); got != tc.wantImplied {
				t.Errorf("implicit-response signal = %v, want %v (%v)", got, tc.wantImplied, oauthSignals(r))
			}
			if got := r.Decision == "BLOCK"; got != tc.wantBlock {
				t.Errorf("BLOCK = %v, want %v (decision %s, %v)", got, tc.wantBlock, r.Decision, oauthSignals(r))
			}
		})
	}
}

// TestOAuthFlowDowngrade_TrueNegatives pins the shapes that are well-formed
// OAuth 2.1 and must stay silent. The machine-to-machine case is the one that
// makes the escalation safe to enforce: authorization_code is absent there
// too, and "authorization_code is missing" alone must never be a finding.
func TestOAuthFlowDowngrade_TrueNegatives(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*OAuthASMetadata)
	}{
		{"machine-to-machine AS: client_credentials only, no authorization_code",
			func(m *OAuthASMetadata) {
				m.GrantTypesSupported = []string{"client_credentials"}
				m.ResponseTypesSupported = nil
			}},
		{"device flow alongside authorization_code",
			func(m *OAuthASMetadata) {
				m.GrantTypesSupported = []string{
					"authorization_code", "refresh_token",
					"urn:ietf:params:oauth:grant-type:device_code",
				}
			}},
		{"token exchange and JWT bearer extensions",
			func(m *OAuthASMetadata) {
				m.GrantTypesSupported = []string{
					"authorization_code",
					"urn:ietf:params:oauth:grant-type:token-exchange",
					"urn:ietf:params:oauth:grant-type:jwt-bearer",
				}
			}},
		{"a vendor grant whose name merely CONTAINS password is not ROPC",
			func(m *OAuthASMetadata) {
				m.GrantTypesSupported = []string{
					"authorization_code",
					"urn:example:params:oauth:grant-type:password-reset",
				}
			}},
		{"grant_types_supported omitted entirely — omission is not an assertion",
			func(m *OAuthASMetadata) { m.GrantTypesSupported = nil }},
		{"response_types_supported omitted entirely",
			func(m *OAuthASMetadata) { m.ResponseTypesSupported = nil }},
		{"case and whitespace variation on a compliant grant",
			func(m *OAuthASMetadata) {
				m.GrantTypesSupported = []string{" Authorization_Code ", "refresh_token"}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := compliantMeta()
			tc.mutate(m)
			r := ScanOAuthASMetadata(m, "auth.example.com")
			for _, f := range r.Findings {
				switch f.Signal {
				case SignalOAuthLegacyGrantAdvertised, SignalOAuthImplicitResponseType,
					SignalOAuthCodeFlowUnavailable:
					t.Errorf("false positive: %s — %s", f.Signal, f.Detail)
				}
			}
		})
	}
}

// TestOAuthFlowDowngrade_ImplicitGrantTokenIsAlsoAGrant pins that the implicit
// flow is caught on BOTH fields it can be declared through. A server that
// advertises it only under grant_types_supported and keeps response_types
// clean would otherwise walk past.
func TestOAuthFlowDowngrade_ImplicitGrantTokenIsAlsoAGrant(t *testing.T) {
	m := compliantMeta()
	m.GrantTypesSupported = []string{"authorization_code", "implicit"}
	r := ScanOAuthASMetadata(m, "auth.example.com")
	if !hasOAuthSignal(r, SignalOAuthLegacyGrantAdvertised) {
		t.Fatalf("implicit declared as a grant type must be flagged, got %v", oauthSignals(r))
	}
}
