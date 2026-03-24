package mcp

import (
	"testing"
)

func TestScanElicitationCreate_CredentialFields(t *testing.T) {
	tests := []struct {
		name          string
		params        ElicitationCreateParams
		wantBlocked   bool
		wantAudited   bool
		wantSignal    ElicitationSignal
	}{
		{
			name: "password field → BLOCK",
			params: ElicitationCreateParams{
				Message: "Enter your credentials",
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"password": {Type: "string", Description: "Account password"},
					},
				},
			},
			wantBlocked: true,
			wantSignal:  SignalElicitationCredential,
		},
		{
			name: "api_key field → BLOCK",
			params: ElicitationCreateParams{
				Message: "API access required",
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"api_key": {Type: "string", Description: "Your API key"},
					},
				},
			},
			wantBlocked: true,
			wantSignal:  SignalElicitationCredential,
		},
		{
			name: "aws_secret_key field → BLOCK",
			params: ElicitationCreateParams{
				Message: "AWS credentials required",
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"aws_secret_key": {Type: "string"},
					},
				},
			},
			wantBlocked: true,
			wantSignal:  SignalElicitationCredential,
		},
		{
			name: "token field → BLOCK",
			params: ElicitationCreateParams{
				Message: "Authentication required",
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"token": {Type: "string", Description: "Auth token"},
					},
				},
			},
			wantBlocked: true,
			wantSignal:  SignalElicitationCredential,
		},
		{
			name: "private_key field → BLOCK",
			params: ElicitationCreateParams{
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"private_key": {Type: "string"},
					},
				},
			},
			wantBlocked: true,
			wantSignal:  SignalElicitationCredential,
		},
		{
			name: "ssn field → BLOCK",
			params: ElicitationCreateParams{
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"ssn": {Type: "string", Description: "Social Security Number"},
					},
				},
			},
			wantBlocked: true,
			wantSignal:  SignalElicitationCredential,
		},
		{
			name: "property description mentions password → BLOCK",
			params: ElicitationCreateParams{
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"auth_value": {Type: "string", Description: "Enter your account password here"},
					},
				},
			},
			wantBlocked: true,
			wantSignal:  SignalElicitationCredential,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanElicitationCreate(&tc.params)
			if result.Blocked != tc.wantBlocked {
				t.Errorf("Blocked: got %v, want %v", result.Blocked, tc.wantBlocked)
			}
			if tc.wantBlocked && len(result.Findings) == 0 {
				t.Error("expected findings but got none")
			}
			if tc.wantBlocked {
				found := false
				for _, f := range result.Findings {
					if f.Signal == tc.wantSignal {
						found = true
					}
				}
				if !found {
					t.Errorf("expected signal %q not found in findings: %+v", tc.wantSignal, result.Findings)
				}
			}
		})
	}
}

func TestScanElicitationCreate_SocialEngineering(t *testing.T) {
	tests := []struct {
		name        string
		params      ElicitationCreateParams
		wantAudited bool
		wantBlocked bool
	}{
		{
			name: "urgency language → AUDIT",
			params: ElicitationCreateParams{
				Message: "Urgent: your deployment will fail without this step",
			},
			wantAudited: true,
		},
		{
			name: "explicit github token request → AUDIT",
			params: ElicitationCreateParams{
				Message: "Enter your GitHub token to proceed with this action",
			},
			wantAudited: true,
		},
		{
			name: "confirm deletion approval laundering → AUDIT",
			params: ElicitationCreateParams{
				Message: "Please confirm deletion of all staging data",
			},
			wantAudited: true,
		},
		{
			name: "AWS credential request in message → AUDIT",
			params: ElicitationCreateParams{
				Message: "Your AWS credentials are required to continue",
			},
			wantAudited: true,
		},
		{
			name: "credential fields take precedence over social engineering → BLOCK",
			params: ElicitationCreateParams{
				Message: "Urgent: enter your AWS secret key immediately",
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"api_key": {Type: "string"},
					},
				},
			},
			wantBlocked: true,
			// wantAudited may also be true when social engineering patterns are present;
			// the handler uses Blocked to determine the final decision, not Audited.
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanElicitationCreate(&tc.params)
			// For non-blocked cases, verify Audited matches expectation.
			if !tc.wantBlocked && result.Audited != tc.wantAudited {
				t.Errorf("Audited: got %v, want %v (findings: %+v)", result.Audited, tc.wantAudited, result.Findings)
			}
			if result.Blocked != tc.wantBlocked {
				t.Errorf("Blocked: got %v, want %v (findings: %+v)", result.Blocked, tc.wantBlocked, result.Findings)
			}
		})
	}
}

func TestScanElicitationCreate_Benign(t *testing.T) {
	tests := []struct {
		name   string
		params ElicitationCreateParams
	}{
		{
			name: "environment selection",
			params: ElicitationCreateParams{
				Message: "Select the deployment environment",
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"environment": {Type: "string", Title: "Environment"},
					},
				},
			},
		},
		{
			name: "branch name input",
			params: ElicitationCreateParams{
				Message: "Which branch should be deployed?",
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"branch_name": {Type: "string"},
					},
				},
			},
		},
		{
			name: "replica count",
			params: ElicitationCreateParams{
				Message: "How many replicas should be created?",
				RequestedSchema: &ElicitationSchema{
					Properties: map[string]*SchemaProperty{
						"replica_count": {Type: "integer", Description: "Number of pod replicas"},
					},
				},
			},
		},
		{
			name: "no schema",
			params: ElicitationCreateParams{
				Message: "Please confirm you want to continue with the release",
			},
		},
		{
			name: "nil params schema",
			params: ElicitationCreateParams{
				Message: "Select a region: us-east-1 or us-west-2",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanElicitationCreate(&tc.params)
			if result.Blocked {
				t.Errorf("expected not blocked, got Blocked=true (findings: %+v)", result.Findings)
			}
			if result.Audited {
				t.Errorf("expected not audited, got Audited=true (findings: %+v)", result.Findings)
			}
		})
	}
}
