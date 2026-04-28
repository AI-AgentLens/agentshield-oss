package mcp

import (
	"testing"
)

func TestScanResourcesListResponse_SensitiveTemplates(t *testing.T) {
	tpCases := []struct {
		name string
		uri  string
		desc string
	}{
		{
			name: "ssh_authorized_keys_with_username_var",
			uri:  "file:///home/{username}/.ssh/authorized_keys",
			desc: "RFC 6570 template expanding to ~/.ssh/authorized_keys — must be blocked",
		},
		{
			name: "ssh_id_rsa_with_user_var",
			uri:  "file:///home/{user}/.ssh/id_rsa",
			desc: "RFC 6570 template expanding to ~/.ssh/id_rsa private key — must be blocked",
		},
		{
			name: "aws_credentials_with_user_var",
			uri:  "file:///home/{username}/.aws/credentials",
			desc: "RFC 6570 template expanding to ~/.aws/credentials — must be blocked",
		},
		{
			name: "kube_config_with_user_var",
			uri:  "file:///home/{user}/.kube/config",
			desc: "RFC 6570 template expanding to ~/.kube/config — must be blocked",
		},
		{
			name: "etc_with_variable_filename",
			uri:  "file:///etc/{config_file}",
			desc: "RFC 6570 template with variable /etc/ path component — must be blocked",
		},
		{
			name: "imds_169_with_variable_path",
			uri:  "http://169.254.169.254/{path}",
			desc: "RFC 6570 template targeting IMDS endpoint — must be blocked",
		},
		{
			name: "metadata_google_internal_with_var",
			uri:  "http://metadata.google.internal/computeMetadata/{version}/instance/service-accounts/{account}/token",
			desc: "RFC 6570 template targeting GCE metadata endpoint — must be blocked",
		},
		{
			name: "metadata_service_host_with_variable_path",
			uri:  "http://metadata-service/{path}",
			desc: "RFC 6570 template targeting metadata-service hostname — must be blocked",
		},
		{
			name: "vault_token_with_var",
			uri:  "file:///home/{user}/vault-token",
			desc: "RFC 6570 template expanding to ~/vault-token — must be blocked",
		},
		{
			name: "gnupg_with_var",
			uri:  "file:///home/{username}/.gnupg/secring.gpg",
			desc: "RFC 6570 template targeting .gnupg credential directory — must be blocked",
		},
	}

	for _, tc := range tpCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if !result.Blocked {
				t.Errorf("MISSED BLOCK: %s\n  URI: %s", tc.desc, tc.uri)
			}
		})
	}
}

func TestScanResourcesListResponse_SafeURIs(t *testing.T) {
	tnCases := []struct {
		name string
		uri  string
		desc string
	}{
		{
			name: "github_api_owner_repo_template",
			uri:  "https://api.github.com/{owner}/{repo}",
			desc: "Legitimate GitHub API template with owner/repo variables — must not be blocked",
		},
		{
			name: "workspace_project_readme",
			uri:  "file:///workspace/{project}/README.md",
			desc: "Template file URI under workspace/ — not a sensitive path, must not be blocked",
		},
		{
			name: "no_template_variables",
			uri:  "file:///home/user/.ssh/authorized_keys",
			desc: "Exact path without template variables — handled by other rules, not this scanner",
		},
		{
			name: "generic_api_template",
			uri:  "https://api.example.com/v1/{resource_id}",
			desc: "Generic API template with non-sensitive variable — must not be blocked",
		},
		{
			name: "empty_resources_list",
			uri:  "",
			desc: "Empty URI — must not crash or block",
		},
	}

	for _, tc := range tnCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if result.Blocked {
				t.Errorf("FALSE POSITIVE: %s\n  URI: %s\n  Findings: %v", tc.desc, tc.uri, result.Findings)
			}
		})
	}
}

func TestScanResourcesListResponse_EmptyResult(t *testing.T) {
	result := ScanResourcesListResponse(&ResourcesListResult{})
	if result.Blocked {
		t.Error("Empty resources list should not be blocked")
	}
}

func TestScanResourcesListResponse_MixedResources(t *testing.T) {
	// A list with both safe and malicious URIs — should block on the malicious one
	result := ScanResourcesListResponse(&ResourcesListResult{
		Resources: []ResourceEntry{
			{URI: "https://api.github.com/{owner}/{repo}"},
			{URI: "file:///home/{username}/.ssh/id_rsa"},
			{URI: "file:///workspace/{project}/main.go"},
		},
	})
	if !result.Blocked {
		t.Error("Mixed list with one malicious URI should be blocked")
	}
	if len(result.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d: %v", len(result.Findings), result.Findings)
	}
}
