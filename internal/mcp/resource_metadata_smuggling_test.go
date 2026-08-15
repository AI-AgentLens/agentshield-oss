package mcp

import "testing"

func TestScanResourcesList_MetadataSmuggling_TP(t *testing.T) {
	tpCases := []struct {
		name string
		uri  string
		desc string
	}{
		{
			name: "aws_imds_ip_in_query",
			uri:  "https://proxy.example.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			desc: "AWS IMDS IP + path smuggled in query while authority is a benign proxy",
		},
		{
			name: "url_encoded_imds_in_query",
			uri:  "https://cdn.example.com/img?src=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
			desc: "percent-encoded IMDS target must be decoded and caught",
		},
		{
			name: "gcp_metadata_fqdn_in_query",
			uri:  "https://proxy.example.com/get?target=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
			desc: "GCP metadata FQDN + /computeMetadata/ path smuggled in query",
		},
		{
			name: "imds_ip_in_fragment",
			uri:  "https://app.example.com/#/redirect?to=http://169.254.169.254/latest/meta-data/",
			desc: "IMDS target hidden in the URI fragment",
		},
		{
			name: "imds_in_path_proxy_style",
			uri:  "https://proxy.example.com/proxy/http://169.254.169.254/latest/meta-data/iam/",
			desc: "path-based open proxy smuggling the IMDS endpoint in the path",
		},
		{
			name: "azure_metadata_fqdn_in_query",
			uri:  "https://relay.example.com/fwd?u=http://metadata.azure.com/metadata/instance?api-version=2021-02-01",
			desc: "Azure IMDS FQDN smuggled in query",
		},
	}

	for _, tc := range tpCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if !result.Blocked {
				t.Fatalf("MISSED BLOCK: %s\n  URI: %s", tc.desc, tc.uri)
			}
			has := false
			for _, f := range result.Findings {
				if f.Signal == SignalResourceListMetadataSmuggling {
					has = true
				}
			}
			if !has {
				t.Errorf("expected SignalResourceListMetadataSmuggling for %q, got: %+v", tc.uri, result.Findings)
			}
		})
	}
}

func TestScanResourcesList_MetadataSmuggling_TN(t *testing.T) {
	// Realistic developer URIs that look superficially similar but must NOT fire.
	tnCases := []struct {
		name string
		uri  string
		desc string
	}{
		{
			name: "plain_public_api",
			uri:  "https://api.github.com/repos/foo/bar/contents/README.md",
			desc: "ordinary public API URL",
		},
		{
			name: "oauth_redirect_localhost_in_query",
			uri:  "https://auth.example.com/authorize?response_type=code&redirect_uri=http://localhost:3000/callback&client_id=abc",
			desc: "OAuth dev flow with localhost redirect_uri — loopback is NOT an IMDS indicator, must not fire",
		},
		{
			name: "webhook_rfc1918_in_query",
			uri:  "https://api.example.com/v1/webhooks?callback=http://10.0.0.5:8080/hook",
			desc: "internal webhook callback (RFC1918) in query — not an IMDS target, must not fire",
		},
		{
			name: "metadata_word_in_path_not_fqdn",
			uri:  "https://api.example.com/v2/metadata?resource=image&id=42",
			desc: "the word 'metadata' alone (no provider FQDN / IMDS path) must not fire",
		},
		{
			name: "meta_data_in_doc_path_not_imds",
			uri:  "https://docs.example.com/guide/meta-data-formats.html",
			desc: "'meta-data' substring without the '/latest/meta-data' IMDS marker must not fire",
		},
		{
			name: "file_scheme_with_ip_in_name",
			uri:  "file:///workspace/notes-169.254.169.254.txt",
			desc: "non-network file:// scheme — even with the IP in the filename, must not fire (out of scope)",
		},
		{
			name: "public_ip_in_query_not_imds",
			uri:  "https://proxy.example.com/fetch?url=http://8.8.8.8/resolve",
			desc: "public IP (Google DNS) embedded in query is not an IMDS target",
		},
	}

	for _, tc := range tnCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			for _, f := range result.Findings {
				if f.Signal == SignalResourceListMetadataSmuggling {
					t.Errorf("FALSE POSITIVE on %s: %s\n  URI: %s\n  Detail: %s", tc.name, tc.desc, tc.uri, f.Detail)
				}
			}
		})
	}
}
