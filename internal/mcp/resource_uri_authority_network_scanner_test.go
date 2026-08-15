package mcp

import (
	"strings"
	"testing"
)

// -----------------------------------------------------------------------------
// Authority spoofing TP / TN
// -----------------------------------------------------------------------------

func TestScanResourcesList_AuthoritySpoofing_TP(t *testing.T) {
	tpCases := []struct {
		name   string
		uri    string
		reason string
	}{
		{
			name:   "userinfo_with_password_on_https",
			uri:    "https://user:hunter2@evil.com/api",
			reason: "embedded password in userinfo — leaks secrets to network logs and the receiving server",
		},
		{
			name:   "authority_confusion_github_lookalike",
			uri:    "https://github.com@evil.com/repo",
			reason: "github.com is the userinfo and evil.com is the host — skim-reader sees github.com but the fetch targets evil.com",
		},
		{
			name:   "authority_confusion_internal_lookalike",
			uri:    "https://internal-api.corp.com@attacker.example/",
			reason: "hostname-shaped userinfo on http(s) — confusion attack",
		},
		{
			name:   "file_uri_with_remote_authority",
			uri:    "file://attacker.com/share/payload.txt",
			reason: "file:// with non-local authority is UNC on Windows / hostname spoof on permissive Unix hosts",
		},
		{
			name:   "file_uri_with_subdomain_localhost_lookalike",
			uri:    "file://localhost.attacker.com/path",
			reason: "localhost subdomain lookalike is not the canonical localhost form",
		},
		{
			name:   "userinfo_with_password_on_http",
			uri:    "http://admin:s3cret@10.example.test/api",
			reason: "userinfo with password on plain http",
		},
	}

	for _, tc := range tpCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if !result.Blocked {
				t.Errorf("MISSED BLOCK: %s\n  URI: %s\n  Reason: %s", tc.name, tc.uri, tc.reason)
				return
			}
			found := false
			for _, f := range result.Findings {
				if f.Signal == SignalResourceListAuthoritySpoofing {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("blocked but missing SignalResourceListAuthoritySpoofing for %q. findings=%+v", tc.uri, result.Findings)
			}
		})
	}
}

func TestScanResourcesList_AuthoritySpoofing_TN(t *testing.T) {
	tnCases := []struct {
		name string
		uri  string
		desc string
	}{
		{
			name: "file_uri_empty_authority_workspace_readme",
			uri:  "file:///workspace/project/README.md",
			desc: "RFC 8089 canonical file URI — empty authority",
		},
		{
			name: "file_uri_localhost_authority",
			uri:  "file://localhost/workspace/project/README.md",
			desc: "RFC 8089 allows explicit 'localhost' authority on file://",
		},
		{
			name: "ssh_userinfo_legitimate",
			uri:  "ssh://git@github.com/owner/repo.git",
			desc: "SSH always carries a username — exempt from userinfo flag",
		},
		{
			name: "git_plus_ssh_userinfo_legitimate",
			uri:  "git+ssh://git@gitlab.example.com/group/project.git",
			desc: "git+ssh is a common rewrite scheme — userinfo is standard",
		},
		{
			name: "https_public_docs_no_userinfo",
			uri:  "https://docs.python.org/3/library/os.html",
			desc: "Public docs URL — no userinfo, no spoofing",
		},
		{
			name: "https_public_api_no_userinfo",
			uri:  "https://api.github.com/repos/example/example",
			desc: "Public API URL",
		},
		{
			name: "ftp_with_userinfo_legitimate",
			uri:  "ftp://anonymous@ftp.gnu.org/pub/gnu/",
			desc: "FTP traditionally carries userinfo — exempt",
		},
	}

	for _, tc := range tnCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if result.Blocked {
				for _, f := range result.Findings {
					if f.Signal == SignalResourceListAuthoritySpoofing {
						t.Errorf("FALSE POSITIVE on authority-spoofing: %s\n  URI: %s\n  Detail: %s", tc.desc, tc.uri, f.Detail)
					}
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Internal network TP / TN
// -----------------------------------------------------------------------------

func TestScanResourcesList_InternalNetwork_TP(t *testing.T) {
	tpCases := []struct {
		name string
		uri  string
		why  string
	}{
		{
			name: "ipv4_loopback_redis",
			uri:  "http://127.0.0.1:6379/dump",
			why:  "loopback Redis admin endpoint",
		},
		{
			name: "ipv4_rfc1918_10_admin",
			uri:  "https://10.0.0.5/admin",
			why:  "10.0.0.0/8 RFC 1918 admin endpoint",
		},
		{
			name: "ipv4_rfc1918_192_168_router",
			uri:  "http://192.168.1.1/router-config",
			why:  "192.168.0.0/16 RFC 1918 router endpoint",
		},
		{
			name: "ipv4_link_local_imds",
			uri:  "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			why:  "AWS IMDS",
		},
		{
			name: "ipv4_rfc1918_172_16",
			uri:  "https://172.20.0.5/api",
			why:  "172.16/12 RFC 1918",
		},
		{
			name: "ipv6_loopback",
			uri:  "http://[::1]:8080/api",
			why:  "IPv6 loopback",
		},
		{
			name: "ipv6_link_local",
			uri:  "http://[fe80::1]/admin",
			why:  "IPv6 link-local",
		},
		{
			name: "ipv6_unique_local",
			uri:  "https://[fd12:3456:789a::1]/dashboard",
			why:  "IPv6 unique-local (fc00::/7)",
		},
		{
			name: "imds_alt_form_decimal_int",
			uri:  "http://2852039166/latest/meta-data/",
			why:  "169.254.169.254 encoded as a single decimal integer",
		},
		{
			name: "imds_alt_form_octal_dotted",
			uri:  "http://0251.0376.0251.0376/latest/meta-data/",
			why:  "169.254.169.254 encoded as octal dotted-quad",
		},
		{
			name: "imds_alt_form_hex_dotted",
			uri:  "http://0xa9.0xfe.0xa9.0xfe/",
			why:  "169.254.169.254 encoded as hex dotted-quad",
		},
		{
			name: "imds_alt_form_hex_single_int",
			uri:  "http://0xa9fea9fe/",
			why:  "169.254.169.254 encoded as a single hex integer",
		},
		{
			name: "all_interfaces_bind",
			uri:  "http://0.0.0.0:8080/",
			why:  "0.0.0.0 binds to all local interfaces — effectively loopback when fetched from local host",
		},
		{
			name: "localhost_hostname",
			uri:  "http://localhost:8000/admin",
			why:  "explicit localhost hostname",
		},
		{
			name: "gcp_metadata_hostname",
			uri:  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
			why:  "GCP IMDS hostname",
		},
	}

	for _, tc := range tpCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if !result.Blocked {
				t.Errorf("MISSED BLOCK: %s\n  URI: %s\n  Why: %s", tc.name, tc.uri, tc.why)
				return
			}
			found := false
			for _, f := range result.Findings {
				if f.Signal == SignalResourceListInternalNetwork {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("blocked but missing SignalResourceListInternalNetwork for %q. findings=%+v", tc.uri, result.Findings)
			}
		})
	}
}

func TestScanResourcesList_InternalNetwork_TN(t *testing.T) {
	tnCases := []struct {
		name string
		uri  string
		desc string
	}{
		{
			name: "public_https_github_api",
			uri:  "https://api.github.com/repos/example/repo",
			desc: "public host on public IP",
		},
		{
			name: "public_https_docs_python",
			uri:  "https://docs.python.org/3/library/os.html",
			desc: "public docs site",
		},
		{
			name: "public_ipv4_dotted_decimal",
			uri:  "https://8.8.8.8/",
			desc: "8.8.8.8 is Google DNS — public IP, not RFC 1918",
		},
		{
			name: "public_ipv4_close_to_172_but_outside_rfc1918",
			uri:  "https://172.32.5.10/api",
			desc: "172.32.x.x is OUTSIDE RFC 1918 (16–31 range)",
		},
		{
			name: "public_ipv6_globally_routable",
			uri:  "https://[2606:4700:4700::1111]/dns-query",
			desc: "Cloudflare public IPv6 DNS — globally routable, not internal",
		},
		{
			name: "file_uri_workspace_path",
			uri:  "file:///workspace/project/notes.md",
			desc: "file URI — handled by other rules, not internal-network",
		},
		{
			name: "mailto_uri",
			uri:  "mailto:maintainer@example.com",
			desc: "non-network scheme",
		},
		{
			name: "custom_mcp_scheme",
			uri:  "mcp+resource://workspace/foo",
			desc: "custom MCP scheme — not in network-fetch list",
		},
		{
			name: "ipv4_close_to_127_but_outside_loopback",
			uri:  "https://128.0.0.1/",
			desc: "128.0.0.1 starts with 128 not 127 — outside loopback",
		},
		{
			name: "ipv4_close_to_10_but_outside_rfc1918",
			uri:  "https://100.0.0.1/",
			desc: "100.x.x.x is NOT 10.x.x.x — outside RFC 1918",
		},
	}

	for _, tc := range tnCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if result.Blocked {
				for _, f := range result.Findings {
					if f.Signal == SignalResourceListInternalNetwork {
						t.Errorf("FALSE POSITIVE on internal-network: %s\n  URI: %s\n  Detail: %s", tc.desc, tc.uri, f.Detail)
					}
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Multi-cloud IMDS (Alibaba 100.100.100.200 / Oracle 192.0.0.192) TP / TN
//
// 169.254.169.254 (AWS/GCP/Azure) is link-local and already covered by the
// RFC1918/loopback/link-local regex. Alibaba's metadata IP lives in the RFC 6598
// CGNAT block and Oracle's in the 192.0.0.0/24 IETF-assignments block — both
// OUTSIDE RFC 1918, so a denylist tuned to AWS misses them. These must block in
// the authority, under alternative-form encoding, and when smuggled into the
// path/query/fragment.
// -----------------------------------------------------------------------------

func TestScanResourcesList_MultiCloudIMDS_TP(t *testing.T) {
	tpCases := []struct {
		name   string
		uri    string
		signal ResourceListSignal
		why    string
	}{
		{
			name:   "alibaba_imds_authority",
			uri:    "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
			signal: SignalResourceListInternalNetwork,
			why:    "Alibaba Cloud ECS metadata service (RFC 6598 CGNAT — bypasses RFC1918 denylists)",
		},
		{
			name:   "oracle_imds_authority",
			uri:    "http://192.0.0.192/opc/v1/instance/metadata/",
			signal: SignalResourceListInternalNetwork,
			why:    "Oracle Cloud legacy IMDS (192.0.0.0/24 IETF-assignments — bypasses RFC1918 denylists)",
		},
		{
			name:   "alibaba_imds_hex_single_int",
			uri:    "http://0x646464c8/latest/meta-data/",
			signal: SignalResourceListInternalNetwork,
			why:    "100.100.100.200 encoded as a single hex integer — alt-form evasion",
		},
		{
			name:   "oracle_imds_decimal_int",
			uri:    "http://3221225664/opc/v1/instance/",
			signal: SignalResourceListInternalNetwork,
			why:    "192.0.0.192 encoded as a single decimal integer — alt-form evasion",
		},
		{
			name:   "alibaba_imds_smuggled_in_query",
			uri:    "https://fetch.example.com/proxy?target=http://100.100.100.200/latest/meta-data/",
			signal: SignalResourceListMetadataSmuggling,
			why:    "Alibaba IMDS smuggled into a benign-looking proxy query param",
		},
		{
			name:   "oracle_imds_smuggled_in_fragment",
			uri:    "https://cdn.example.com/redirect#http://192.0.0.192/opc/v1/instance/",
			signal: SignalResourceListMetadataSmuggling,
			why:    "Oracle IMDS smuggled into the URI fragment",
		},
	}

	for _, tc := range tpCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if !result.Blocked {
				t.Errorf("MISSED BLOCK: %s\n  URI: %s\n  Why: %s", tc.name, tc.uri, tc.why)
				return
			}
			found := false
			for _, f := range result.Findings {
				if f.Signal == tc.signal {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("blocked but missing %s for %q. findings=%+v", tc.signal, tc.uri, result.Findings)
			}
		})
	}
}

func TestScanResourcesList_MultiCloudIMDS_TN(t *testing.T) {
	// Near-miss addresses that must NOT fire: the IMDS check is an exact-literal
	// match, not a range. A public host one octet off an IMDS literal is benign.
	tnCases := []struct {
		name string
		uri  string
		desc string
	}{
		{
			name: "cgnat_neighbor_not_alibaba_imds",
			uri:  "https://100.100.100.201/api",
			desc: "100.100.100.201 is one off the Alibaba IMDS literal — not the metadata endpoint",
		},
		{
			name: "ietf_assignments_neighbor_not_oracle_imds",
			uri:  "https://192.0.0.193/health",
			desc: "192.0.0.193 is one off the Oracle IMDS literal — not the metadata endpoint",
		},
		{
			name: "documentation_range_testnet1",
			uri:  "https://192.0.2.10/sample",
			desc: "192.0.2.0/24 is TEST-NET-1 documentation range — not the Oracle IMDS literal",
		},
		{
			name: "public_cgnat_lookalike",
			uri:  "https://100.64.0.1/cdn-asset",
			desc: "100.64.0.1 is in the CGNAT block but is not the Alibaba IMDS literal",
		},
	}

	for _, tc := range tnCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if result.Blocked {
				for _, f := range result.Findings {
					if f.Signal == SignalResourceListInternalNetwork || f.Signal == SignalResourceListMetadataSmuggling {
						t.Errorf("FALSE POSITIVE on multi-cloud IMDS: %s\n  URI: %s\n  Detail: %s", tc.desc, tc.uri, f.Detail)
					}
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Scheme evasion TP / TN
// -----------------------------------------------------------------------------

func TestScanResourcesList_SchemeEvasion_TP(t *testing.T) {
	tpCases := []struct {
		name string
		uri  string
		why  string
	}{
		{
			name: "tab_in_javascript",
			uri:  "java\tscript:alert(steal())",
			why:  "embedded TAB in scheme — WebKit/Electron strip tabs during URL parsing",
		},
		{
			name: "newline_in_javascript",
			uri:  "javasc\nript:alert('xss')",
			why:  "embedded LF in scheme",
		},
		{
			name: "carriage_return_in_vbscript",
			uri:  "vbsc\rript:msgbox(\"pwn\")",
			why:  "embedded CR in scheme",
		},
		{
			name: "tab_in_data",
			uri:  "da\tta:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
			why:  "embedded TAB in data: scheme — smuggled HTML payload",
		},
		{
			name: "percent_encoded_j_in_javascript",
			uri:  "%6aavascript:alert(1)",
			why:  "percent-encoded 'j' — some hosts re-decode scheme bytes",
		},
		{
			name: "null_in_javascript",
			uri:  "java\x00script:alert(1)",
			why:  "embedded NUL byte",
		},
	}

	for _, tc := range tpCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if !result.Blocked {
				t.Errorf("MISSED BLOCK: %s\n  URI: %q\n  Why: %s", tc.name, tc.uri, tc.why)
				return
			}
			found := false
			for _, f := range result.Findings {
				if f.Signal == SignalResourceListSchemeEvasion {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("blocked but missing SignalResourceListSchemeEvasion for %q. findings=%+v", tc.uri, result.Findings)
			}
		})
	}
}

func TestScanResourcesList_SchemeEvasion_TN(t *testing.T) {
	tnCases := []struct {
		name string
		uri  string
		desc string
	}{
		{
			name: "normal_https",
			uri:  "https://api.github.com/repos/example/repo",
			desc: "vanilla https — must not trigger evasion rule",
		},
		{
			name: "normal_file_uri",
			uri:  "file:///workspace/notes.md",
			desc: "vanilla file URI",
		},
		{
			name: "git_plus_ssh_scheme",
			uri:  "git+ssh://git@github.com/owner/repo.git",
			desc: "scheme with '+' is valid RFC 3986 — must not flag",
		},
		{
			name: "custom_vscode_scheme",
			uri:  "vscode://file/workspace/project/foo.ts",
			desc: "custom IDE scheme — clean characters",
		},
		{
			name: "percent_encoded_in_path_not_scheme",
			uri:  "https://api.example.com/path/with%20space",
			desc: "percent-encoding in path is fine; only scheme matters",
		},
		{
			name: "uri_with_inline_colon_in_path",
			uri:  "https://example.com/foo:bar/baz",
			desc: "colon later in URI must not confuse the scheme parser",
		},
	}

	for _, tc := range tnCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{
				Resources: []ResourceEntry{{URI: tc.uri}},
			})
			if result.Blocked {
				for _, f := range result.Findings {
					if f.Signal == SignalResourceListSchemeEvasion {
						t.Errorf("FALSE POSITIVE on scheme-evasion: %s\n  URI: %q\n  Detail: %s", tc.desc, tc.uri, f.Detail)
					}
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Helper-level unit tests (ipv4FromAltForm + isInternalIPv6)
// -----------------------------------------------------------------------------

func TestIPv4FromAltForm(t *testing.T) {
	cases := []struct {
		host string
		want string
		ok   bool
	}{
		{"169.254.169.254", "", false}, // standard dotted-decimal — not alt-form
		{"127.0.0.1", "", false},
		{"2852039166", "169.254.169.254", true},
		{"0xa9fea9fe", "169.254.169.254", true},
		{"0251.0376.0251.0376", "169.254.169.254", true},
		{"0xa9.0xfe.0xa9.0xfe", "169.254.169.254", true},
		{"example.com", "", false},
		{"", "", false},
		{"0", "0.0.0.0", true},
	}
	for _, c := range cases {
		got, ok := ipv4FromAltForm(c.host)
		if ok != c.ok {
			t.Errorf("ipv4FromAltForm(%q) ok = %v, want %v (got=%q)", c.host, ok, c.ok, got)
			continue
		}
		if ok && got != c.want {
			t.Errorf("ipv4FromAltForm(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

func TestIsInternalIPv6(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"::1", true},
		{"0:0:0:0:0:0:0:1", true},
		{"fe80::1", true},
		{"fe80::abcd:1", true},
		{"febf::1", true},
		{"fc00::1", true},
		{"fdff::abcd", true},
		{"2606:4700:4700::1111", false}, // public
		{"2001:db8::1", false},          // documentation prefix — public space
		{"8.8.8.8", false},              // IPv4 — not IPv6
		{"", false},
	}
	for _, c := range cases {
		got := isInternalIPv6(c.host)
		if got != c.want {
			t.Errorf("isInternalIPv6(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Sanity: handler reason strings include enough context for the audit log
// -----------------------------------------------------------------------------

func TestFindingDetailsAreActionable(t *testing.T) {
	// Verify each new signal's detail mentions a concrete actionable phrase a
	// SecOps reader could grep for in the audit log.
	cases := []struct {
		uri        string
		wantSubstr string
	}{
		{"http://10.0.0.5/admin", "private/loopback/link-local"},
		{"http://2852039166/", "alternative-form IPv4"},
		{"java\tscript:alert(1)", "embedded control characters"},
		{"file://attacker.com/share/payload", "RFC 8089"},
		{"https://github.com@evil.com/", "authority-confusion"},
	}
	for _, c := range cases {
		result := ScanResourcesListResponse(&ResourcesListResult{
			Resources: []ResourceEntry{{URI: c.uri}},
		})
		if !result.Blocked {
			t.Errorf("expected block for %q", c.uri)
			continue
		}
		var combined string
		for _, f := range result.Findings {
			combined += f.Detail + "\n"
		}
		if !strings.Contains(combined, c.wantSubstr) {
			t.Errorf("uri %q: findings missing substring %q. got=%s", c.uri, c.wantSubstr, combined)
		}
	}
}

// -----------------------------------------------------------------------------
// DNS-rebinding SSRF: an internal IPv4 smuggled into the DNS labels of a
// public-looking hostname (nip.io / sslip.io / xip.io / traefik.me and any other
// wildcard-DNS service). The authority parses as a hostname, not a bare IP, so
// the IP-literal checks all miss it. Detection is range-gated on the embedded
// octets, so embedded PUBLIC IPs (legit reverse-DNS / EC2-style names) stay clean.
// -----------------------------------------------------------------------------

func TestScanResourcesList_DNSRebindingEmbeddedIP_TP(t *testing.T) {
	tpCases := []struct {
		name string
		uri  string
		why  string
	}{
		{"nip_io_imds_dotted", "https://169.254.169.254.nip.io/latest/meta-data/iam/security-credentials/", "AWS IMDS via nip.io dotted form"},
		{"nip_io_imds_dashed", "http://169-254-169-254.nip.io/latest/meta-data/", "AWS IMDS via nip.io dashed form"},
		{"sslip_io_rfc1918", "https://10.0.0.1.sslip.io/admin", "RFC1918 10/8 via sslip.io"},
		{"xip_io_loopback", "http://127.0.0.1.xip.io/dump", "loopback via xip.io"},
		{"traefik_me_dashed_192", "http://192-168-1-1.traefik.me/router-config", "192.168/16 via traefik.me dashed"},
		{"nip_io_alibaba_imds", "http://100.100.100.200.nip.io/latest/meta-data/", "Alibaba IMDS (CGNAT) embedded"},
		{"nip_io_oracle_imds", "https://192.0.0.192.nip.io/opc/v1/instance/", "Oracle IMDS (192.0.0.0/24) embedded"},
		{"embedded_mid_hostname", "https://app.192.168.0.5.attacker.example/dashboard", "internal IP embedded mid-hostname, non-leading"},
	}
	for _, tc := range tpCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{Resources: []ResourceEntry{{URI: tc.uri}}})
			if !result.Blocked {
				t.Errorf("MISSED BLOCK: %s\n  URI: %s\n  Why: %s", tc.name, tc.uri, tc.why)
				return
			}
			found := false
			for _, f := range result.Findings {
				if f.Signal == SignalResourceListInternalNetwork {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("blocked but missing SignalResourceListInternalNetwork for %q. findings=%+v", tc.uri, result.Findings)
			}
		})
	}
}

func TestScanResourcesList_DNSRebindingEmbeddedIP_TN(t *testing.T) {
	tnCases := []struct {
		name string
		uri  string
		desc string
	}{
		{"ec2_public_reverse_dns", "https://ec2-54-12-34-56.compute-1.amazonaws.com/api", "EC2-style name embeds a PUBLIC IP in a prefixed label — not a bare dashed quad, public range"},
		{"public_ip_via_nip_io", "https://1.2.3.4.nip.io/", "nip.io with a PUBLIC IP — no internal target, no SSRF"},
		{"public_ip_embedded", "https://8.8.8.8.cdn.example.com/asset.js", "8.8.8.8 embedded is a public IP"},
		{"two_numeric_labels_only", "https://192.168.example.com/", "only two numeric labels — not a full embedded quad"},
		{"octets_outside_rfc1918", "https://172.32.0.1.example.com/", "172.32 is outside RFC 1918 (16–31) — public"},
		{"dashed_triplet_not_quad", "https://10-20-30.svc.example.com/", "three dashed octets, not a 4-octet quad"},
		{"versioned_build_label", "https://build-123-456.ci.example.com/status", "non-numeric prefix on dashed label — not a quad"},
		{"semver_like_labels", "https://1.2.30.release.example.com/notes", "numeric labels but not 4 consecutive valid octets forming an internal IP"},
	}
	for _, tc := range tnCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanResourcesListResponse(&ResourcesListResult{Resources: []ResourceEntry{{URI: tc.uri}}})
			if result.Blocked {
				for _, f := range result.Findings {
					if f.Signal == SignalResourceListInternalNetwork {
						t.Errorf("FALSE POSITIVE on DNS-rebinding: %s\n  URI: %s\n  Detail: %s", tc.desc, tc.uri, f.Detail)
					}
				}
			}
		})
	}
}
