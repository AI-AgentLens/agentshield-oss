package mcp

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// #4270: basicAuthRe used to be `https?://[^:]+:[^@]+@`, whose negated
// classes cross whitespace, '/', quotes and newlines. It matched from any URL
// to the next ':' and the next '@' anywhere later in the text, and the
// tool-response secret scan BLOCKed on it: 35 of 289 benign corpus docs, the
// cobra README with a 4,122-character match. Every fixture below is built by
// concatenation so no credential-shaped literal sits in this file.

const (
	sch  = "https" + "://"
	schP = "http" + "://"
	at   = "@"
)

// cred joins a userinfo the way a URL does, from parts.
func cred(user, pass string) string { return user + ":" + pass + at }

// fakeAppToken has the shape of a GitHub App installation token ("v1." and 40
// hex digits) and is fake. Written as one literal it was the one exception to
// the rule above, and GitHub push protection refused the agentshield-oss
// publish of 2026-10-15 on it.
var fakeAppToken = "v1." + strings.Repeat("0123456789abcdef", 3)[:40]

// basicAuthTPs are real user:password userinfo shapes. Each must match the
// narrowed pattern, BLOCK as a tool argument, and BLOCK as a tool result.
var basicAuthTPs = map[string]string{
	"plain https":                sch + cred("admin", "s3cret_p4ss") + "internal-api.company.com/data",
	"plain http":                 schP + cred("deploy", "hunter2") + "ci.internal:8080/",
	"percent-encoded userinfo":   sch + cred("jane%40corp.com", "p%40ss%2Fw0rd%20x") + "git.corp.example/repo.git",
	"IPv6 host":                  sch + cred("svc", "Zq9-long_pass") + "[2001:db8::1]:8443/api",
	"raw @ in password":          sch + cred("svc", "p"+at+"ss") + "host.example/",
	"raw : in password":          sch + cred("svc", "a:b:c") + "host.example/",
	"sub-delims in password":     sch + cred("svc", "p!$&'()*+,;=ss") + "host.example/",
	"# and ? in password":        sch + cred("svc", "pa#s?s") + "host.example/",
	"token as password":          sch + cred("x-access-token", fakeAppToken) + "github.example/o/r.git",
	"inside JSON string":         `{"remote":"` + sch + cred("ci", "Tk3n_9xY") + `git.example/r.git"}`,
	"markdown autolink":          "clone <" + sch + cred("ci", "Tk3n_9xY") + "git.example/r.git>",
	"markdown code span":         "run `git clone " + sch + cred("ci", "Tk3n_9xY") + "git.example/r.git`",
	"inside multi-line text":     "line one\nremote = " + sch + cred("ci", "Tk3n_9xY") + "git.example/r.git\nline three",
	"JWT-length password":        sch + cred("x", "eyJ"+strings.Repeat("k", 2500)) + "dev.example/org/_git/repo",
	"long username at the bound": sch + cred(strings.Repeat("u", 256), "pw") + "host.example/",
	// Pass 1 of the review: an e-mail / UPN username written raw. Go
	// net/http, Python and Node all send it as Basic auth.
	"UPN user, raw @ (corporate proxy)":    schP + cred("john.doe"+at+"corp.com", "Passw0rd!2024") + "proxy.corp.com:8080",
	"e-mail user, raw @ (Atlassian token)": sch + cred("me"+at+"company.com", "ATATT3x"+"FfGF0"+strings.Repeat("Zk9_Lq-2", 8)) + "company.atlassian.net/rest/api/3/myself",
	"e-mail user, raw @, inside JSON":      `{"proxy":"` + schP + cred("j.doe"+at+"corp.example", "S3cretPass") + `proxy:3128"}`,
	"password with < > and a backtick":     sch + cred("svc", "p<a>s`s9") + "host.example/",
	"URL after unrelated : and @":          "note: mail me@example.com, then " + sch + cred("ci", "Tk3n_9xY") + "git.example/",
}

// basicAuthTNs are benign texts the old pattern matched by spanning. None
// holds a credential, so none may match.
var basicAuthTNs = map[string]string{
	// The cobra README shape: a URL in an HTML attribute, prose with a ':'
	// further down, and the '@' of a `go get …@latest` line 4,122 bytes later.
	"cobra README shape": `<a href="` + sch + `cobra.dev">` + "\n<img src=\"" + sch + "github.com/user-attachments/assets/c8bf9aad\" />\n</a>\n\n" +
		"Cobra is a library: it provides a simple interface.\n\n# Installing\n\n```\ngo get -u github.com/spf13/cobra" + at + "latest\n```\n",
	"URL then email on the next line":       sch + "example.com\nContact: support" + at + "example.com",
	"URL then prose colon then npm scope":   "Docs at " + sch + "docs.example.com and usage: npm i " + at + "scope/pkg",
	"port then @ in the path (npm scope)":   sch + "registry.npmjs.org:443/" + at + "babel/core",
	"port then @ in the path (mastodon)":    sch + "mastodon.social:443/" + at + "someone",
	"minified JSON, URL then email":         `{"homepage":"` + sch + `lodash.com","author":{"name":"John","email":"john` + at + `example.com"}}`,
	"backticked URL then backticked email":  "see `" + sch + "example.com`:`me" + at + "example.com`",
	"URL then key:value email, same line":   "fetched " + sch + "example.com for email:jane" + at + "example.com",
	"URL with port, then prose, then email": "server " + sch + "ci.example.com:8080 is down, mail ops" + at + "example.com",
	// The user part may not hold '/': an image digest after a path is not
	// userinfo (pass-1 mutant R2 matched it).
	// '"' stays out of the password: a port, then the next JSON value.
	"minified JSON, URL with port then email": `{"u":"` + sch + `h.example:8080","e":"a` + at + `b.example"}`,
	// '"' stays out of the user part: a CSV row, website then a mailto link.
	"CSV row, URL then mailto": `"Acme","` + sch + `acme.example","mailto:jane` + at + `acme.example"`,
	// '>' stays out of the user part: minified HTML with an unquoted attribute.
	"unquoted HTML attribute, then text":   "<a href=" + sch + "example.com>Contact:jane" + at + "example.com",
	"image digest after a path":            sch + "hub.docker.com/_/node:18" + at + "sha256:" + strings.Repeat("ab12", 16),
	"username only, no password":           sch + "ghx_token_value" + at + "github.example/o/r.git",
	"empty username (unchanged from main)": sch + ":onlypass" + at + "host.example/",
	"username over the bound":              sch + cred(strings.Repeat("u", 257), "pw") + "host.example/",
}

func TestBasicAuthRe_TruePositivesStillMatch(t *testing.T) {
	for name, s := range basicAuthTPs {
		if !basicAuthRe.MatchString(s) {
			t.Errorf("TP %q: no longer matches: %q", name, s)
		}
	}
}

func TestBasicAuthRe_SpanningTextDoesNotMatch(t *testing.T) {
	for name, s := range basicAuthTNs {
		if m := basicAuthRe.FindString(s); m != "" {
			t.Errorf("TN %q: matched %q", name, m)
		}
	}
}

// byteArrayLiteral renders s as the numeric byte-array literal the
// obfuscated-secret decoder reads (`var k = [104, 116, ...]`).
func byteArrayLiteral(s string) string {
	parts := make([]string, 0, len(s))
	for i := 0; i < len(s); i++ {
		parts = append(parts, strconv.Itoa(int(s[i])))
	}
	return "var k = [" + strings.Join(parts, ", ") + "]"
}

// Every enforcement path that reads basicAuthRe: an outbound tool argument,
// an inbound tool result as text and as structuredContent (the #3807 secret
// scan), and the byte-array decode re-check (containsKnownSecretPattern).
func TestBasicAuth_AllPathsBlockTPs(t *testing.T) {
	for name, s := range basicAuthTPs {
		arg := ScanToolCallContent("fetch", map[string]interface{}{"url": s})
		basic := false
		for _, f := range arg.Findings {
			basic = basic || f.Signal == SignalBasicAuth
		}
		if !arg.Blocked || !basic {
			t.Errorf("TP %q: tool argument blocked=%v basic_auth=%v", name, arg.Blocked, basic)
		}
		if res := ScanToolCallResponseForSecrets([]ContentItem{{Type: "text", Text: s}}, nil); !res.Blocked {
			t.Errorf("TP %q: tool result (text) not blocked", name)
		}
		if res := ScanToolCallResponseForSecrets(nil, map[string]interface{}{"data": map[string]interface{}{"v": s}}); !res.Blocked {
			t.Errorf("TP %q: tool result (structuredContent) not blocked", name)
		}
		if len(s) <= 512 {
			if b := ScanToolCallContent("write_file", map[string]interface{}{"content": byteArrayLiteral(s)}); !b.Blocked {
				t.Errorf("TP %q: byte-array literal not blocked", name)
			}
		}
	}
}

func TestBasicAuth_ToolResultTNsNotBlocked(t *testing.T) {
	for name, s := range basicAuthTNs {
		res := ScanToolCallResponseForSecrets([]ContentItem{{Type: "text", Text: s}}, nil)
		if res.Blocked {
			t.Errorf("TN %q: tool result blocked: %+v", name, res.Findings)
		}
		arg := ScanToolCallContent("fetch", map[string]interface{}{"body": s})
		for _, f := range arg.Findings {
			if f.Signal == SignalBasicAuth {
				t.Errorf("TN %q: tool argument raised basic_auth", name)
			}
		}
	}
}

// The `Authorization: Basic <base64>` header (#4273) is not a URL-userinfo
// shape, so basicAuthRe must not match it; it is detected on the response
// path as a non-blocking AUDIT finding instead.
func TestBasicAuth_HeaderFormIsAuditOnResponse(t *testing.T) {
	hdr := "Authorization: Basic " + "dXNlcjpwYXNzd29yZA=="
	if basicAuthRe.MatchString(hdr) {
		t.Fatal("basicAuthRe must stay URL-only")
	}
	res := ScanToolCallResponseForSecrets([]ContentItem{{Type: "text", Text: hdr}}, nil)
	if res.Blocked {
		t.Fatalf("the header form must be AUDIT, not BLOCK (%+v)", res.Findings)
	}
	if !res.Found || res.Findings[0].Signal != SignalResponseSecretBasicAuthHeader {
		t.Fatalf("header form not detected: %+v", res)
	}
}

func TestBasicAuthHeader_TPAndTN(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	tps := []string{
		"Authorization: Basic " + enc("admin:hunter2"),
		"curl -H 'Authorization: Basic " + enc("svc:p@ss") + "' https://api.example.com",
		`{"headers":{"authorization":"Basic ` + enc("u:p") + `"}}`,
		"authorization = Basic " + base64.RawURLEncoding.EncodeToString([]byte("a?>:b?>")),
	}
	for _, tp := range tps {
		if _, ok := matchBasicAuthHeader(tp); !ok {
			t.Errorf("expected detection: %q", tp)
		}
		if res := ScanToolCallResponseForSecrets([]ContentItem{{Type: "text", Text: tp}}, nil); res.Blocked || !res.Found {
			t.Errorf("want AUDIT-only finding for %q, got %+v", tp, res)
		}
	}
	tns := []string{
		"Authorization: Basic <credentials>",
		"Authorization: Basic base64string",
		"Authorization: Basic " + enc("nocolonhere"),
		"Use HTTP Basic authentication for the API",
		"The Basic plan includes authorization: yes",
		"Authorization: Bearer abc",
	}
	for _, tn := range tns {
		if _, ok := matchBasicAuthHeader(tn); ok {
			t.Errorf("unexpected detection: %q", tn)
		}
	}
	res := ScanToolCallResponseForSecrets(nil, map[string]interface{}{"req": "Authorization: Basic " + enc("a:b")})
	if !res.Found || res.Blocked {
		t.Errorf("structuredContent: %+v", res)
	}
}
