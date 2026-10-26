package analyzer

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The fixtures use RFC 2606 / RFC 5737 names and benign payloads on purpose:
// what is under test is host extraction and matching, not attack shapes.

func TestEgressAllowlist_Allows(t *testing.T) {
	list, invalid := NewEgressAllowlist([]string{
		"github.com",
		"*.wild.example",
		"192.0.2.10",
		"[2001:db8::1]",
		"https://docs-mcp.example.com/path", // written as a URL: read for its host
		"db.internal.example:5432",          // with a port: read for its host
		" Mixed.Case.Example. ",             // case, trailing dot and spaces
		"",                                  // invalid
		"not a host",                        // invalid
		"*.192.0.2.1",                       // invalid: wildcard on an IP
	})
	if want := []string{"", "not a host", "*.192.0.2.1"}; !reflect.DeepEqual(invalid, want) {
		t.Errorf("invalid entries = %q, want %q", invalid, want)
	}

	cases := []struct {
		host string
		want bool
	}{
		{"github.com", true},
		{"api.github.com", true},
		{"gist.github.com", true},
		{"a.b.github.com", true},
		{"github.com.evil.example", false},
		{"evilgithub.com", false},
		{"github.io", false},
		{"githubusercontent.com", false},
		{"com", false},
		{"wild.example", false}, // *.x is subdomains only
		{"a.wild.example", true},
		{"192.0.2.10", true},
		{"192.0.2.11", false},
		{"::ffff:192.0.2.10", true}, // the same address, IPv4-mapped
		{"2001:db8::1", true},
		{"2001:db8::2", false},
		{"docs-mcp.example.com", true},
		{"db.internal.example", true},
		{"mixed.case.example", true},
		{"pypi.org", false},
	}
	for _, c := range cases {
		host, ok := normalizeHost(c.host)
		if !ok {
			t.Fatalf("normalizeHost(%q) rejected a valid host", c.host)
		}
		if got := list.Allows(host); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// Loopback is never egress, so it passes with an empty list (Gary,
// 2026-10-20). Exactly localhost / *.localhost, 127.0.0.0/8 and ::1; the
// "all interfaces" addresses, lookalike names and alternate spellings of a
// loopback address do not.
func TestEgressAllowlist_LoopbackExempt(t *testing.T) {
	list, _ := NewEgressAllowlist(nil)
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST.", true}, // after normalisation: case and trailing dot
		{"app.localhost", true},
		{"a.b.localhost", true},
		{"127.0.0.1", true},
		{"127.8.9.10", true},
		{"127.255.255.255", true},
		{"[::1]", true},
		{"::ffff:127.0.0.1", true}, // the same IPv4 loopback, IPv4-mapped
		{"localhost.evil.example", false},
		{"evil-localhost", false},
		{"mylocalhost", false},
		{"localhost.localdomain", false},
		{"0.0.0.0", false}, // all interfaces, not this host
		{"[::]", false},
		{"::2", false},
		{"128.0.0.1", false},
		{"126.255.255.255", false},
		{"127.1", false},      // not an IP literal by parseHostIP: an unlisted name
		{"2130706433", false}, // likewise
		{"192.0.2.11", false},
	}
	for _, c := range cases {
		host, ok := normalizeHost(c.host)
		if !ok {
			t.Fatalf("normalizeHost(%q) rejected a valid host", c.host)
		}
		if got := list.Allows(host); got != c.want {
			t.Errorf("Allows(%q) with an empty list = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestEgressAllowlist_IPNeverMatchedByName(t *testing.T) {
	// An IP literal is allowed only when that literal is listed. A host entry
	// whose text happens to end like an address must not cover it.
	list, _ := NewEgressAllowlist([]string{"0.2.10", "example.com"})
	if list.Allows("192.0.2.10") {
		t.Error("an IP was matched by a name entry's suffix rule")
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"GitHub.COM", "github.com", true},
		{"github.com.", "github.com", true},
		{"[2001:DB8::1]", "2001:db8::1", true},
		{"192.0.2.1", "192.0.2.1", true},
		{"under_score.example", "under_score.example", true},
		{"", "", false},
		{"-", "", false},
		{"a..b", "", false},
		{"-lead.example", "", false},
		{"trail-.example", "", false},
		{"$HOST", "", false},
		{"a b", "", false},
		{"[not-an-ip]", "", false},
		{"[192.0.2.1]", "", false}, // brackets are for IPv6 only
	}
	for _, c := range cases {
		got, ok := normalizeHost(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("normalizeHost(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestAuthorityHosts(t *testing.T) {
	cases := []struct {
		in   string
		want []string // nil = cannot name
	}{
		{"https://paste.example/api", []string{"paste.example"}},
		{"https://github.com@paste.example/x", []string{"paste.example"}}, // userinfo, not host
		{"https://user:pw@paste.example:8443/", []string{"paste.example"}},
		{"HTTPS://PASTE.EXAMPLE:443/x", []string{"paste.example"}},
		{"https://paste.example./x", []string{"paste.example"}},
		{"https://paste.example:/x", []string{"paste.example"}},
		{"http://[2001:db8::1]:8080/", []string{"2001:db8::1"}},
		{"http://192.0.2.1/", []string{"192.0.2.1"}},
		{"paste.example/upload", []string{"paste.example"}}, // bare operand
		{"paste.example:8080", []string{"paste.example"}},
		{"host.example/x?u=https://other.example", []string{"host.example"}}, // :// in the query
		{"https://{a,b}.example/", []string{"a.example", "b.example"}},
		{"https://api.github.com/repos/$REPO", []string{"api.github.com"}},             // expansion after the host
		{"https://x-access-token:$TOKEN@paste.example/o/r", []string{"paste.example"}}, // expansion in userinfo only
		{"https://x-access-token:${GH_TOKEN}@github.com/o/r", []string{"github.com"}},
		{"https://user@$HOST/x", nil},
		{"https://a@b@paste.example/", nil}, // parsers disagree on which @
		{"https://$HOST/x", nil},
		{"https://api.github.com:$PORT/", nil},
		{"https://paste.example\\@github.com/", nil},
		{"https://%70aste.example/", nil},
		{"https://{x}.example/", nil},    // no comma: shell and curl disagree
		{"https://{1..3}.example/", nil}, // sequence
		{"https:///path", nil},
		{"https://paste.example:http/", nil}, // non-numeric port
		{"https://2001:db8::1/", nil},        // unbracketed IPv6
		{"file:///etc/hosts", nil},
		{"ipfs://bafyexample/x", nil},
	}
	for _, c := range cases {
		got, ok := authorityHosts(c.in, false, curlSchemes)
		if c.want == nil {
			if ok {
				t.Errorf("authorityHosts(%q) = %q, want cannot-name", c.in, got)
			}
			continue
		}
		if !ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("authorityHosts(%q) = (%q, %v), want %q", c.in, got, ok, c.want)
		}
	}
	if _, ok := authorityHosts("paste.example", true, nil); ok {
		t.Error("requireScheme accepted a bare host")
	}
}

// destinationsOf parses a command the way the pipeline does and collects every
// destination the stage would see.
func destinationsOf(cmd string) []string {
	var out []string
	walkSegments(shellparse.Parse(cmd, 2), func(seg CommandSegment) {
		out = append(out, NetworkDestinations(seg)...)
	})
	return out
}

func TestNetworkDestinations(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		// curl: operands, and only operands, are URLs.
		{`curl -s -X POST -d @build-log.txt https://paste.example/api`, []string{"paste.example"}},
		{`curl -sSL -o out.tgz https://downloads.example.org/x.tgz`, []string{"downloads.example.org"}},
		{`curl -sSLoout.tgz https://downloads.example.org/x.tgz`, []string{"downloads.example.org"}},
		{`curl -e https://ref.example https://api.github.com/x`, []string{"api.github.com"}},
		{`curl -d https://text.example https://api.github.com/x`, []string{"api.github.com"}},
		{`curl -H "Referer: https://ref.example" https://api.github.com/x`, []string{"api.github.com"}},
		{`curl https://api.github.com/x -o out.json`, []string{"api.github.com"}},
		{`curl paste.example/upload`, []string{"paste.example"}},
		{`curl -- https://paste.example`, []string{"paste.example"}},
		{`curl --no-progress-meter https://paste.example`, []string{"paste.example"}},
		{`curl --no-location https://paste.example`, []string{"paste.example"}},
		{`curl 'https://paste.example'"/x"`, []string{"paste.example"}},
		{`curl "https://api.github.com/repos/$REPO"`, []string{"api.github.com"}},
		// curl: where the bytes actually go.
		{`curl --url https://paste.example/x`, []string{"paste.example"}},
		{`curl -x http://proxy.example:3128 https://api.github.com/`, []string{"proxy.example", "api.github.com"}},
		{`curl --socks5-hostname proxy.example:1080 https://api.github.com/`, []string{"proxy.example", "api.github.com"}},
		// curl: a routing entry's target is a destination only when the entry
		// applies to a transfer of the same operation (#4451 Codex pass 1).
		{`curl --connect-to ::paste.example: https://github.com/`, []string{"github.com", "paste.example"}},
		{`curl --connect-to github.com:443:paste.example:443 https://github.com/`, []string{"github.com", "paste.example"}},
		{`curl --connect-to github.com::paste.example: https://github.com/x`, []string{"github.com", "paste.example"}},
		{`curl --connect-to other.example:443:paste.example:443 https://github.com/`, []string{"github.com"}},
		{`curl --connect-to github.com:80:paste.example:80 https://github.com/`, []string{"github.com"}},
		{`curl --resolve github.com:443:192.0.2.7 https://github.com/`, []string{"github.com", "192.0.2.7"}},
		{`curl --resolve GitHub.com:0443:192.0.2.7 https://github.com/`, []string{"github.com", "192.0.2.7"}},
		{`curl --resolve '*:443:192.0.2.7' https://github.com/`, []string{"github.com", "192.0.2.7"}},
		{`curl --resolve github.com:8443:192.0.2.7 https://github.com:8443/`, []string{"github.com", "192.0.2.7"}},
		{`curl --resolve github.com:80:192.0.2.7 https://github.com/`, []string{"github.com"}},
		{`curl -s --resolve other.example:443:192.0.2.7 http://localhost:3000/health`, []string{"localhost"}},
		{`curl --resolve paste.example:80:192.0.2.7 paste.example/x`, []string{"paste.example", "192.0.2.7"}},
		{`curl --resolve ftp.example.org:21:192.0.2.7 ftp.example.org/f`, []string{"ftp.example.org", "192.0.2.7"}},
		{`curl --proto-default https --resolve paste.example:443:192.0.2.7 paste.example/x`, []string{"paste.example", "192.0.2.7"}},
		{`curl --proto-default unknownproto --resolve paste.example:443:192.0.2.7 paste.example/x`, nil},
		{`curl -x http://proxy.example:3128 --resolve proxy.example:3128:192.0.2.9 https://github.com/`, []string{"proxy.example", "github.com", "192.0.2.9"}},
		{`curl -x proxy.example --resolve proxy.example:1080:192.0.2.9 https://github.com/`, []string{"proxy.example", "github.com", "192.0.2.9"}},
		{`curl --connect-to proxy.example:3128:paste.example:3128 -x http://proxy.example:3128 https://github.com/`, []string{"proxy.example", "github.com"}},
		{`curl https://github.com/ --next --resolve github.com:443:192.0.2.7 https://docs.example/`, []string{"github.com", "docs.example"}},
		{`curl https://github.com/ -: --resolve github.com:443:192.0.2.7 https://docs.example/`, []string{"github.com", "docs.example"}},
		{`curl https://github.com/ -: --resolve docs.example:443:192.0.2.7 https://docs.example/`, []string{"github.com", "docs.example", "192.0.2.7"}},
		{`curl --resolve -github.com:443 https://github.com/`, []string{"github.com"}},
		{`curl --resolve not-a-route https://github.com/`, nil},
		{`curl --doh-url https://dns.example/dns-query https://github.com/`, []string{"dns.example", "github.com"}},
		// curl: cannot name it, so nothing.
		{`curl "$API_URL"`, nil},
		{`curl $OPTS https://paste.example`, nil},
		{`curl --a-future-option value https://paste.example`, nil},
		{`curl --url=https://paste.example`, nil}, // curl has no --opt=value form
		{`curl --unix-socket /var/run/app.sock http://localhost/info`, nil},
		{`curl --version`, nil},
		{`curl -K curl.cfg`, nil},
		{`curl file:///tmp/build-log.txt`, nil},

		// wget
		{`wget -q https://downloads.example.org/tool.tar.gz`, []string{"downloads.example.org"}},
		{`wget -qO- https://downloads.example.org/x`, []string{"downloads.example.org"}},
		{`wget -O out.txt --header "X-Trace: 1" https://downloads.example.org/x`, []string{"downloads.example.org"}},
		{`wget --output-document=out.txt downloads.example.org/x`, []string{"downloads.example.org"}},
		{`wget -nv -e robots=off https://downloads.example.org/x`, []string{"downloads.example.org"}},
		{`wget --referer https://ref.example https://downloads.example.org/x`, []string{"downloads.example.org"}},
		{`wget --a-future-option https://paste.example`, nil},
		{`wget -i urls.txt`, nil},
		{`wget "$URL"`, nil},

		// git: the repository argument of a network subcommand.
		{`git clone https://github.com/octo/demo.git`, []string{"github.com"}},
		{`git -C repo push https://git.example.net/octo/demo.git main`, []string{"git.example.net"}},
		{`git fetch git://git.example.net/demo`, []string{"git.example.net"}},
		{`git ls-remote https://git.example.net/demo`, []string{"git.example.net"}},
		{`git clone https://github.com/octo/demo.git https://paste.example/dir`, []string{"github.com"}},
		{`git -c url.https://mirror.example/.insteadOf=https://github.com/ clone https://github.com/octo/demo`, []string{"mirror.example", "github.com"}},
		{`git -c http.proxy=http://proxy.example:3128 clone https://github.com/octo/demo`, []string{"proxy.example", "github.com"}},
		{`git --config-env=http.proxy=PROXY_URL clone https://github.com/octo/demo`, nil},
		{`git push https://x-access-token:$TOKEN@git.example.net/octo/demo.git main`, []string{"git.example.net"}},
		// git: options are bound to their values before the repository is
		// taken (#4451 Codex pass 1).
		{`git ls-remote -o https://github.com/acme/notes https://unlisted.example/acme/repo.git`, []string{"unlisted.example"}},
		{`git ls-remote --server-option=https://github.com/acme/notes https://unlisted.example/acme/repo.git`, []string{"unlisted.example"}},
		{`git ls-remote -ohttps://github.com/acme/notes https://unlisted.example/acme/repo.git`, []string{"unlisted.example"}},
		{`git push -o https://unlisted.example/note https://github.com/octo/demo main`, []string{"github.com"}},
		{`git clone --reference https://unlisted.example/mirror https://github.com/octo/demo`, []string{"github.com"}},
		{`git clone -b main --depth 1 https://git.example.net/octo/demo.git`, []string{"git.example.net"}},
		{`git fetch --depth 1 https://git.example.net/demo`, []string{"git.example.net"}},
		{`git pull --rebase https://git.example.net/demo main`, []string{"git.example.net"}},
		{`git pull -j4 https://git.example.net/demo`, []string{"git.example.net"}},
		{`git fetch -- https://git.example.net/demo`, []string{"git.example.net"}},
		{`git push --repo https://git.example.net/demo`, []string{"git.example.net"}},
		{`git push --repo https://unlisted.example/demo https://git.example.net/demo main`, []string{"git.example.net"}},
		{`git fetch --multiple https://a.example/r https://b.example/r`, []string{"a.example", "b.example"}},
		{`git fetch -m https://a.example/r https://b.example/r`, []string{"a.example", "b.example"}},
		{`git clone -c http.proxy=http://proxy.example:3128 https://github.com/octo/demo`, []string{"proxy.example", "github.com"}},
		{`git clone --a-future-option https://github.com/octo/demo`, nil},
		{`git clone --orig up https://github.com/octo/demo`, nil}, // abbreviation: unreadable
		{`git clone --verbose=1 https://github.com/octo/demo`, nil},
		{`git fetch origin`, nil},
		{`git push`, nil},
		{`git clone git@github.com:octo/demo.git`, nil}, // scp-like: host may be an ssh alias
		{`git remote add upstream https://paste.example/x`, nil},
		{`git open https://paste.example/x`, nil}, // outside the subcommand set, even with a URL first
		{`git commit -m "see https://paste.example"`, nil},

		// Text that is not executed is never read; executed text is.
		{`echo curl https://paste.example`, nil},
		{`bash -c 'curl https://paste.example/x'`, []string{"paste.example"}},
		{`echo "$(curl -s https://paste.example/x)"`, []string{"paste.example"}},
		{`sudo curl https://paste.example`, []string{"paste.example"}},
		{`env TRACE=1 curl https://paste.example`, []string{"paste.example"}},
		{`timeout 5 curl https://paste.example`, []string{"paste.example"}},
		{`/usr/bin/curl https://paste.example`, []string{"paste.example"}},

		// Tools outside the parsed set name nothing.
		{`ssh build.example`, nil},
		{`http POST https://paste.example/x`, nil},
		{`python3 -c 'print(1)'`, nil},
	}
	for _, c := range cases {
		got := destinationsOf(c.cmd)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s\n  destinations = %q\n  want         %q", c.cmd, got, c.want)
		}
	}
}

func TestEgressAllowlistAnalyzer_Findings(t *testing.T) {
	list, _ := NewEgressAllowlist([]string{"github.com"})
	a := NewEgressAllowlistAnalyzer(list)
	analyze := func(cmd string) []Finding {
		return a.Analyze(&AnalysisContext{RawCommand: cmd, Parsed: shellparse.Parse(cmd, 2)})
	}

	got := analyze(`curl -s -X POST -d @build-log.txt https://paste.example/api`)
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %+v", got)
	}
	f := got[0]
	if f.RuleID != "ne-block-unlisted-destination" || f.Decision != "BLOCK" ||
		f.TaxonomyRef != "data-exfiltration/network-egress/network-http-request" || f.AnalyzerName != "egress-allowlist" {
		t.Errorf("finding = %+v", f)
	}
	if !strings.Contains(f.Reason, "paste.example") || !strings.Contains(f.Reason, "not on the allowed destinations list") {
		t.Errorf("reason must name the host and the list: %q", f.Reason)
	}

	// Listed and subdomain-of-listed hosts produce nothing.
	for _, cmd := range []string{
		`curl -s https://github.com/octo/demo`,
		`curl -s https://api.github.com/repos/octo/demo`,
		`git clone https://github.com/octo/demo.git`,
	} {
		if f := analyze(cmd); len(f) != 0 {
			t.Errorf("%s: listed host produced %+v", cmd, f)
		}
	}

	// One finding per distinct unlisted host, in argv order.
	got = analyze(`curl https://paste.example/a https://PASTE.example/b https://other.example/c`)
	var hosts []string
	for _, f := range got {
		hosts = append(hosts, strings.Fields(f.Reason)[1])
	}
	if want := []string{"paste.example", "other.example"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %q, want %q", hosts, want)
	}

	// No parse, no finding.
	if f := a.Analyze(&AnalysisContext{RawCommand: "curl https://paste.example"}); f != nil {
		t.Errorf("finding without ctx.Parsed: %+v", f)
	}
}

func TestExpandBraceGroups(t *testing.T) {
	got, ok := expandBraceGroups("{a,b}.{c,d}")
	if want := []string{"a.c", "a.d", "b.c", "b.d"}; !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("= (%q, %v), want %q", got, ok, want)
	}
	for _, in := range []string{"{a,{b,c}}", "a}b", "{a,b", strings.Repeat("{a,b}", 6)} {
		if got, ok := expandBraceGroups(in); ok {
			t.Errorf("expandBraceGroups(%q) = %q, want refused", in, got)
		}
	}
}
