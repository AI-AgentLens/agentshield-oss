package analyzer

import (
	"net/netip"
	"strings"
)

// safeDNSLookupOnly reports whether a command earns the DNS-safe override
// (sem-allow-dns-safe, sem-allow-dns-safe-recon, and through their
// dns-query-safe intent ts-sem-allow-dns-safe). Two conditions: at least one
// dig/nslookup/host query for a well-known security record (DMARC, SPF, DKIM,
// ACME, MTA-STS), and EVERY segment is either such a query or a text filter
// that cannot run anything.
//
// The "every segment" half is the fix for #4000. The combiner applies an
// override to its whole taxonomy across the whole command, so a safe lookup
// appended to a DNS-tunneling or zone-transfer command used to turn that
// command's BLOCK into ALLOW: 13 of 13 corpus TPs in
// TestOverrideCannotSilenceAnotherStatement. A short allowlist is the right
// shape here because it GRANTS an ALLOW, and the safe set can be listed. The
// stream editors are left out on purpose, because both of the common ones can
// run commands.
//
// Within a lookup segment the same holds for its operands (#4594): every
// operand must be safe, not just one. See dnsOperandsAllSafe. And a safe name
// must be a literal (#4625): see isSafeDNSRecordName.
func safeDNSLookupOnly(parsed *ParsedCommand) bool {
	sawSafeLookup := false
	for _, seg := range allSegments(parsed) {
		switch seg.Executable {
		case "dig", "nslookup", "host":
			// hasSafeDNSRecordArg is the grant main made, and it is what
			// requires at least one safe name. dnsOperandsAllSafe can only take
			// grants away from it, so this predicate can never grant the
			// override where main did not.
			if !hasSafeDNSRecordArg(seg.Args) || !dnsOperandsAllSafe(seg.Executable, seg.RawWords) {
				return false
			}
			sawSafeLookup = true
		case "grep", "egrep", "fgrep", "cut", "head", "tail", "sort", "uniq", "tr", "jq", "wc":
			// pure text filters on the lookup's output
		default:
			return false
		}
	}
	return sawSafeLookup
}

// hasSafeDNSRecordArg reports whether any argument names a well-known
// security record.
func hasSafeDNSRecordArg(args []string) bool {
	for _, arg := range args {
		if isSafeDNSRecordName(arg) {
			return true
		}
	}
	return false
}

// isSafeDNSRecordName reports whether a word names a well-known security
// record. The prefix list is unchanged from the override's original inline
// form.
//
// The word must also be a literal (#4625). A prefix test alone accepted
// anything after "_dmarc.", so `_dmarc.${X}.exfil.invalid` earned the
// override and its receipt attested a DMARC lookup for a name built from the
// environment. A name Shield cannot read is a name it cannot vouch for, so a
// word the shell would rewrite voids the override and the other rules decide.
// That can only take an ALLOW away.
func isSafeDNSRecordName(word string) bool {
	if !isLiteralShellWord(word) {
		return false
	}
	lower := strings.ToLower(word)
	return strings.HasPrefix(lower, "_dmarc.") ||
		strings.HasPrefix(lower, "_spf.") ||
		strings.HasPrefix(lower, "_dkim.") ||
		strings.HasPrefix(lower, "_domainkey.") ||
		strings.HasPrefix(lower, "_acme-challenge.") ||
		strings.HasPrefix(lower, "_mta-sts.")
}

// nonLiteralWordChars are the characters that let the shell, rather than the
// text as written, decide what a word becomes (#4625): "$" opens every
// parameter, command and arithmetic expansion and ANSI-C quoting, "`" the old
// command substitution, "*?[" a glob, the quotes and the backslash quoting.
// The words are CommandSegment.RawWords and Args, which keep this text as
// written. Brace expansion is left out on purpose: its text is all written
// out, and every word it yields keeps the literal prefix in front of it.
const nonLiteralWordChars = "$`*?[\"'\\"

// isLiteralShellWord reports whether the shell passes word through unchanged,
// so the text Shield reads is the text the program receives.
func isLiteralShellWord(word string) bool {
	return !strings.ContainsAny(word, nonLiteralWordChars)
}

// dnsOperandsAllSafe reports whether EVERY word of one dig/nslookup/host
// invocation is safe to vouch for (#4594). dig sends one query per name, and
// nslookup and host resolve a server written as a host name before they
// query it, so one security-record operand used to earn the override for an
// invocation that also put an arbitrary name on the wire.
//
// The rule: every name the tool would look up must be a security-record name.
// Every other word must be a lookup record type, a class, a server written as
// an IP literal, or an option whose value is one of those or a number. Any
// other word voids the override, including one this walk does not know. That
// direction is safe because the walk only ever takes an ALLOW away: an
// unrecognised word leaves the command at the decision its other rules give.
//
// words is the segment's argv in order (CommandSegment.RawWords), because
// Args and Flags lose which value belongs to which option. Words are read as
// written: a quoted word matches nothing here and voids the override, as it
// already failed the prefix test on main.
func dnsOperandsAllSafe(exe string, words []string) bool {
	switch exe {
	case "dig":
		return digWordsSafe(words)
	case "nslookup":
		return nslookupWordsSafe(words)
	case "host":
		return hostWordsSafe(words)
	}
	return false
}

// digWordsSafe walks dig's argv. dig reads every positional word as a type, a
// class, or a query name, in any order, so every name must be safe.
func digWordsSafe(words []string) bool {
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case strings.HasPrefix(w, "-"):
			consumed, ok := shortOptionsSafe(w[1:], words[i+1:], digBoolFlags, digValueFlags)
			if !ok {
				return false
			}
			i += consumed
		case strings.HasPrefix(w, "+"):
			if !digQueryOptionSafe(w[1:]) {
				return false
			}
		case strings.HasPrefix(w, "@"):
			if !isIPLiteral(w[1:]) {
				return false
			}
		case isLookupRRType(w), isDNSClass(w), isSafeDNSRecordName(w):
		default:
			return false
		}
	}
	return true
}

// nslookupWordsSafe walks nslookup's argv: options anywhere, then at most a
// name and a server. A bare "-" switches to interactive mode, where the names
// come from stdin, so it is not a safe name and voids the override.
func nslookupWordsSafe(words []string) bool {
	var operands []string
	for _, w := range words {
		if len(w) > 1 && strings.HasPrefix(w, "-") {
			if !nslookupOptionSafe(w[1:]) {
				return false
			}
			continue
		}
		operands = append(operands, w)
	}
	return nameThenServerSafe(operands)
}

// hostWordsSafe walks host's argv: getopt options, then a name and an
// optional server. -l is a zone transfer, so it is not in the allowed flags.
func hostWordsSafe(words []string) bool {
	var operands []string
	for i := 0; i < len(words); i++ {
		w := words[i]
		if len(w) > 1 && strings.HasPrefix(w, "-") {
			consumed, ok := shortOptionsSafe(w[1:], words[i+1:], hostBoolFlags, hostValueFlags)
			if !ok {
				return false
			}
			i += consumed
			continue
		}
		operands = append(operands, w)
	}
	return nameThenServerSafe(operands)
}

// nameThenServerSafe checks nslookup's and host's operands: a security-record
// name, then optionally a server. The server must be an IP literal, because
// a server written as a host name is itself looked up first.
func nameThenServerSafe(operands []string) bool {
	switch len(operands) {
	case 1:
		return isSafeDNSRecordName(operands[0])
	case 2:
		return isSafeDNSRecordName(operands[0]) && isIPLiteral(operands[1])
	}
	return false
}

// dig's and host's short options. A flag listed in neither table voids the
// override, and so does every value-taking flag left out of the value table:
// dig -q (the value is a name, so it must pass as one), -x (a reverse lookup
// of an address), -f (names read from a file), -b, -k and -y; host -l (a zone
// transfer) and -m.
const (
	digBoolFlags  = "46hmruv"
	hostBoolFlags = "aACdirsTUvVw46"
)

var (
	digValueFlags = map[byte]func(string) bool{
		't': isLookupRRType,
		'c': isDNSClass,
		'p': isDigits,
		'q': isSafeDNSRecordName,
	}
	hostValueFlags = map[byte]func(string) bool{
		't': isLookupRRType,
		'c': isDNSClass,
		'N': isDigits,
		'p': isDigits,
		'R': isDigits,
		'W': isDigits,
	}
)

// shortOptionsSafe reads one short-option cluster the way dig and getopt do:
// boolean flags first, then at most one value-taking flag whose value is the
// rest of the cluster or, when the cluster ends there, the next word. It
// returns how many following words the value consumed.
func shortOptionsSafe(cluster string, rest []string, bools string, values map[byte]func(string) bool) (int, bool) {
	if cluster == "" {
		return 0, false
	}
	for j := 0; j < len(cluster); j++ {
		c := cluster[j]
		if strings.IndexByte(bools, c) >= 0 {
			continue
		}
		valueOK, takesValue := values[c]
		if !takesValue {
			return 0, false
		}
		if j+1 < len(cluster) {
			return 0, valueOK(cluster[j+1:])
		}
		if len(rest) == 0 {
			return 0, false
		}
		return 1, valueOK(rest[0])
	}
	return 0, true
}

// digQueryOptionSafe accepts a +option with no value or with a number
// (+short, +noall, +time=2). Any other value voids the override, because it
// can carry data or a name: +domain= sets a search domain that is appended to
// the query name, and +ednsopt=, +cookie= and +subnet= put bytes in the
// packet.
func digQueryOptionSafe(opt string) bool {
	name, value, hasValue := strings.Cut(opt, "=")
	return isOptionWord(name) && (!hasValue || isDigits(value))
}

// nslookupOptionSafe accepts -option and -option=value where the value is a
// lookup record type, a class or a number (-type=TXT, -q=txt, -port=53).
// -type=AXFR is a zone transfer, and -domain= and -srchlist= set search
// domains, so those void the override.
func nslookupOptionSafe(opt string) bool {
	name, value, hasValue := strings.Cut(opt, "=")
	if !isOptionWord(name) {
		return false
	}
	return !hasValue || isLookupRRType(value) || isDNSClass(value) || isDigits(value)
}

// isOptionWord reports whether s is a plain option name: letters, digits and
// hyphens, starting with a letter.
func isOptionWord(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// lookupRRTypes are the record types a lookup may ask for. AXFR and IXFR are
// left out on purpose: they are zone transfers, not lookups, and
// ne-block-dns-zone-transfer BLOCKs them.
var lookupRRTypes = map[string]bool{
	"A": true, "AAAA": true, "ANY": true, "CAA": true, "CDNSKEY": true,
	"CDS": true, "CERT": true, "CNAME": true, "DNAME": true, "DNSKEY": true,
	"DS": true, "HINFO": true, "HTTPS": true, "LOC": true, "MX": true,
	"NAPTR": true, "NS": true, "NSEC": true, "NSEC3": true,
	"NSEC3PARAM": true, "OPENPGPKEY": true, "PTR": true, "RRSIG": true,
	"SMIMEA": true, "SOA": true, "SPF": true, "SRV": true, "SSHFP": true,
	"SVCB": true, "TLSA": true, "TXT": true, "URI": true,
}

func isLookupRRType(s string) bool { return lookupRRTypes[strings.ToUpper(s)] }

func isDNSClass(s string) bool {
	switch strings.ToUpper(s) {
	case "IN", "CH", "CHAOS", "HS", "HESIOD":
		return true
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isIPLiteral reports whether s is an IPv4 or IPv6 address with no zone.
func isIPLiteral(s string) bool {
	ip, err := netip.ParseAddr(s)
	return err == nil && ip.Zone() == ""
}
