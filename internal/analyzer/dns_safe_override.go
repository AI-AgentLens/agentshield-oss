package analyzer

import "strings"

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
func safeDNSLookupOnly(parsed *ParsedCommand) bool {
	sawSafeLookup := false
	for _, seg := range allSegments(parsed) {
		switch seg.Executable {
		case "dig", "nslookup", "host":
			if !hasSafeDNSRecordArg(seg.Args) {
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
// security record. The prefix list is unchanged from the override's original
// inline form.
func hasSafeDNSRecordArg(args []string) bool {
	for _, arg := range args {
		lower := strings.ToLower(arg)
		if strings.HasPrefix(lower, "_dmarc.") ||
			strings.HasPrefix(lower, "_spf.") ||
			strings.HasPrefix(lower, "_dkim.") ||
			strings.HasPrefix(lower, "_domainkey.") ||
			strings.HasPrefix(lower, "_acme-challenge.") ||
			strings.HasPrefix(lower, "_mta-sts.") {
			return true
		}
	}
	return false
}
