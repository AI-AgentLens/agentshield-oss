package testdata

// ===========================================================================
// Kingdom 8 (*): Reconnaissance & Discovery
// ===========================================================================
//
// These tests validate detection of commands that enumerate systems,
// discover sensitive files, or gather information for lateral movement.
//
// Test count targets (medium priority = 5 per weakness):
//   - Category 8.1 Network Discovery: port-scan (10)

// NetworkScanningCases tests detection of network scanning/enumeration.
var NetworkScanningCases = []TestCase{

	// --- TRUE POSITIVES (basic nmap — AUDIT) ---

	{
		ID:               "TP-NETSCAN-001",
		Command:          `nmap -sV 192.168.1.0/24`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `Network service version scan of a subnet. nmap scans all
			hosts on the network and identifies running services. This
			is a classic reconnaissance technique. Should be audited
			to flag potential lateral movement preparation.`,
		Tags: []string{"canonical"},
	},
	{
		ID:               "TP-NETSCAN-002",
		Command:          `nmap -p 22,80,443 10.0.0.1`,
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `Basic nmap scan of specific ports on a single host.
			No aggressive flags; should be audited, not blocked.`,
		Tags: []string{"canonical"},
	},

	// --- TRUE POSITIVES (aggressive nmap — BLOCK) ---

	{
		ID:               "TP-NE-BLOCK-NMAP-AGG-001",
		Command:          `nmap -sS -A 192.168.1.0/24`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `nmap with -A (aggressive mode: OS detect, version detect,
			script scan, traceroute) targeting a subnet. Must be blocked.`,
		Tags: []string{"canonical", "aggressive"},
	},
	{
		ID:               "TP-NE-BLOCK-NMAP-AGG-002",
		Command:          `nmap -O --script vuln 10.0.0.1`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `nmap OS fingerprinting (-O) with NSE vulnerability scripts.
			Highly targeted attack reconnaissance. Must be blocked.`,
		Tags: []string{"canonical", "aggressive"},
	},

	// --- TRUE POSITIVES (aggressive scanners — BLOCK) ---

	{
		ID:               "TP-NE-BLOCK-PORT-SCANNER-001",
		Command:          `masscan --rate=10000 10.0.0.0/8 -p80,443`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `masscan high-speed scan of an entire RFC-1918 /8 block.
			Inherently aggressive; must always be blocked.`,
		Tags: []string{"canonical", "aggressive"},
	},
	{
		ID:               "TP-NE-BLOCK-PORT-SCANNER-002",
		Command:          `rustscan -a 192.168.1.0/24 -- -sV`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `rustscan with nmap passthrough (-sV). Bulk scanner;
			must be blocked regardless of flags.`,
		Tags: []string{"canonical", "aggressive"},
	},

	// --- TRUE NEGATIVES ---

	{
		ID:               "TN-NETSCAN-001",
		Command:          `ping -c 3 google.com`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Description: `Simple connectivity check via ping. This is a basic
			networking diagnostic tool used by every developer. Should
			not be flagged as port scanning.`,
		Tags: []string{"common-dev-operation"},
	},
	{
		ID:               "TN-NETSCAN-002",
		Command:          `curl -I https://api.example.com`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Description: `HTTP HEAD request to check API availability. This is a
			standard developer operation for testing endpoints.`,
		Tags: []string{"common-dev-operation"},
	},
	{
		ID:               "TN-NE-AUDIT-NMAP-001",
		Command:          `nmap localhost -p 8080`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `Basic nmap check of a single localhost port. No aggressive
			flags; should be audited only, not blocked.`,
		Tags: []string{"common-dev-operation"},
	},
	{
		ID:               "TN-NE-AUDIT-NMAP-002",
		Command:          `nmap -p 443 github.com`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `Single-host single-port nmap check against a public host.
			No aggressive flags; should be audited, not blocked.`,
		Tags: []string{"common-dev-operation"},
	},

	// --- KNOWN FALSE NEGATIVES (documented gaps) ---

	{
		ID:               "FN-NETSCAN-001",
		Command:          `for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i; done`,
		ExpectedDecision: "AUDIT",
		Classification:   "FN",
		TaxonomyRef:      "reconnaissance/network-discovery/port-scan",
		Analyzer:         "structural",
		Description: `KNOWN FALSE NEGATIVE. Ping sweep using a shell loop. This
			scans an entire subnet using only ping (no nmap needed).
			Current rules don't detect loop-based scanning. The structural
			analyzer should detect loop constructs with network commands.`,
		Tags: []string{"known-gap", "evasion"},
	},
}

// AllReconnaissanceCases returns all test cases for Kingdom 8.
func AllReconnaissanceCases() []TestCase {
	var all []TestCase
	all = append(all, NetworkScanningCases...)
	return all
}
