package mcp

import (
	"regexp"
)

// FormulaInjectionSignal identifies a CSV/spreadsheet formula-injection
// payload in tool response text. Agents routinely export tool results to
// CSV/XLSX for downstream review or charting — a tool response carrying a
// line that starts with a formula prefix followed by a known dangerous
// function or DDE syntax becomes a code-execution gadget when the resulting
// file is opened in Excel, LibreOffice, or Google Sheets.
//
// The risk is well-known in security (OWASP "CSV Injection") but is
// under-defended at the LLM/MCP boundary: text scanners look for prompt
// injection markers, not formula prefixes. A tool returning a line such as
//
//   =cmd|'/c calc'!A1
//
// passes every text-scanner pattern. Yet an agent that pipes the text into
// a write_file call produces a document that owns whichever workstation
// opens it.
type FormulaInjectionSignal string

const (
	// SignalCSVFormulaInjection flags tool response text containing a CSV
	// formula injection payload: line-starting =cmd|, =DDE(, =HYPERLINK
	// concat-exfil shape, =WEBSERVICE(, =IMPORTXML(, =IMPORTDATA(,
	// =IMPORTHTML(, =IMPORTRANGE(, or =MSEXCEL| DDE-EXEC.
	SignalCSVFormulaInjection FormulaInjectionSignal = "csv_formula_injection"
)

// FormulaInjectionFinding records one detected formula-injection payload.
type FormulaInjectionFinding struct {
	Signal  FormulaInjectionSignal `json:"signal"`
	Detail  string                 `json:"detail"`
	Snippet string                 `json:"snippet,omitempty"`
}

// FormulaInjectionScanResult is the result of scanning tool response text.
type FormulaInjectionScanResult struct {
	Blocked  bool                      `json:"blocked"`
	Findings []FormulaInjectionFinding `json:"findings,omitempty"`
}

// ScanFormulaInjection inspects text content items for CSV formula injection
// shapes. Returns findings if any line begins with a formula prefix followed
// by a known-dangerous function or DDE invocation.
func ScanFormulaInjection(items []ContentItem) FormulaInjectionScanResult {
	var result FormulaInjectionScanResult
	for _, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		scanFormulaInjectionText(&result, item.Text)
	}
	result.Blocked = len(result.Findings) > 0
	return result
}

func scanFormulaInjectionText(result *FormulaInjectionScanResult, text string) {
	for _, p := range formulaInjectionPatterns {
		if loc := p.re.FindStringIndex(text); loc != nil {
			result.Findings = append(result.Findings, FormulaInjectionFinding{
				Signal:  SignalCSVFormulaInjection,
				Detail:  p.description,
				Snippet: safeSnippet(text, loc[0], 100),
			})
			return // one finding per response is sufficient
		}
	}
}

// formulaInjectionPattern pairs a regex with the description that ends up in
// the audit reason. Each pattern matches a formula prefix at the start of a
// CSV cell — anchored to start-of-string, newline, or a CSV separator (comma,
// semicolon, tab). This catches payloads in any column, not just the first,
// while avoiding mid-cell matches in code snippets that legitimately use
// formula characters inside identifiers or operators.
var formulaInjectionPatterns = []struct {
	re          *regexp.Regexp
	description string
}{
	// DDE invocation. The cmd-pipe form is the canonical Excel DDE payload
	// used in every public CSV-injection PoC.
	{regexp.MustCompile(`(?i)(?:\A|[\r\n,;\t])[ \t"]*[=+\-@][ \t]*cmd[ \t]*[|:]`),
		"CSV formula injection: cmd-pipe DDE payload at cell start (runs when opened in Excel)"},

	// Explicit =DDE invocation.
	{regexp.MustCompile(`(?i)(?:\A|[\r\n,;\t])[ \t"]*[=+\-@][ \t]*DDE[ \t]*\(`),
		"CSV formula injection: DDE(...) payload at cell start (runs when opened in Excel)"},

	// HYPERLINK exfil shape — only flag when the URL is concatenated with a
	// cell reference or other expression that is the typical exfil gadget.
	// Bare HYPERLINK("url","label") is legitimate.
	{regexp.MustCompile(`(?i)(?:\A|[\r\n,;\t])[ \t"]*[=+\-@][ \t]*HYPERLINK[ \t]*\([^)]*&[^)]*\)`),
		"CSV formula injection: HYPERLINK with concatenation — data exfil via clickable link in Excel"},

	// WEBSERVICE — fetches arbitrary URL on open. No legitimate use in
	// tool-generated content destined for CSV.
	{regexp.MustCompile(`(?i)(?:\A|[\r\n,;\t])[ \t"]*[=+\-@][ \t]*WEBSERVICE[ \t]*\(`),
		"CSV formula injection: WEBSERVICE(...) at cell start (fetches attacker URL when opened)"},

	// IMPORTXML / IMPORTDATA / IMPORTHTML / IMPORTRANGE — Google Sheets
	// import functions; first cell evaluation can exfiltrate adjacent cells.
	{regexp.MustCompile(`(?i)(?:\A|[\r\n,;\t])[ \t"]*[=+\-@][ \t]*IMPORT(?:XML|DATA|HTML|RANGE)[ \t]*\(`),
		"CSV formula injection: IMPORT* Sheets import at cell start (fetches/exfils to attacker URL on cell evaluation)"},

	// MSEXCEL EXEC shape — older DDE-equivalent vector.
	{regexp.MustCompile(`(?i)(?:\A|[\r\n,;\t])[ \t"]*[=+\-@][ \t]*MSEXCEL[ \t]*\|`),
		"CSV formula injection: MSEXCEL DDE-EXEC payload at cell start"},
}
