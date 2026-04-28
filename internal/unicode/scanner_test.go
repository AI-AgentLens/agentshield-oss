package unicode

import (
	"testing"
)

func TestScan_CleanASCII(t *testing.T) {
	result := Scan("ls -la /tmp")
	if !result.Clean {
		t.Errorf("expected clean result for ASCII command, got threats: %v", result.Threats)
	}
	if result.Sanitized != "ls -la /tmp" {
		t.Errorf("expected sanitized = original, got %q", result.Sanitized)
	}
}

func TestScan_ZeroWidthSpace(t *testing.T) {
	// "ls\u200B -la" — zero-width space between ls and space
	input := "ls\u200B -la"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for zero-width space")
	}
	if len(result.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(result.Threats))
	}
	if result.Threats[0].Category != "zero-width" {
		t.Errorf("expected category 'zero-width', got %q", result.Threats[0].Category)
	}
	if result.Threats[0].Severity != "block" {
		t.Errorf("expected severity 'block', got %q", result.Threats[0].Severity)
	}
	if result.Sanitized != "ls -la" {
		t.Errorf("expected sanitized 'ls -la', got %q", result.Sanitized)
	}
}

func TestScan_ZeroWidthJoiner(t *testing.T) {
	input := "rm\u200D -rf /"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for zero-width joiner")
	}
	if result.Threats[0].Category != "zero-width" {
		t.Errorf("expected 'zero-width', got %q", result.Threats[0].Category)
	}
}

func TestScan_BOM(t *testing.T) {
	input := "\uFEFFecho hello"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for BOM")
	}
	if result.Threats[0].Category != "zero-width" {
		t.Errorf("expected 'zero-width', got %q", result.Threats[0].Category)
	}
	if result.Sanitized != "echo hello" {
		t.Errorf("expected sanitized without BOM, got %q", result.Sanitized)
	}
}

func TestScan_BidiOverride(t *testing.T) {
	// RTL override — makes displayed text differ from executed text
	input := "echo \u202Erm -rf /\u202C safe"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for bidi override")
	}

	foundBidi := false
	for _, threat := range result.Threats {
		if threat.Category == "bidi-override" {
			foundBidi = true
			if threat.Severity != "block" {
				t.Errorf("expected severity 'block' for bidi, got %q", threat.Severity)
			}
		}
	}
	if !foundBidi {
		t.Error("expected at least one bidi-override threat")
	}
}

func TestScan_CyrillicHomoglyph(t *testing.T) {
	// "cаt" where а is Cyrillic (U+0430), not Latin 'a'
	input := "c\u0430t secrets.txt"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for Cyrillic homoglyph")
	}
	if result.Threats[0].Category != "homoglyph-cyrillic" {
		t.Errorf("expected 'homoglyph-cyrillic', got %q", result.Threats[0].Category)
	}
	if result.Threats[0].Severity != "audit" {
		t.Errorf("expected severity 'audit' for homoglyph, got %q", result.Threats[0].Severity)
	}
}

func TestScan_CyrillicHomoglyphInURL(t *testing.T) {
	// IDN homograph: "gіthub.com" where і is Cyrillic (U+0456)
	input := "curl https://g\u0456thub.com/install.sh"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for IDN homograph")
	}
	foundHomoglyph := false
	for _, threat := range result.Threats {
		if threat.Category == "homoglyph-cyrillic" {
			foundHomoglyph = true
		}
	}
	if !foundHomoglyph {
		t.Error("expected homoglyph threat for Cyrillic і in URL")
	}
}

func TestScan_TagCharacters(t *testing.T) {
	// Tag characters used for hidden smuggling
	input := "echo \U000E0001hello\U000E007F"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for tag characters")
	}
	foundTag := false
	for _, threat := range result.Threats {
		if threat.Category == "tag-char" {
			foundTag = true
		}
	}
	if !foundTag {
		t.Error("expected tag-char threat")
	}
}

func TestScan_ControlCharacters(t *testing.T) {
	// Null byte injection
	input := "ls\x00 -la"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for control character")
	}
	if result.Threats[0].Category != "control-char" {
		t.Errorf("expected 'control-char', got %q", result.Threats[0].Category)
	}
}

func TestScan_AllowsTabAndNewline(t *testing.T) {
	input := "echo\thello\nworld"
	result := Scan(input)

	if !result.Clean {
		t.Errorf("tab and newline should be allowed, got threats: %v", result.Threats)
	}
}

func TestScan_MultipleThreats(t *testing.T) {
	// Combine zero-width + bidi + homoglyph
	input := "c\u0430t\u200B \u202Efile.txt"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected multiple threats")
	}
	if len(result.Threats) < 3 {
		t.Errorf("expected at least 3 threats, got %d: %v", len(result.Threats), result.Threats)
	}
}

func TestScan_GreekHomoglyph(t *testing.T) {
	// Greek omicron (ο, U+03BF) instead of Latin 'o'
	input := "ech\u03BF hello"
	result := Scan(input)

	if result.Clean {
		t.Fatal("expected threats for Greek homoglyph")
	}
	if result.Threats[0].Category != "homoglyph-greek" {
		t.Errorf("expected 'homoglyph-greek', got %q", result.Threats[0].Category)
	}
}

func TestScan_RawHexOutput(t *testing.T) {
	input := "ls\u200B"
	result := Scan(input)

	if result.RawHex == "" {
		t.Error("expected RawHex to contain hex dump of non-ASCII bytes")
	}
}
