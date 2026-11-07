package shellparse

import (
	"errors"
	"strings"
	"testing"
)

// The chain bound (#4778). Texts are generated: a 1 MiB fixture would be
// noise in the repo.

// chain is n stages of `a` joined by op.
func chain(n int, op string) string { return strings.Repeat("a"+op, n-1) + "a" }

func TestChainOperators_Counts(t *testing.T) {
	for _, c := range []struct {
		text string
		want int
	}{
		{"", 0},
		{"a", 0},
		{"a|b", 1},
		{"a||b", 1},
		{"a|&b", 1},
		{"a&&b", 1},
		{"a & b", 0},           // a background job does not nest
		{"a &>f", 0},           // a redirect
		{"a|||b", 2},           // `||` then `|`
		{"a && b || c | d", 3}, // one each
		{"echo 'a|b' \"c&&d\"", 2},
		{chain(100, "|"), 99},
		{chain(100, "&&"), 99},
	} {
		if got := ChainOperators(c.text); got != c.want {
			t.Errorf("ChainOperators(%q) = %d, want %d", c.text, got, c.want)
		}
	}
}

// TestChainOperators_StopsJustPastTheBound: the count is only ever compared
// with the bound, so it stops once it passes it.
func TestChainOperators_StopsJustPastTheBound(t *testing.T) {
	if got := ChainOperators(chain(4*MaxChainOperators, "|")); got != MaxChainOperators+1 {
		t.Errorf("ChainOperators on 4x the bound = %d, want %d", got, MaxChainOperators+1)
	}
}

// TestCheckChainBound_Boundary: a text AT the bound is parsed, one operator
// more is not.
func TestCheckChainBound_Boundary(t *testing.T) {
	for _, op := range []string{"|", "|&", "||", "&&"} {
		at := chain(MaxChainOperators+1, op) // MaxChainOperators operators
		if e := CheckChainBound(at); e != nil {
			t.Errorf("%q: a text at the bound was refused: %v", op, e)
		}
		past := chain(MaxChainOperators+2, op)
		e := CheckChainBound(past)
		if e == nil {
			t.Fatalf("%q: a text one operator past the bound was not refused", op)
		}
		if e.Derived {
			t.Errorf("%q: the call's own text was reported as derived", op)
		}
	}
}

// TestGuardChainBound_OwnTextIsNotRead: past the bound the reading does not
// run at all.
func TestGuardChainBound_OwnTextIsNotRead(t *testing.T) {
	ran := false
	e := GuardChainBound(chain(MaxChainOperators+2, "|"), func() { ran = true })
	if e == nil || e.Derived {
		t.Fatalf("GuardChainBound = %v, want the call's own text refused", e)
	}
	if ran {
		t.Error("the reading ran on a text past the bound")
	}
}

// derivedPastTheBound is a short command whose nested shell text, once its
// variable is substituted, is past the bound: 40 copies of a 1000-operator
// chain read by `bash -c`, in under 3 KiB. On main a 10 000-operator X
// (20 KiB) overflowed the stack in buildExecSymbols at depth 1.
func derivedPastTheBound(perCopy int) string {
	return "X='" + chain(perCopy, "|") + "'; bash -c \"" + strings.Repeat("$X|", 39) + "$X\""
}

// TestParse_DerivedTextPastTheBoundPanicsWithTheBoundsError: the call's own
// text is under the bound, the nested text Parse derives from it is past it;
// the parse of that text panics with the bound's error, which GuardChainBound
// returns as Derived.
func TestParse_DerivedTextPastTheBoundPanicsWithTheBoundsError(t *testing.T) {
	cmd := derivedPastTheBound(MaxChainOperators/40 + 100)
	if n := ChainOperators(cmd); n > MaxChainOperators {
		t.Fatalf("control: the command itself has %d operators, past the bound", n)
	}
	var pc *ParsedCommand
	e := GuardChainBound(cmd, func() { pc = Parse(cmd, 2) })
	if e == nil {
		t.Fatalf("GuardChainBound returned nil; the derived text was parsed (segments: %d)", len(pc.Segments))
	}
	if !e.Derived {
		t.Errorf("the error says the call's own text: %v", e)
	}
}

// TestParse_DerivedTextUnderTheBoundIsParsed is the control: the same shape
// whose derived text stays under the bound parses as before.
func TestParse_DerivedTextUnderTheBoundIsParsed(t *testing.T) {
	cmd := derivedPastTheBound(10)
	var pc *ParsedCommand
	if e := GuardChainBound(cmd, func() { pc = Parse(cmd, 2) }); e != nil {
		t.Fatalf("a derived text of %d operators was refused: %v", 40*9+39, e)
	}
	if pc == nil || len(pc.Subcommands) == 0 {
		t.Fatalf("the nested text was not read: %+v", pc)
	}
}

// TestParse_FoldOutputPastTheBound: `eval $X$X…` is spliced unquoted by
// MaterializeAssignments, so the call's own (folded) text is past the bound
// at depth 0 although the command is not. On main this overflowed the stack
// in buildExecSymbols; the check after each fold stops it.
func TestParse_FoldOutputPastTheBound(t *testing.T) {
	cmd := "X='" + chain(MaxChainOperators/40+100, "|") + "'; eval " + strings.Repeat("$X", 40)
	if n := ChainOperators(cmd); n > MaxChainOperators {
		t.Fatalf("control: the command itself has %d operators, past the bound", n)
	}
	if e := GuardChainBound(cmd, func() { Parse(cmd, 2) }); e == nil || !e.Derived {
		t.Fatalf("GuardChainBound = %v, want a derived text past the bound", e)
	}
}

// TestParse_DecodedNestedTextPastTheBound: a nested shell's ANSI-C text holds
// no `|` byte (each is the escape \x7c), so the call passes the bound, but
// the text the nested reading parses is the decoded chain. No fold produces
// it, so only the check on entry to parseWithDepth sees it.
func TestParse_DecodedNestedTextPastTheBound(t *testing.T) {
	esc := string([]byte{'\\', 'x', '7', 'c'})
	cmd := "bash -c $'" + strings.Repeat("a"+esc, MaxChainOperators+100) + "a'"
	if n := ChainOperators(cmd); n != 0 {
		t.Fatalf("control: the command itself has %d operators", n)
	}
	if e := GuardChainBound(cmd, func() { Parse(cmd, 2) }); e == nil || !e.Derived {
		t.Fatalf("GuardChainBound = %v, want the decoded nested text past the bound", e)
	}
}

// TestParseBashFile_PastTheBound: the shared bash parse helper, which reads
// derived texts too (MaterializeAssignments' output in pipe_executor.go),
// refuses a text past the bound with the bound's panic.
func TestParseBashFile_PastTheBound(t *testing.T) {
	text := chain(MaxChainOperators+2, "|")
	if e := GuardChainBound("", func() { parseBashFile(text) }); e == nil {
		t.Fatal("parseBashFile parsed a text past the bound")
	}
	if e := GuardChainBound("", func() { parseBashFile(chain(10, "|")) }); e != nil {
		t.Fatalf("control: a short text was refused: %v", e)
	}
}

// TestZshReadingErased_PassesTheBoundOn: the zsh reading recovers its own
// panics as "no reading"; the bound's must reach the surface instead.
func TestZshReadingErased_PassesTheBoundOn(t *testing.T) {
	text := chain(MaxChainOperators+2, "|")
	if e := GuardChainBound("", func() { ZshReadingErased(text) }); e == nil {
		t.Fatal("ZshReadingErased swallowed the bound's panic")
	}
}

// TestGuardChainBound_OtherPanicsPropagate: the guard only answers its own
// panic; anything else is a bug it must not hide.
func TestGuardChainBound_OtherPanicsPropagate(t *testing.T) {
	boom := errors.New("boom")
	defer func() {
		if p := recover(); p != boom {
			t.Errorf("recovered %v, want the reading's own panic", p)
		}
	}()
	GuardChainBound("a|b", func() { panic(boom) })
	t.Error("GuardChainBound returned after the reading panicked")
}

// TestParseText_RefusesPastTheBound: the one parse helper refuses a text
// past the bound with the bound's panic and parses one at it.
func TestParseText_RefusesPastTheBound(t *testing.T) {
	if e := GuardChainBound("", func() { _, _ = ParseText(chain(MaxChainOperators+2, "|")) }); e == nil {
		t.Fatal("ParseText parsed a text past the bound")
	}
	parsed := false
	if e := GuardChainBound("", func() {
		f, err := ParseText(chain(MaxChainOperators+1, "|"))
		parsed = err == nil && f != nil
	}); e != nil || !parsed {
		t.Fatalf("ParseText did not parse a text at the bound: %v", e)
	}
}
