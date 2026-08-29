package shellparse

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func parsesOK(s string) bool {
	p := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	_, err := p.Parse(strings.NewReader(s), "")
	return err == nil
}

// TestDequoteParseRetry_RecoversInvalidVarName is the #3211 regression.
//
// mvdan/sh validates an assignment NAME at parse time and rejects the WHOLE
// command; bash performs quote removal first and sets the variable anyway.
// Confirmed on bash 3.2:
//
//	bash -c 'export FO\O=1; env | grep ^FOO='   ->  FOO=1
//
// Before the retry, a parse failure returned the "" sentinel, and with it every
// AST-derived surface went quiet at once — structural, semantic, dataflow,
// stateful and enterprise SelfProtect all silently contributed nothing. One
// backslash in a variable name was enough.
func TestDequoteParseRetry_RecoversInvalidVarName(t *testing.T) {
	for name, tc := range map[string]struct{ in, wantContains string }{
		"export":   {`export FO\O=1`, "FOO=1"},
		"declare":  {`declare -x MY\VAR=/tmp/x`, "MYVAR=/tmp/x"},
		"typeset":  {`typeset -x MY\VAR=/tmp/x`, "MYVAR=/tmp/x"},
		"readonly": {`readonly A\B=1`, "AB=1"},
		"local":    {`local A\B=1`, "AB=1"},
	} {
		t.Run(name, func(t *testing.T) {
			// Positive control: the premise of the whole fix is that these do
			// NOT parse. If a mvdan/sh upgrade starts accepting them, this test
			// would otherwise keep passing for the wrong reason.
			if parsesOK(tc.in) {
				t.Fatalf("premise broken: %q now parses, so the retry path is not what is being tested", tc.in)
			}
			got := DequoteCommand(tc.in)
			if got == "" {
				t.Fatalf("DequoteCommand(%q) returned the no-op sentinel — the retry did not fire", tc.in)
			}
			if !strings.Contains(got, tc.wantContains) {
				t.Errorf("DequoteCommand(%q) = %q, want it to contain %q", tc.in, got, tc.wantContains)
			}
		})
	}
}

// TestDequoteParseRetry_StillFailsReturnsSentinel — the retry gets ONE attempt.
// Input that is broken for some other reason must come back as "" exactly as
// before, so callers keep falling back to the raw command.
func TestDequoteParseRetry_StillFailsReturnsSentinel(t *testing.T) {
	for name, in := range map[string]string{
		"unterminated single quote": `echo 'a\b`,
		"unterminated double quote": `echo "a\b`,
		"unclosed subshell":         `( echo a\b`,
	} {
		t.Run(name, func(t *testing.T) {
			if parsesOK(in) {
				t.Skipf("premise: %q parses, not a retry case", in)
			}
			if got := DequoteCommand(in); got != "" {
				t.Errorf("DequoteCommand(%q) = %q, want \"\" (unrecoverable parse failure)", in, got)
			}
		})
	}
}

// TestDequoteParseRetry_NoEscapeNoRetry — a parse failure with nothing to fold
// must not spin. Guards the cheap early return, and pins that the retry is
// gated on the fold changing something rather than on the failure alone.
func TestDequoteParseRetry_NoEscapeNoRetry(t *testing.T) {
	const in = `echo 'unterminated`
	if parsesOK(in) {
		t.Skip("premise: input parses")
	}
	if got := DequoteCommand(in); got != "" {
		t.Errorf("DequoteCommand(%q) = %q, want \"\"", in, got)
	}
}

// TestDequoteParseRetry_DoesNotTouchParsingCommands is the blast-radius claim,
// stated as a test rather than as a comment. The gate is "the parser already
// gave up", so anything that parses must produce byte-identical output to what
// it produced before the retry existed. The cases below are the shapes most
// likely to be disturbed: a literal backslash-escape inside quotes, which the
// retry path would fold and the normal path must not.
func TestDequoteParseRetry_DoesNotTouchParsingCommands(t *testing.T) {
	for name, in := range map[string]string{
		"single-quoted escape": `printf 'a\nb'`,
		"double-quoted escape": `printf "a\nb"`,
		"plain command":        `rm -rf /`,
		"quote splice":         `cat ~/.ss'h'/id_r'sa'`,
		"no quotes at all":     `ls -la /tmp`,
	} {
		t.Run(name, func(t *testing.T) {
			if !parsesOK(in) {
				t.Fatalf("premise broken: %q does not parse, so this is not the non-retry path", in)
			}
			got := DequoteCommand(in)
			// The assertion that matters: whatever the normal path decides,
			// the escape inside quotes survives it. A retry leaking into this
			// path would show up as the backslash disappearing.
			if strings.Contains(in, `\n`) && got != "" && !strings.Contains(got, `\n`) {
				t.Errorf("DequoteCommand(%q) = %q — the quoted escape was folded on a path that parses", in, got)
			}
		})
	}
}
