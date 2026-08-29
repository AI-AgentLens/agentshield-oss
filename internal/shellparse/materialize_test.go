package shellparse

import "testing"

// TestMaterializeAssignments_SplitConcat is the core issue-#3249 shape: a
// split-concat path assignment must materialize to the real spelling a
// command_regex/structural rule is keyed on, the same way DequoteCommand
// collapses a quote-splice.
func TestMaterializeAssignments_SplitConcat(t *testing.T) {
	// The mvdan/sh printer re-renders top-level ";"-separated statements as
	// newline-separated ones (pre-existing behavior shared by every other
	// text-fold in this package — DequoteCommand, NormalizeUnsetParamExp,
	// ExpandBraces all print through the same syntax.Printer). Functionally
	// equivalent as a command_regex/AST subject; expectations below use "\n"
	// to match what the printer actually emits.
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"ssh-key-absolute",
			"P1=/root/.ssh; P2=id_rsa; cat /root/.ssh/$P2",
			"P1=/root/.ssh\nP2=id_rsa\ncat /root/.ssh/id_rsa",
		},
		{
			"ssh-key-both-halves",
			"p=id_rsa; cat /root/.ssh/$p",
			"p=id_rsa\ncat /root/.ssh/id_rsa",
		},
		{
			"rm-rf-sysdir",
			"ZB=etc;rm -rf /$ZB",
			"ZB=etc\nrm -rf /etc",
		},
		{
			// P2's own assignment RHS is intentionally left untouched (same
			// as TestMaterializeAssignments_PrefixAssignmentUntouched below)
			// — only the read site materializes. Internally the resolver
			// still chains through P1 to fully resolve P2's value for that
			// read, proving multi-hop resolution works even though nothing
			// downstream prints it back into the P2= line.
			"multi-hop-chain",
			"P1=/root/.ssh\nP2=$P1/id_rsa\ncat $P2",
			"P1=/root/.ssh\nP2=$P1/id_rsa\ncat /root/.ssh/id_rsa",
		},
		{
			"braced-form",
			"p=id_rsa; cat /root/.ssh/${p}",
			"p=id_rsa\ncat /root/.ssh/id_rsa",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MaterializeAssignments(tc.in)
			if got != tc.want {
				t.Errorf("MaterializeAssignments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMaterializeAssignments_ConstantParamOp closes the ${x/foo/bar}-style
// evasion of the plain $VAR fold — the value and the operator's operands are
// both compile-time constants, so the fold is exact (mirrors #3220's
// reasoning, reused via FoldConstantParamOp).
func TestMaterializeAssignments_ConstantParamOp(t *testing.T) {
	in := "p=idQrsa; cat /root/.ssh/${p/Q/_}"
	want := "p=idQrsa\ncat /root/.ssh/id_rsa"
	got := MaterializeAssignments(in)
	if got != want {
		t.Errorf("MaterializeAssignments(%q) = %q, want %q", in, got, want)
	}
}

// TestMaterializeAssignments_WellKnownVarLeadingSlash covers issue #3378: a
// ${VAR:0:1} substring read of PATH/HOME with no in-script assignment at all
// — a shape TestMaterializeAssignments_ConstantParamOp does not exercise,
// since that one requires the variable to be bound locally.
func TestMaterializeAssignments_WellKnownVarLeadingSlash(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"path-no-local-assignment",
			"cat ${PATH:0:1}etc${PATH:0:1}shadow",
			"cat /etc/shadow",
		},
		{
			"home-no-local-assignment",
			"cat ${HOME:0:1}etc${HOME:0:1}shadow",
			"cat /etc/shadow",
		},
		{
			// A local assignment must win over the well-known fallback —
			// PATH=xyz means ${PATH:0:1} is "x", not "/", proving the bound
			// symbol table is checked first.
			"local-assignment-overrides-wellknown",
			"PATH=xyz; cat ${PATH:0:1}etc${PATH:0:1}shadow",
			"PATH=xyz\ncat xetcxshadow",
		},
		{
			// Non-zero offset: PATH's second character is machine-specific
			// and not knowable statically — must not fold.
			"non-zero-offset-not-folded",
			"cat ${PATH:1:1}etc${PATH:1:1}shadow",
			"",
		},
		{
			// Length other than 1: everything past the first character of
			// PATH is unpredictable — must not fold.
			"length-other-than-one-not-folded",
			"cat ${PATH:0:2}etc${PATH:0:2}shadow",
			"",
		},
		{
			// USER is well-known-SET (unset_paramexp.go's wellKnownEnvVars)
			// but not well-known-ABSOLUTE-PATH — its first character is
			// unpredictable, so it must stay in the narrower set here and
			// not fold.
			"non-path-wellknown-var-not-folded",
			"cat ${USER:0:1}etc${USER:0:1}shadow",
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MaterializeAssignments(tc.in)
			if got != tc.want {
				t.Errorf("MaterializeAssignments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMaterializeAssignments_DeclClause covers export/declare/local —
// parsed as *syntax.DeclClause, a distinct node from *syntax.CallExpr,
// mirroring the same gap DequoteCommand and buildExecSymbols each closed for
// their own surface (#2984, #3248).
func TestMaterializeAssignments_DeclClause(t *testing.T) {
	in := "declare p=id_rsa; cat /root/.ssh/$p"
	want := "declare p=id_rsa\ncat /root/.ssh/id_rsa"
	got := MaterializeAssignments(in)
	if got != want {
		t.Errorf("MaterializeAssignments(%q) = %q, want %q", in, got, want)
	}
}

// TestMaterializeAssignments_RedirectAndTestClause mirrors #3325's coverage
// for DequoteCommand: a split-concat path doesn't have to appear as a
// command argument to be read — a redirect target or a `[[ ]]` test operand
// resolves the same path a real shell would open.
func TestMaterializeAssignments_RedirectAndTestClause(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"redirect-target",
			"p=id_rsa; cat < /root/.ssh/$p",
			"p=id_rsa\ncat </root/.ssh/id_rsa",
		},
		{
			"test-clause",
			"p=id_rsa; [[ -f /root/.ssh/$p ]] && cat /root/.ssh/$p",
			"p=id_rsa\n[[ -f /root/.ssh/id_rsa ]] && cat /root/.ssh/id_rsa",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MaterializeAssignments(tc.in)
			if got != tc.want {
				t.Errorf("MaterializeAssignments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMaterializeAssignments_NoOp checks the "" sentinel convention holds
// for commands with nothing to materialize: no '$' at all, no assignments,
// an unbound variable, and a dynamic (CmdSubst) RHS that can't be folded
// here — CmdSubst decoder-pipeline folding stays Layer 2.5's job.
func TestMaterializeAssignments_NoOp(t *testing.T) {
	cases := []string{
		"cat /root/.ssh/id_rsa",               // no '$' at all
		"cat $UNBOUND_VAR",                    // no assignment for the var
		"p=$(hostname); cat /root/.ssh/$p",    // dynamic RHS, not statically resolvable
		"echo hello world",                    // plain command, no assignments
		"p=id_rsa; echo just talking about p", // assignment exists but never read
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := MaterializeAssignments(in); got != "" {
				t.Errorf("MaterializeAssignments(%q) = %q, want \"\" (no-op)", in, got)
			}
		})
	}
}

// TestMaterializeAssignments_PrefixAssignmentUntouched confirms the
// assignment statement itself is never rewritten — only the AT-READ usage
// site is, mirroring DequoteCommand's separation between an Assign's own
// value and a later reference to it.
func TestMaterializeAssignments_PrefixAssignmentUntouched(t *testing.T) {
	in := "p=id_rsa; cat /root/.ssh/$p"
	got := MaterializeAssignments(in)
	want := "p=id_rsa\ncat /root/.ssh/id_rsa"
	if got != want {
		t.Errorf("MaterializeAssignments(%q) = %q, want %q", in, got, want)
	}
}

// TestMaterializeAssignments_ParseFailure returns "" rather than panicking
// on unparseable input.
func TestMaterializeAssignments_ParseFailure(t *testing.T) {
	in := "p=id_rsa; cat $p ((("
	if got := MaterializeAssignments(in); got != "" {
		t.Errorf("MaterializeAssignments(%q) = %q, want \"\" on parse failure", in, got)
	}
}

// TestMaterializeAssignmentsQuotePreservation is issue #3352: a value
// substituted into a word that was double-quoted (`"$zc"`) must stay ONE
// argv token in the reconstruction — real bash never word-splits a quoted
// expansion, no matter what it resolves to. Before this fix, the fold
// dropped the quoting and printed a bare multi-word Lit; a downstream
// re-parse then split it into extra argv tokens, and bash -c's own
// first-word-only payload rule truncated the effective command to a single
// word (e.g. "cat"), hiding the rest from every AST-based analyzer.
func TestMaterializeAssignmentsQuotePreservation(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"bash-c-quoted-multiword",
			`zc='cat /etc/shadow'; bash -c "$zc"`,
			`zc='cat /etc/shadow'` + "\n" + `bash -c 'cat /etc/shadow'`,
		},
		{
			"bash-c-quoted-multiword-with-unset-paramexp-payload",
			`zc='cat /${zqx}etc/shadow'; bash -c "$zc"`,
			`zc='cat /${zqx}etc/shadow'` + "\n" + `bash -c 'cat /${zqx}etc/shadow'`,
		},
		{
			"sh-c-quoted-multiword",
			`p='rm -rf /'; sh -c "$p"`,
			`p='rm -rf /'` + "\n" + `sh -c 'rm -rf /'`,
		},
		{
			"declclause-quoted-multiword",
			`p='a b'; export FOO="$p"`,
			`p='a b'` + "\n" + `export FOO='a b'`,
		},
		{
			"testclause-quoted-multiword",
			`p='a b'; [[ -n "$p" ]] && echo yes`,
			`p='a b'` + "\n" + `[[ -n 'a b' ]] && echo yes`,
		},
		{
			"embedded-single-quote-escaped",
			`p="it's a b"; bash -c "$p"`,
			`p="it's a b"` + "\n" + `bash -c 'it'\''s a b'`,
		},
		{
			// Contrast case: a BARE (unquoted) top-level expansion of a
			// multi-word value must NOT be re-quoted — bash itself word-splits
			// an unquoted expansion, so the flat unquoted reconstruction (which
			// a downstream re-parse re-tokenizes on whitespace) is the correct
			// emulation, not a bug. Guards against overcorrecting the #3352 fix
			// into the opposite mistake.
			"bare-unquoted-multiword-stays-unquoted",
			`zc='cat /etc/shadow'; bash -c $zc`,
			`zc='cat /etc/shadow'` + "\n" + `bash -c cat /etc/shadow`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MaterializeAssignments(tc.in)
			if got != tc.want {
				t.Errorf("MaterializeAssignments(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestInlineCodeFragments_QuotedCarrierPayloadNotTruncated is the
// integration-level assertion for #3352: bash -c's own payload-selection
// semantics (only the first word after -c is ever the executed script) make
// the quote-drop bug externally visible as a wrong extracted fragment, which
// is how the bug was originally found while root-causing #3321.
func TestInlineCodeFragments_QuotedCarrierPayloadNotTruncated(t *testing.T) {
	in := `zc='cat /${zqx}etc/shadow'; bash -c "$zc"`
	got := InlineCodeFragments(in)
	want := []string{"cat /${zqx}etc/shadow"}
	if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) {
		t.Errorf("InlineCodeFragments(%q) = %q, want %q", in, got, want)
	}
}
