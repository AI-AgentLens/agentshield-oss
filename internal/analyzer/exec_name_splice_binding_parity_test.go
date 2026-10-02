package analyzer_test

import "testing"

// TestExecNameSpliceBindingParity covers #3848 class A end to end: a builtin
// that binds a variable from stdin or the positional list (read, mapfile,
// readarray, set --) or invalidates one (shift) is the same builtin when its
// NAME carries a no-op backslash or empty quotes, so the spliced spelling must
// decide exactly as the plain one does.
//
// Every row asserts its CONTROL first. Without that a row whose plain spelling
// stopped BLOCKing for an unrelated reason would pass on "spliced == control"
// while measuring nothing.
//
// These are deliberately NOT corpus cases. A BLOCK case in testdata joins
// blockingBaseline, and the read family already leaks under the exec-wrapper
// sweeps (`sudo read …` — a separate, pre-existing gap), so each one added
// here as a TP pushed TestWrapperPositionalParity / TestExecWrapperParity /
// the shell-source-carrier sweep over budget by one. Raising three budgets to
// land a fix for a fourth is how a sweep stops measuring anything.
//
// TestEscapeSpliceParity/exec-backslash generates the single-line shapes from
// the corpus too, but only as a budgeted aggregate, and its field-joining
// mutation flattens newlines — so the heredoc row below is the only place that
// spelling is measured with its newlines intact.
func TestExecNameSpliceBindingParity(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := func(c string) string { return string(engine.Evaluate(c, nil).Decision) }

	rows := []struct {
		name    string
		control string
		spliced []string
		want    string
	}{
		{
			name:    "read scalar from a here-string",
			control: `read zc <<< "rm -rf /"; $zc`,
			spliced: []string{`r\ead zc <<< "rm -rf /"; $zc`, `re""ad zc <<< "rm -rf /"; $zc`, `'read' zc <<< "rm -rf /"; $zc`},
			want:    "BLOCK",
		},
		{
			name:    "read array from a here-string",
			control: `read -ra parts <<< "rm -rf /"; "${parts[@]}"`,
			spliced: []string{`r\ead -ra parts <<< "rm -rf /"; "${parts[@]}"`, `re""ad -ra parts <<< "rm -rf /"; "${parts[@]}"`},
			want:    "BLOCK",
		},
		{
			name:    "read scalar from a quoted heredoc, newlines intact",
			control: "read zc <<'EOF'\nrm -rf /\nEOF\n$zc",
			spliced: []string{"r\\ead zc <<'EOF'\nrm -rf /\nEOF\n$zc"},
			want:    "BLOCK",
		},
		{
			name:    "mapfile",
			control: `mapfile -t za <<< "rm -rf /"; ${za[0]}`,
			spliced: []string{`m\apfile -t za <<< "rm -rf /"; ${za[0]}`},
			want:    "BLOCK",
		},
		{
			name:    "readarray",
			control: `readarray za <<< "rm -rf /"; ${za[0]}`,
			spliced: []string{`r\eadarray za <<< "rm -rf /"; ${za[0]}`},
			want:    "BLOCK",
		},
		{
			name:    "set -- positional binding",
			control: `set -- rm -rf /; "$@"`,
			spliced: []string{`s\et -- rm -rf /; "$@"`},
			want:    "BLOCK",
		},
		{
			// The false-BLOCK direction of the same defect. bash runs the
			// spliced shift, "$@" is empty, nothing destructive executes. While
			// `s\hift` went unrecognised the positional binding stayed live
			// and this BLOCKed on words that had already been shifted away.
			name:    "shift empties the positional list",
			control: `set -- rm -rf /; shift 3; "$@"`,
			spliced: []string{`set -- rm -rf /; s\hift 3; "$@"`},
			want:    "AUDIT",
		},
		{
			// The unset-parameter fold asks "is x assigned anywhere?". A spliced
			// read still binds x, so `r${x}m` is `rzm`, not `rm`. While the
			// assignment scan compared the raw name it missed the binding,
			// folded the splice away and BLOCKed a command that runs `rzm`.
			name:    "a spliced read still counts as an assignment",
			control: `read x <<< "z"; r${x}m -rf /`,
			spliced: []string{`r\ead x <<< "z"; r${x}m -rf /`, `re""ad x <<< "z"; r${x}m -rf /`},
			want:    "AUDIT",
		},
		{
			name:    "benign value stays benign",
			control: `read zc <<< "ls -la /tmp"; $zc`,
			spliced: []string{`r\ead zc <<< "ls -la /tmp"; $zc`},
			want:    "AUDIT",
		},
	}

	// The other direction, which the first cut of this fix had no row for and
	// got wrong: a spelling bash does NOT resolve to the builtin must not be
	// treated as one. Each of these is "command not found" in bash (verified on
	// 5.3 with a harmless stand-in), so the not-a-shift word is a no-op and the
	// command must decide exactly as it does without it.
	notBuiltin := []struct {
		name    string
		control string
		cmds    []string
		want    string
	}{
		{
			name:    "a quoted or escaped backslash is not shift — the BLOCK must survive",
			control: `set -- rm -rf /; "$@"`,
			cmds: []string{
				`set -- rm -rf /; 's\hift' 3; "$@"`,
				`set -- rm -rf /; "s\hift" 3; "$@"`,
				`set -- rm -rf /; \\shift 3; "$@"`,
				`set -- rm -rf /; shift\\ 3; "$@"`,
				`set -- rm -rf /; SHIFT 3; "$@"`,
			},
			want: "BLOCK",
		},
		{
			// The assignment scan in unset_paramexp.go is the OTHER site where a
			// match removes a BLOCK: a name it takes for read/mapfile suppresses
			// the unset-parameter fold. A spelling bash does not run as read
			// must leave the fold — and the BLOCK — in place. The review of
			// #3875 found this site had no must-not row: restoring the loose
			// comparison there, or accepting READ, survived the whole suite.
			name:    "a quoted backslash or wrong case is not read — the unset-param fold must survive",
			control: `true </dev/null; r${zqx}m -rf /`,
			cmds: []string{
				`'r\ead' zqx </dev/null; r${zqx}m -rf /`,
				`"r\ead" zqx </dev/null; r${zqx}m -rf /`,
				`\\read zqx </dev/null; r${zqx}m -rf /`,
				`READ zqx </dev/null; r${zqx}m -rf /`,
				`'m\apfile' zqx </dev/null; r${zqx}m -rf /`,
			},
			want: "BLOCK",
		},
		{
			name:    "a quoted backslash is not read or set — nothing is bound, nothing to BLOCK",
			control: `nosuchcmd zc <<< "rm -rf /"; $zc`,
			cmds: []string{
				`'\read' zc <<< "rm -rf /"; $zc`,
				`'s\et' -- rm -rf /; "$@"`,
			},
			want: "AUDIT",
		},
	}
	for _, row := range notBuiltin {
		t.Run(row.name, func(t *testing.T) {
			if got := decide(row.control); got != row.want {
				t.Fatalf("CONTROL %q = %s, want %s — the row measures nothing until this holds", row.control, got, row.want)
			}
			for _, c := range row.cmds {
				if got := decide(c); got != row.want {
					t.Errorf("%q = %s, want %s (bash does not run a builtin here)", c, got, row.want)
				}
			}
		})
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := decide(row.control); got != row.want {
				t.Fatalf("CONTROL %q = %s, want %s — the row measures nothing until this holds", row.control, got, row.want)
			}
			for _, s := range row.spliced {
				if got := decide(s); got != row.want {
					t.Errorf("%q = %s, want %s (same as its control)", s, got, row.want)
				}
			}
		})
	}
}

// TestBindingInvalidatorsClosed is the regression test for the #3876 (a) and
// (b) tightenings, converted from the rows TestBindingInvalidatorsFailOpen_KnownGap
// used to pin at AUDIT. A builtin that merely NAMES a variable no longer
// switches the static model off when it cannot change the value bash sees:
//
//   - `read NAME` at EOF (`</dev/null`, an empty here-string, no stdin source)
//     leaves NAME empty, which expands exactly like unset, so the
//     unset-parameter fold now stays on for NAME;
//   - `shift 0`, a shift past the bound words, a shift inside a function body
//     and a shift after the last positional use move nothing, so positional
//     resolution now stays on.
//
// bash runs the payload in every row (verified on 5.3 with a harmless
// stand-in). Every row asserts its CONTROL first so a row whose plain
// spelling stopped BLOCKing for an unrelated reason cannot pass vacuously.
func TestBindingInvalidatorsClosed(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := func(c string) string { return string(engine.Evaluate(c, nil).Decision) }

	for _, row := range []struct{ control, closed string }{
		// (a) read at EOF keeps the unset-parameter fold
		{`true </dev/null; r${zqx}m -rf /`, `read zqx </dev/null; r${zqx}m -rf /`},
		{`true </dev/null; r${zqx}m -rf /`, `r\ead zqx </dev/null; r${zqx}m -rf /`},
		{`true </dev/null; r${zqx}m -rf /`, `read zqx <<< ""; r${zqx}m -rf /`},
		{`true </dev/null; r${zqx}m -rf /`, `read zqx; r${zqx}m -rf /`},
		{`true </dev/null; r${zqx}m -rf /`, `mapfile zqx </dev/null; r${zqx}m -rf /`},
		// (b) a shift that moves nothing keeps positional resolution
		{`set -- rm -rf /; "$@"`, `set -- rm -rf /; shift 0; "$@"`},
		{`set -- rm -rf /; "$@"`, `set -- rm -rf /; s\hift 0; "$@"`},
		{`set -- rm -rf /; "$@"`, `set -- rm -rf /; shift 99; "$@"`},
		{`set -- rm -rf /; "$@"`, `set -- rm -rf /; "$@"; shift`},
		{`f() { true; }; set -- rm -rf /; "$@"`, `f() { shift; }; set -- rm -rf /; "$@"`},
		{`set -- rm -rf /; f() { true; }; "$@"`, `set -- rm -rf /; f() { shift; }; "$@"`},
		{`set -- rm -rf /; f() { true; }; f; "$@"`, `set -- rm -rf /; f() { shift; }; f; "$@"`},
		// (a) set-but-empty operators: bash expands `${zq+rm}` and `${zq:-rm}`
		// to rm after a read at EOF (verified on 3.2 and 5.3).
		{`true </dev/null; ${zq:-rm} -rf /`, `read zq </dev/null; ${zq+rm} -rf /`},
		{`true </dev/null; ${zq:-rm} -rf /`, `read zq </dev/null; ${zq:-rm} -rf /`},
	} {
		if got := decide(row.control); got != "BLOCK" {
			t.Fatalf("CONTROL %q = %s, want BLOCK — the row measures nothing until this holds", row.control, got)
		}
		if got := decide(row.closed); got != "BLOCK" {
			t.Errorf("%q = %s, want BLOCK (same as its control; #3876 closed this shape)", row.closed, got)
		}
	}

	// FP boundary of (a): a read at EOF leaves zq SET but empty, so `${zq-rm}`
	// and `${zq=rm}` expand to "" and `${zq:+rm}` to "" — bash runs `-rf /`,
	// not `rm -rf /`. Modelling the name as unset folded these to `rm -rf /`
	// and BLOCKed a command bash never runs (Codex review of #3962). The
	// control shows the same text BLOCKs when zq really is unset.
	for _, row := range []struct{ control, benign string }{
		{`${zq-rm} -rf /`, `read zq </dev/null; ${zq-rm} -rf /`},
		{`${zq-rm} -rf /`, `read zq </dev/null; ${zq=rm} -rf /`},
		{`${zq-rm} -rf /`, `read zq </dev/null; ${zq:+rm} -rf /`},
	} {
		if got := decide(row.control); got != "BLOCK" {
			t.Fatalf("CONTROL %q = %s, want BLOCK — the row measures nothing until this holds", row.control, got)
		}
		if got := decide(row.benign); got == "BLOCK" {
			t.Errorf("%q = BLOCK, want not BLOCK: bash expands the parameter to \"\" (set but empty) and never runs rm", row.benign)
		}
	}
}

// TestBindingInvalidatorsFailOpen_KnownGap pins the gaps #3876 deliberately
// RETAINS; it does not endorse them:
//
//   - a `read` from a plausible non-empty source (a file, a non-literal
//     here-string, a heredoc, a pipe, `-u N`) may bind NAME to anything, so
//     the unset-parameter fold is still switched off for NAME. bash reads the
//     file's first line, and the corpus has no benign command whose
//     read-bound name splits a word run, so this stays open until a value
//     model for the source exists;
//   - a `shift` that really moves the words is not modelled: the table cannot
//     renumber, so positional resolution still bails. bash runs the payload
//     in the row below (`set -- x rm -rf /; shift; "$@"` executes `rm -rf /`).
//
// Residual shapes (Codex review of #3962; 0 corpus flips over 6,785 rows,
// accepted as documented gaps), one representative of each direction pinned:
//
//   - bypass direction, still bails conservatively: `( shift )` (a subshell
//     shifts its own copy; the walk sees a top-level shift), `shift nope`,
//     `shift "$1"`, `shift $#`, `false && shift`, `read zq <<< "$(true)"`,
//     `read -u99 zq </dev/null`;
//   - FP direction, bash binds non-empty but the fold or resolution is
//     retained: `IFS= read zq <<<"  "` (whitespace survives with IFS empty),
//     `{ read zq; } </etc/hosts` (redirect on the block, not the call),
//     `exec 3</etc/hosts; read -ru3 zq` (`-u` inside a flag cluster),
//     `mapfile zq <<<""` (one newline element), `builtin shift` /
//     `command shift` (pre-existing: not recognised as a shift at all, so
//     the words resolve unshifted).
//
// Each row is asserted at its CURRENT decision so that closing it has to be
// deliberate, and so that a change which silently makes it worse (AUDIT ->
// ALLOW) fails. Same pattern as TN-SSHKEY-VARSHELL-002. The control is the
// same payload with the invalidator removed, proving the payload BLOCKs when
// the model is on.
func TestBindingInvalidatorsFailOpen_KnownGap(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := func(c string) string { return string(engine.Evaluate(c, nil).Decision) }

	for _, row := range []struct{ control, gap, why string }{
		{`true </etc/hostname; r${zqx}m -rf /`, `read zqx </etc/hostname; r${zqx}m -rf /`, "read from a plausible source disables the fold"},
		{`true </etc/hostname; r${zqx}m -rf /`, `read zqx <<< "$x"; r${zqx}m -rf /`, "read from a non-literal here-string disables the fold"},
		{`set -- rm -rf /; "$@"`, `set -- x rm -rf /; shift; "$@"`, "a shift that moves the words is not modelled"},
		{`set -- rm -rf /; "$@"`, `set -- x rm -rf /; shift 1; "$@"`, "a shift that moves the words is not modelled"},
		{`set -- rm -rf /; "$@"`, `set -- rm -rf /; shift $n; "$@"`, "a non-literal shift count is not modelled"},
		{`set -- rm -rf /; "$@"`, `set -- rm -rf /; ( shift ); "$@"`, "residual bypass: a subshell shift moves nothing outside, the walk still bails"},
	} {
		if got := decide(row.control); got != "BLOCK" {
			t.Fatalf("CONTROL %q = %s, want BLOCK — the row measures nothing until this holds", row.control, got)
		}
		if got := decide(row.gap); got != "AUDIT" {
			t.Errorf("%q = %s, want AUDIT (retained #3876 gap: %s). BLOCK means the gap closed — update this test and #3876 deliberately; ALLOW means it got worse.", row.gap, got, row.why)
		}
	}

	// FP-direction residual, pinned at its CURRENT (false) BLOCK: with IFS
	// empty a whitespace-only here-string binds zq="  " (verified on 5.3), so
	// bash runs the unknown command `r  m`, yet the fold treats the read as
	// EOF and folds `r${zq}m` to rm. The control is the command bash actually
	// runs. Closing this needs an IFS-aware here-string model; until then a
	// silent flip to AUDIT here should be a deliberate change, not drift.
	const fpControl, fpGap = `true; r  m -rf /`, `IFS= read zq <<<"  "; r${zq}m -rf /`
	if got := decide(fpControl); got == "BLOCK" {
		t.Fatalf("CONTROL %q = BLOCK — the FP row measures nothing until bash's real command is not a BLOCK", fpControl)
	}
	if got := decide(fpGap); got != "BLOCK" {
		t.Errorf("%q = %s, want BLOCK (retained #3876 FP-direction residual: IFS= keeps the whitespace). AUDIT/ALLOW means the residual closed — update this test and #3876 deliberately.", fpGap, got)
	}
}
