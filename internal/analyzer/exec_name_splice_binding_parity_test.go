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

// TestBindingInvalidatorsFailOpen_KnownGap pins a gap, it does not endorse it
// (#3876). A builtin that merely NAMES a variable switches the static model
// off, whether or not it changes the value bash sees:
//
//   - read NAME at EOF leaves NAME empty, which expands exactly like unset, yet
//     the unset-parameter fold is suppressed for NAME;
//   - any shift — even `shift 0`, which shifts nothing — bails positional
//     resolution.
//
// bash runs the payload in every row (verified on 5.3 with a harmless
// stand-in). Both are deliberate fail-open choices that predate #3874, and at
// corpus scale each is a short general-purpose downgrade prefix. They are
// asserted here at their CURRENT decision so that closing #3876 has to flip
// these rows on purpose, and so that a change which silently makes them worse
// (AUDIT -> ALLOW) fails. Same pattern as TN-SSHKEY-VARSHELL-002.
func TestBindingInvalidatorsFailOpen_KnownGap(t *testing.T) {
	engine, _ := blockingBaseline(t)
	decide := func(c string) string { return string(engine.Evaluate(c, nil).Decision) }

	for _, row := range []struct{ control, gap string }{
		{`true </dev/null; r${zqx}m -rf /`, `read zqx </dev/null; r${zqx}m -rf /`},
		{`true </dev/null; r${zqx}m -rf /`, `r\ead zqx </dev/null; r${zqx}m -rf /`},
		{`set -- rm -rf /; "$@"`, `set -- rm -rf /; shift 0; "$@"`},
		{`set -- rm -rf /; "$@"`, `set -- rm -rf /; s\hift 0; "$@"`},
	} {
		if got := decide(row.control); got != "BLOCK" {
			t.Fatalf("CONTROL %q = %s, want BLOCK — the row measures nothing until this holds", row.control, got)
		}
		if got := decide(row.gap); got != "AUDIT" {
			t.Errorf("%q = %s, want AUDIT (the pinned #3876 gap). BLOCK means the gap closed — update this test and #3876 deliberately; ALLOW means it got worse.", row.gap, got)
		}
	}
}
