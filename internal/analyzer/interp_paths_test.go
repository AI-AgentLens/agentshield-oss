package analyzer

import (
	"slices"
	"testing"
)

// The three shapes measured exit-0 through the real hook on 2026-09-02 with
// protected_paths ["~/.ssh/**", "~/.agentshield/**"], plus the controls that
// pin the false-positive boundary.

func TestSubstitution_HomeVariableFoldsToTilde(t *testing.T) {
	got := runSubstitution(t, "P=$HOME/.ssh; cat $P/id_rsa")
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Fatalf("materialized = %v; want ~/.ssh/id_rsa — $HOME left unbound drops the whole word and the split-concat protection never applies", got)
	}
}

func TestSubstitution_InterpreterFileCall_ViaVariable(t *testing.T) {
	got := runSubstitution(t, `P=$HOME/.ssh; python3 -c "print(open('$P/id_rsa').read())"`)
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Fatalf("materialized = %v; want ~/.ssh/id_rsa extracted from the open() argument", got)
	}
}

func TestSubstitution_InterpreterFileCall_HomeInline(t *testing.T) {
	got := runSubstitution(t, `python3 -c "print(open('$HOME/.ssh/id_rsa').read())"`)
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Fatalf("materialized = %v; want ~/.ssh/id_rsa", got)
	}
}

func TestSubstitution_InterpreterFileCall_ConfigWriteViaVariable(t *testing.T) {
	got := runSubstitution(t, `CFG=$HOME/.agentshield; python3 -c "open('$CFG/policy.yaml','w').write('disable_rules: [x]')"`)
	if !slices.Contains(got, "~/.agentshield/policy.yaml") {
		t.Fatalf("materialized = %v; want ~/.agentshield/policy.yaml", got)
	}
	if slices.Contains(got, "w") {
		t.Errorf("mode string 'w' extracted as a path: %v", got)
	}
}

func TestSubstitution_InterpreterFileCall_PureLiteralWord(t *testing.T) {
	got := runSubstitution(t, `python3 -c "print(open('/Users/dev/.ssh/id_rsa').read())"`)
	if !slices.Contains(got, "/Users/dev/.ssh/id_rsa") {
		t.Fatalf("materialized = %v; want the literal open() argument even though the word needed no substitution", got)
	}
}

func TestSubstitution_InterpreterFileCall_OtherLanguages(t *testing.T) {
	cases := map[string]string{
		`perl -e 'open(F, ">", "/Users/dev/.agentshield/policy.yaml"); print F "x"'`:            "/Users/dev/.agentshield/policy.yaml",
		`node -e "require('fs').writeFileSync('/Users/dev/.agentshield/policy.yaml','x')"`:      "/Users/dev/.agentshield/policy.yaml",
		`ruby -e 'File.write("/Users/dev/.agentshield/managed.json", "{}")'`:                    "/Users/dev/.agentshield/managed.json",
		`php -r 'file_put_contents("/Users/dev/.agentshield/policy.yaml", "x");'`:               "/Users/dev/.agentshield/policy.yaml",
		`python3 -c "import shutil; shutil.copy('/tmp/p.yaml', '/Users/dev/.agentshield/policy.yaml')"`: "/Users/dev/.agentshield/policy.yaml",
	}
	for cmd, want := range cases {
		got := runSubstitution(t, cmd)
		if !slices.Contains(got, want) {
			t.Errorf("%s\n  materialized = %v; want %s", cmd, got, want)
		}
	}
}

// TestSubstitution_InterpreterFileCall_DocTextIsNotAPath pins the false-
// positive boundary: a path that is merely printed or mentioned is not a
// file access and must not become a protected-path hit — that is the exact
// class the community rules were narrowed for.
func TestSubstitution_InterpreterFileCall_DocTextIsNotAPath(t *testing.T) {
	cases := []string{
		`python3 -c "print('see ~/.ssh/id_rsa for the key')"`,
		`python3 -c "import sys; sys.stdout.write('~/.ssh/id_rsa\n')"`,
		`python3 -c "import subprocess; subprocess.Popen(['ls', '/Users/dev/.ssh'])"`,
		`node -e "console.log('/Users/dev/.ssh/id_rsa')"`,
		`python3 -c "print('~/.ssh/id_rsa is where keys live')"`,
	}
	for _, cmd := range cases {
		got := runSubstitution(t, cmd)
		for _, p := range got {
			if p == "~/.ssh/id_rsa" || p == "/Users/dev/.ssh/id_rsa" || p == "/Users/dev/.ssh" {
				t.Errorf("doc-text literal extracted as a file path (%q): %s", p, cmd)
			}
		}
	}
}

func TestExtractFileCallPaths_Unit(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`open('~/.ssh/id_rsa').read()`, []string{"~/.ssh/id_rsa"}},
		{`open("/etc/shadow", "r")`, []string{"/etc/shadow"}},
		{`open('policy.yaml','w')`, nil}, // relative without slash: the normalizer's job
		{`print('~/.ssh/id_rsa')`, nil},
		{`os.popen('cat /etc/passwd')`, nil}, // popen is not open
		{`Path('/Users/dev/.aws').joinpath('credentials')`, []string{"/Users/dev/.aws"}},
		{`fs.readFileSync('/Users/dev/.aws/credentials', 'utf8')`, []string{"/Users/dev/.aws/credentials"}},
		{`no call here ~/.ssh/id_rsa`, nil},
		{`open('~root')`, []string{"~root"}}, // tilde-user with no slash still counts as a path (pins the HasPrefix clause)
	}
	for _, tc := range cases {
		got := extractFileCallPaths(tc.in)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s → %v; want %v", tc.in, got, tc.want)
		}
	}
}
