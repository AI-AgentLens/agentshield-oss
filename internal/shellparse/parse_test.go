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
	parsed := Parse("echo hello > /tmp/out.txt", 2)
	if parsed == nil {
		t.Fatal("expected parsed result")
	}
	if len(parsed.Redirects) == 0 {
		t.Fatal("expected redirects")
	}
	if parsed.Redirects[0].Path != "/tmp/out.txt" {
		t.Errorf("expected redirect path /tmp/out.txt, got %q", parsed.Redirects[0].Path)
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
