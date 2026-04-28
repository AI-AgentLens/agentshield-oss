package normalize

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

func TestClassifyArgs_Echo(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "echo",
		Args:       []string{"check", "~/.ssh/id_rsa", "for", "keys"},
		Flags:      map[string]string{},
	}
	roles := ClassifyArgs(seg)
	for i, role := range roles {
		if role != ArgRoleText {
			t.Errorf("echo arg[%d] %q: got %d, want ArgRoleText", i, seg.Args[i], role)
		}
	}
}

func TestClassifyArgs_Printf(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "printf",
		Args:       []string{"%s\\n", "~/.aws/credentials"},
		Flags:      map[string]string{},
	}
	roles := ClassifyArgs(seg)
	for i, role := range roles {
		if role != ArgRoleText {
			t.Errorf("printf arg[%d]: got %d, want ArgRoleText", i, role)
		}
	}
}

func TestClassifyArgs_Grep(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "grep",
		Args:       []string{"password", "/etc/shadow"},
		Flags:      map[string]string{"r": ""},
	}
	roles := ClassifyArgs(seg)
	if roles[0] != ArgRoleText {
		t.Errorf("grep arg[0] (pattern): got %d, want ArgRoleText", roles[0])
	}
	if roles[1] != ArgRoleUnknown {
		t.Errorf("grep arg[1] (path): got %d, want ArgRoleUnknown", roles[1])
	}
}

func TestClassifyArgs_Sed(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "sed",
		Args:       []string{"s/foo/bar/g", "/tmp/file.txt"},
		Flags:      map[string]string{"i": ""},
	}
	roles := ClassifyArgs(seg)
	if roles[0] != ArgRoleText {
		t.Errorf("sed arg[0] (expression): got %d, want ArgRoleText", roles[0])
	}
	if roles[1] != ArgRoleUnknown {
		t.Errorf("sed arg[1] (file): got %d, want ArgRoleUnknown", roles[1])
	}
}

func TestClassifyArgs_GitCommit(t *testing.T) {
	// git commit -m "msg" → the message is in Flags["m"], not in Args
	// But we verify the TextFlags are identified correctly
	seg := shellparse.CommandSegment{
		Executable: "git",
		SubCommand: "commit",
		Args:       []string{},
		Flags:      map[string]string{"m": "fix ~/.ssh/id_rsa detection"},
	}
	textFlags := ClassifyFlags(seg)
	if !textFlags["m"] {
		t.Error("git commit: flag 'm' should be classified as text")
	}
	if !textFlags["message"] {
		t.Error("git commit: flag 'message' should be classified as text")
	}
}

func TestClassifyArgs_GhIssueCreate(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "gh",
		SubCommand: "issue create",
		Args:       []string{},
		Flags:      map[string]string{"body": "See ~/.aws/credentials", "title": "FP fix"},
	}
	textFlags := ClassifyFlags(seg)
	if !textFlags["body"] {
		t.Error("gh issue create: flag 'body' should be classified as text")
	}
	if !textFlags["title"] {
		t.Error("gh issue create: flag 'title' should be classified as text")
	}
}

func TestClassifyArgs_GhPrCreate(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "gh",
		SubCommand: "pr create",
		Args:       []string{},
		Flags:      map[string]string{"body": "See ~/.ssh/id_rsa", "title": "Fix"},
	}
	textFlags := ClassifyFlags(seg)
	if !textFlags["body"] {
		t.Error("gh pr create: flag 'body' should be classified as text")
	}
}

func TestClassifyArgs_BashInlineCode(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "bash",
		Args:       []string{},
		Flags:      map[string]string{"c": "echo ~/.ssh/id_rsa"},
		IsShell:    true,
	}
	textFlags := ClassifyFlags(seg)
	if !textFlags["c"] {
		t.Error("bash: flag 'c' should be classified as text (inline code)")
	}
}

func TestClassifyArgs_PythonInlineCode(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "python3",
		Args:       []string{},
		Flags:      map[string]string{"c": "import os; print(os.path.expanduser('~/.ssh'))"},
	}
	textFlags := ClassifyFlags(seg)
	if !textFlags["c"] {
		t.Error("python3: flag 'c' should be classified as text (inline code)")
	}
}

func TestClassifyArgs_UnknownCommand(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "somecommand",
		Args:       []string{"~/.ssh/id_rsa", "/tmp/output"},
		Flags:      map[string]string{},
	}
	roles := ClassifyArgs(seg)
	for i, role := range roles {
		if role != ArgRoleUnknown {
			t.Errorf("unknown command arg[%d]: got %d, want ArgRoleUnknown (conservative)", i, role)
		}
	}
}

func TestClassifyFlags_UniversalTextFlags(t *testing.T) {
	// Even for unknown commands, universal text flags should be classified
	seg := shellparse.CommandSegment{
		Executable: "somecommand",
		Args:       []string{},
		Flags:      map[string]string{"message": "see ~/.ssh/id_rsa", "output": "/tmp/file"},
	}
	textFlags := ClassifyFlags(seg)
	if !textFlags["message"] {
		t.Error("universal flag 'message' should be classified as text for any command")
	}
	if !textFlags["body"] {
		t.Error("universal flag 'body' should be classified as text for any command")
	}
	if textFlags["output"] {
		t.Error("'output' should NOT be a universal text flag")
	}
}

func TestClassifyArgs_CatNoSpecialHandling(t *testing.T) {
	// cat is not in the registry — all args should be Unknown (conservative = path)
	seg := shellparse.CommandSegment{
		Executable: "cat",
		Args:       []string{"~/.ssh/id_rsa"},
		Flags:      map[string]string{},
	}
	roles := ClassifyArgs(seg)
	if roles[0] != ArgRoleUnknown {
		t.Errorf("cat arg[0]: got %d, want ArgRoleUnknown", roles[0])
	}
}

func TestClassifyArgs_RubyInlineCode(t *testing.T) {
	seg := shellparse.CommandSegment{
		Executable: "ruby",
		Args:       []string{},
		Flags:      map[string]string{"e": "puts File.read('~/.ssh/id_rsa')"},
	}
	textFlags := ClassifyFlags(seg)
	if !textFlags["e"] {
		t.Error("ruby: flag 'e' should be classified as text (inline code)")
	}
}
