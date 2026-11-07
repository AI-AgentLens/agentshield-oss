package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// A settings.json that starts with a UTF-8 BOM is a real state (Windows
// PowerShell 5.1 writes one, Claude Code reads it), and setup used to stop on
// it with "invalid character 'ï'" (#4741).
func TestInstallClaudeCodeHook_SettingsWithBOM_4741(t *testing.T) {
	doc := "{\r\n" +
		"  \"permissions\": {\"deny\": [\"WebFetch\"]},\r\n" +
		"  \"env\": {\"FOO\": \"bar\"},\r\n" +
		"  \"hooks\": {\"PreToolUse\": [{\"matcher\": \"Edit\", \"hooks\": [{\"type\": \"command\", \"command\": \"other-tool --check\"}]}]}\r\n" +
		"}\r\n"
	path := filepath.Join(t.TempDir(), ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append([]byte{}, utf8BOM...), doc...), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := installClaudeCodeHook(path, "/usr/local/bin/agentshield", true, onFailureOmit)
	if err != nil {
		t.Fatalf("setup must read a BOM settings file: %v", err)
	}
	if !res.Added {
		t.Fatalf("AgentShield entry not added: %+v", res)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(out, utf8BOM) {
		t.Fatal("the rewritten file must not carry a BOM")
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("rewritten file is not JSON: %v", err)
	}
	if _, ok := got["permissions"]; !ok {
		t.Error("permissions were lost")
	}
	if env, _ := got["env"].(map[string]interface{}); env["FOO"] != "bar" {
		t.Error("env was lost")
	}
	groups, _ := got["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
	if len(groups) != 2 {
		t.Fatalf("want the foreign group plus ours, got %d groups: %s", len(groups), out)
	}
	if !strings.Contains(string(out), "other-tool --check") {
		t.Error("the foreign hook was lost")
	}
}

func TestReadClaudeSettings_BOMVariants_4741(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("BOM only reads as an empty document", func(t *testing.T) {
		s, err := readClaudeSettings(write("bomonly.json", utf8BOM))
		if err != nil || len(s) != 0 {
			t.Fatalf("got %v, %v", s, err)
		}
	})
	t.Run("a file without a BOM is read as before", func(t *testing.T) {
		s, err := readClaudeSettings(write("plain.json", []byte(`{"a":1}`)))
		if err != nil || s["a"] == nil {
			t.Fatalf("got %v, %v", s, err)
		}
	})
	t.Run("invalid JSON after a BOM is still an error", func(t *testing.T) {
		if _, err := readClaudeSettings(write("bad.json", append(append([]byte{}, utf8BOM...), "{nope"...))); err == nil {
			t.Fatal("a broken file must still be refused, not overwritten")
		}
	})
	t.Run("a BOM in the middle is not stripped", func(t *testing.T) {
		if _, err := readClaudeSettings(write("mid.json", append([]byte(`{"a":1}`), utf8BOM...))); err == nil {
			t.Fatal("only a leading BOM is tolerated")
		}
	})
}
