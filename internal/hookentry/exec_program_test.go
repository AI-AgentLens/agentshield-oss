package hookentry

import "testing"

// setup on Windows writes the exec-form command as the full path to
// agentshield.exe. Recognising it is what keeps setup idempotent and lets
// --disable remove it (#4717); a lookalike is still some other program.
func TestIsExecProgramOn_Windows(t *testing.T) {
	cases := []struct {
		cmd           string
		windows, unix bool
	}{
		{`C:\Users\u\AppData\Local\Programs\AgentShield\agentshield.exe`, true, false},
		{`C:/Users/u/AppData/Local/Programs/AgentShield/agentshield.exe`, true, false},
		{`C:\Tools\AGENTSHIELD.EXE`, true, false},
		{`agentshield.exe`, true, false},
		{`agentshield`, true, true},
		{`/usr/local/bin/agentshield`, true, true},
		{`C:\Tools\agentshield`, true, false},
		{`C:\Tools\agentshield-evil.exe`, false, false},
		{`C:\Tools\agentshield.exe.bat`, false, false},
		{`C:\Tools\agentshield.exe `, false, false},
		{`C:\Tools\`, false, false},
		{``, false, false},
	}
	for _, c := range cases {
		if got := isExecProgramOn("windows", c.cmd); got != c.windows {
			t.Errorf("windows %q: got %v, want %v", c.cmd, got, c.windows)
		}
		if got := isExecProgramOn("darwin", c.cmd); got != c.unix {
			t.Errorf("darwin %q: got %v, want %v", c.cmd, got, c.unix)
		}
	}
}

// The whole entry setup writes on Windows classifies as exec form, so
// SettingsHasPreToolUseHook (setup, status, the watchdog) sees it.
func TestClassify_WindowsExecEntry(t *testing.T) {
	if !isExecProgramOn("windows", `C:\x\agentshield.exe`) {
		t.Fatal("precondition: the windows path must be recognised")
	}
	entry := map[string]interface{}{
		"type":    "command",
		"command": `C:\x\agentshield.exe`,
		"args":    []interface{}{"hook"},
	}
	want := Exec
	if !isExecProgram(`C:\x\agentshield.exe`) {
		want = None // not windows: the path names no agentshield binary here
	}
	if got := Classify(entry); got != want {
		t.Fatalf("Classify = %v, want %v", got, want)
	}
}
