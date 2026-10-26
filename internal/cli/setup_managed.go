package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/hookentry"
)

// Claude Code managed settings (#4292).
//
// A repository's committed .claude/settings.json with "disableAllHooks": true
// turns off every user-, project- and local-scope hook, including the one
// `agentshield setup claude-code` writes to ~/.claude/settings.json. A hook in
// Claude Code's managed settings survives it: measured for a SessionStart hook
// on Claude Code 2.1.296 (2026-10-12); for PreToolUse, the event AgentShield
// uses, documented but not measured. Two ways to put it there (Gary,
// 2026-10-19):
//
//   - --managed prints the managed-settings JSON and the per-OS file path,
//     for an MDM (Jamf, Intune) to deploy. It writes nothing.
//   - --write-managed merges the hook into this machine's managed settings
//     file. It needs administrator rights and never acquires them itself.
//
// Both build the entry with mergeClaudeCodeHook, the function the user-scope
// install uses, so the managed entry is the user-scope entry. The user-scope
// registration stays, as defence in depth.

// managedSettingsPaths lists the documented file locations for the --managed
// output, in a fixed order. The values come from hookentry.ManagedSettingsPath,
// which cites the Claude Code page they are from.
var managedSettingsPaths = []struct{ label, goos string }{
	{"macOS", "darwin"},
	{"Linux and WSL", "linux"},
	{"Windows", "windows"},
}

// managedSettingsSnippet is the managed-settings JSON that registers
// AgentShield's hook: the result of merging the hook into an empty document.
func managedSettingsSnippet(binPath string, execOK bool) ([]byte, claudeHookInstall, error) {
	doc := map[string]interface{}{}
	res := mergeClaudeCodeHook(doc, binPath, execOK)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, res, fmt.Errorf("failed to marshal the managed settings snippet: %w", err)
	}
	return append(out, '\n'), res, nil
}

// printManagedClaudeSnippet is `agentshield setup claude-code --managed`. The
// JSON goes to stdout alone, so `... --managed > agentshield.json` is a file an
// MDM can deploy; the guidance goes to stderr. It writes no file.
func printManagedClaudeSnippet(stdout, stderr io.Writer, binPath, blocker, thisOSPath string) error {
	snippet, res, err := managedSettingsSnippet(binPath, blocker == "")
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stderr, "AgentShield's Claude Code hook, for managed settings (#4292)")
	_, _ = fmt.Fprintln(stderr)
	_, _ = fmt.Fprintln(stderr, "Claude Code documents that a hook in managed settings keeps running when a repository's")
	_, _ = fmt.Fprintln(stderr, "committed .claude/settings.json sets \"disableAllHooks\": true, and a user-scope hook does not")
	_, _ = fmt.Fprintln(stderr, "(measured for a SessionStart hook on Claude Code 2.1.296; not yet for PreToolUse).")
	_, _ = fmt.Fprintln(stderr)
	_, _ = fmt.Fprintln(stderr, "Managed settings file (https://code.claude.com/docs/en/managed-settings):")
	for _, p := range managedSettingsPaths {
		_, _ = fmt.Fprintf(stderr, "  %-14s %s\n", p.label+":", hookentry.ManagedSettingsPath(p.goos))
	}
	_, _ = fmt.Fprintf(stderr, "  This machine:  %s\n", thisOSPath)
	_, _ = fmt.Fprintln(stderr)
	if blocker != "" {
		_, _ = fmt.Fprintf(stderr, "⚠  %s\n\n", blocker)
	}
	_, _ = fmt.Fprintf(stderr, "The snippet on stdout registers the hook in %s, the entry `agentshield setup claude-code`\n", res.Form)
	_, _ = fmt.Fprintln(stderr, "writes at user scope. To deploy it:")
	_, _ = fmt.Fprintln(stderr, "  - Merge it into the managed settings you already deploy. Keep your other keys; if you")
	_, _ = fmt.Fprintln(stderr, "    deploy hooks.PreToolUse already, append this group to that list.")
	_, _ = fmt.Fprintln(stderr, "  - The command path is this machine's agentshield. It must be the agentshield path")
	_, _ = fmt.Fprintf(stderr, "    on every machine you deploy to: %s\n", binPath)
	_, _ = fmt.Fprintln(stderr, "  - Claude Code uses one managed source: server-managed settings first, then an MDM")
	_, _ = fmt.Fprintln(stderr, "    profile or HKLM registry value, then this file. Put the hook in the source your")
	_, _ = fmt.Fprintln(stderr, "    machines use; /status in Claude Code names it on its Setting sources line.")
	_, _ = fmt.Fprintln(stderr, "  - Do not set disableAllHooks in managed settings: it turns off managed hooks too.")
	_, _ = fmt.Fprintln(stderr)
	_, _ = fmt.Fprintln(stderr, "To write this machine's file instead, as an administrator:")
	_, _ = fmt.Fprintln(stderr, "  "+elevatedWriteManagedCommand())
	_, _ = fmt.Fprintln(stderr)
	_, err = stdout.Write(snippet)
	return err
}

// elevatedWriteManagedCommand is the command to re-run --write-managed with
// administrator rights. AgentShield prints it and never runs it.
func elevatedWriteManagedCommand() string {
	if runtime.GOOS == "windows" {
		return "agentshield setup claude-code --write-managed   (from an Administrator prompt)"
	}
	return "sudo agentshield setup claude-code --write-managed"
}

// errNeedsElevation wraps a permission failure on the managed settings file
// in the message that tells the user what to do.
func errNeedsElevation(path string, err error) error {
	return fmt.Errorf("cannot write Claude Code managed settings %s: %w\n"+
		"   Managed settings live in a system directory. Re-run with administrator rights:\n"+
		"     %s\n"+
		"   AgentShield does not elevate itself", path, err, elevatedWriteManagedCommand())
}

// managedWrite reports what writeManagedClaudeHook did.
type managedWrite struct {
	claudeHookInstall
	// Path is the file written: the managed settings path, or the file a
	// symlink there points to.
	Path string
	// Created is true when the file did not exist before.
	Created bool
	// Mode is the file's permission bits after the call.
	Mode fs.FileMode
	// DisablesAllHooks is true when the file sets "disableAllHooks": true,
	// which turns off managed hooks too, ours included.
	DisablesAllHooks bool
}

// writeManagedClaudeHook merges AgentShield's hook into the Claude Code
// managed settings file at path. Managed settings carry the organization's
// other policies, so it never clobbers them:
//
//   - A missing or empty file becomes the snippet.
//   - Every key outside hooks.PreToolUse is kept; so is every other hook
//     group and hook object, and every key of a hook object it migrates.
//   - A file that already holds our entry is left byte-for-byte unchanged, so
//     running it twice gives one entry.
//   - A file that is not a JSON object, or whose hooks or hooks.PreToolUse
//     has the wrong type, is refused and left as it is.
//   - The write is atomic (temp file in the same directory, then rename), so
//     a crash cannot leave a half-written file, which would stop Claude Code
//     from starting. The file keeps its permission bits; a new file is 0644,
//     since Claude Code reads it as the user.
//
// A permission failure returns errNeedsElevation; nothing is retried or
// elevated.
func writeManagedClaudeHook(path, binPath string, execOK bool) (managedWrite, error) {
	res := managedWrite{Path: path}
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return res, fmt.Errorf("cannot resolve symlink %s: %w", path, err)
		}
		res.Path = target
	}

	data, err := os.ReadFile(res.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		res.Created = true
	case errors.Is(err, fs.ErrPermission):
		return res, errNeedsElevation(res.Path, err)
	case err != nil:
		return res, fmt.Errorf("cannot read Claude Code managed settings %s: %w", res.Path, err)
	}
	settings, err := parseManagedSettings(res.Path, data)
	if err != nil {
		return res, err
	}

	res.claudeHookInstall = mergeClaudeCodeHook(settings, binPath, execOK)
	res.DisablesAllHooks = settings["disableAllHooks"] == true
	if !res.changed() {
		if fi, err := os.Stat(res.Path); err == nil {
			res.Mode = fi.Mode().Perm()
		}
		return res, nil
	}

	mode := fs.FileMode(0o644)
	if fi, err := os.Stat(res.Path); err == nil {
		mode = fi.Mode().Perm()
	}
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return res, fmt.Errorf("failed to marshal managed settings: %w", err)
	}
	if err := writeFileAtomic(res.Path, append(out, '\n'), mode); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return res, errNeedsElevation(res.Path, err)
		}
		return res, fmt.Errorf("cannot write Claude Code managed settings %s: %w", res.Path, err)
	}
	res.Mode = mode
	return res, nil
}

// parseManagedSettings parses a managed settings document for the merge. An
// empty file counts as {} (Claude Code reads it so). Anything that is not a
// JSON object, or whose hooks/hooks.PreToolUse the merge would have to
// replace, is refused: overwriting it would drop whatever the organization
// meant by it.
func parseManagedSettings(path string, data []byte) (map[string]interface{}, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]interface{}{}, nil
	}
	refuse := func(why string) error {
		return fmt.Errorf("refusing to change Claude Code managed settings %s: %s. The file was not modified; fix it, then re-run", path, why)
	}
	// UseNumber keeps every number as written: decoding into float64 would
	// rewrite an integer above 2^53 in an organization's key as a different
	// value.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc interface{}
	if err := dec.Decode(&doc); err != nil {
		return nil, refuse(fmt.Sprintf("it does not parse as JSON (%v), and Claude Code refuses to start while it is malformed", err))
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, refuse("it does not parse as JSON (data after the top-level value), and Claude Code refuses to start while it is malformed")
	}
	settings, ok := doc.(map[string]interface{})
	if !ok {
		return nil, refuse("its top level is not a JSON object")
	}
	if h, present := settings["hooks"]; present {
		hooks, ok := h.(map[string]interface{})
		if !ok {
			return nil, refuse(`"hooks" is not a JSON object`)
		}
		if p, present := hooks["PreToolUse"]; present {
			if _, ok := p.([]interface{}); !ok {
				return nil, refuse(`"hooks.PreToolUse" is not a JSON array`)
			}
		}
	}
	return settings, nil
}

// writeFileAtomic writes data to path through a temp file in the same
// directory and a rename, so a reader sees the old file or the new one, never
// a partial write. It creates the directory (0755) when it is missing.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".agentshield-managed-settings-*.json")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// runWriteManaged is `agentshield setup claude-code --write-managed`.
func runWriteManaged(stdout io.Writer, path, binPath, blocker string) error {
	res, err := writeManagedClaudeHook(path, binPath, blocker == "")
	if err != nil {
		return err
	}
	if res.Form == hookentry.Shell && blocker != "" {
		_, _ = fmt.Fprintf(stdout, "⚠  %s\n", blocker)
	}
	switch {
	case res.Added && res.Created:
		_, _ = fmt.Fprintf(stdout, "✅ Claude Code managed settings created with AgentShield's PreToolUse hook (%s): %s\n", res.Form, res.Path)
	case res.Added:
		_, _ = fmt.Fprintf(stdout, "✅ AgentShield's PreToolUse hook added to Claude Code managed settings (%s): %s\n", res.Form, res.Path)
		_, _ = fmt.Fprintln(stdout, "   Every other key and hook in the file was kept.")
	case len(res.Migrated) > 0:
		_, _ = fmt.Fprintf(stdout, "✅ AgentShield's hook in Claude Code managed settings migrated from shell form to exec form: %s\n", res.Path)
		for _, was := range res.Migrated {
			_, _ = fmt.Fprintf(stdout, "   was: %q\n", was)
		}
	default:
		_, _ = fmt.Fprintf(stdout, "✅ Claude Code managed settings already hold AgentShield's hook (%s): %s — not modified\n", res.Form, res.Path)
	}
	if res.Form == hookentry.Exec {
		_, _ = fmt.Fprintf(stdout, "   \"command\": %q, \"args\": [\"hook\"]\n", binPath)
	}
	if res.DisablesAllHooks {
		_, _ = fmt.Fprintln(stdout, "⚠  This file sets \"disableAllHooks\": true, which turns off managed hooks too: AgentShield's hook will not run until it is removed.")
	}
	if runtime.GOOS != "windows" && res.Mode != 0 && res.Mode&0o004 == 0 {
		_, _ = fmt.Fprintf(stdout, "⚠  %s is mode %#o: Claude Code running as a user who cannot read it starts without managed settings.\n", res.Path, res.Mode)
	}
	_, _ = fmt.Fprintln(stdout)
	_, _ = fmt.Fprintln(stdout, "Check it in Claude Code with /status: the Setting sources line should show")
	_, _ = fmt.Fprintln(stdout, "Enterprise managed settings (file). If it names another source (remote, plist, HKLM),")
	_, _ = fmt.Fprintln(stdout, "Claude Code is using that one and ignores this file; put the hook there instead")
	_, _ = fmt.Fprintln(stdout, "(`agentshield setup claude-code --managed` prints it).")
	_, _ = fmt.Fprintln(stdout)
	_, _ = fmt.Fprintln(stdout, "The user-scope hook stays as defence in depth. To install or migrate it, run this as")
	_, _ = fmt.Fprintln(stdout, "each user, without sudo: agentshield setup claude-code")
	return nil
}

// managedSetupPath is the managed settings file setup reads and writes. Tests
// point enterprise.ClaudeManagedSettingsPath at a temp file; the watchdog
// reads the same variable, so the two always agree.
func managedSetupPath() string {
	return enterprise.ClaudeManagedSettingsPath()
}
