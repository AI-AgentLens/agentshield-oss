// Package testhome points a test's home directory at a throwaway dir on every
// OS. It is imported only by _test.go files, so it never reaches a binary.
//
// The product finds the home only through os.UserHomeDir (internal/homedir).
// That reads HOME on macOS and Linux, but USERPROFILE on Windows. A test that
// isolates itself with t.Setenv("HOME", dir) therefore still reads and writes
// the real profile on Windows, and its expected paths point somewhere the
// product never looks (#5021: most of the 212 Windows failures in the first
// aial-04 run).
//
// Set and SetProcess set HOME everywhere and, on Windows only, the profile
// variables as well (USERPROFILE, APPDATA, LOCALAPPDATA), the same set the cli
// package's TestMain pins. Elsewhere they leave those variables alone: the
// PowerShell lane resolves $env:USERPROFILE from the process environment, and
// its tests expect it unset off Windows. So on macOS and Linux, Set is exactly
// t.Setenv("HOME", dir).
package testhome

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Set points the home at dir for the rest of tb, restoring it afterwards.
// It has t.Setenv's rules: it panics in a parallel test. An empty dir means
// "no home" on every OS.
func Set(tb testing.TB, dir string) {
	tb.Helper()
	tb.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		for k, v := range windowsVars(dir) {
			tb.Setenv(k, v)
		}
	}
}

// SetProcess is Set for a TestMain: it changes the process environment and
// never restores it.
func SetProcess(dir string) {
	_ = os.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		for k, v := range windowsVars(dir) {
			_ = os.Setenv(k, v)
		}
	}
}

// ChildEnv makes a child process's environment name the same home on Windows
// as it does elsewhere. Call it on a command's Env after building it.
//
// A test hands its child a home as "HOME=<dir>", or removes HOME to mean "no
// home". On Windows the child reads USERPROFILE instead, and inherits the
// parent's. So ChildEnv appends USERPROFILE, APPDATA and LOCALAPPDATA for the
// last HOME entry, or removes them when env has no HOME at all. os/exec keeps
// the last of duplicate keys, case-insensitively on Windows. A nil env (inherit
// the parent's) is returned unchanged, and so is any env off Windows.
func ChildEnv(env []string) []string { return childEnv(env, runtime.GOOS) }

func childEnv(env []string, goos string) []string {
	if env == nil || goos != "windows" {
		return env
	}
	home, found := "", false
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, "HOME") {
			home, found = v, true
		}
	}
	if found {
		out := append([]string(nil), env...)
		for k, v := range windowsVars(home) {
			out = append(out, k+"="+v)
		}
		return out
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, profile := windowsVars("x")[strings.ToUpper(k)]; profile {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// windowsVars are the Windows profile variables that hold the home. An empty
// dir empties them all, so os.UserHomeDir reports no home, as it does for an
// empty HOME elsewhere.
func windowsVars(dir string) map[string]string {
	if dir == "" {
		return map[string]string{"USERPROFILE": "", "APPDATA": "", "LOCALAPPDATA": ""}
	}
	return map[string]string{
		"USERPROFILE":  dir,
		"APPDATA":      filepath.Join(dir, "AppData", "Roaming"),
		"LOCALAPPDATA": filepath.Join(dir, "AppData", "Local"),
	}
}
