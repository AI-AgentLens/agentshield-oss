package testhome

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The contract the 95 call sites rely on: after Set, the product's view of the
// home (os.UserHomeDir) is dir on this OS. And off Windows, the profile
// variables are untouched.
func TestSetPointsUserHomeDirAtDir(t *testing.T) {
	dir := t.TempDir()
	before, hadBefore := os.LookupEnv("USERPROFILE")
	Set(t, dir)
	got, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir after Set: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(dir) {
		t.Fatalf("UserHomeDir = %q after Set(%q)", got, dir)
	}
	if runtime.GOOS != "windows" {
		after, hadAfter := os.LookupEnv("USERPROFILE")
		if after != before || hadAfter != hadBefore {
			t.Fatalf("USERPROFILE changed off Windows: %q (set=%v) -> %q (set=%v)", before, hadBefore, after, hadAfter)
		}
	}
}

func TestSetEmptyMeansNoHome(t *testing.T) {
	Set(t, "")
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		t.Fatalf("UserHomeDir = %q after Set(\"\"); want no home", h)
	}
}

func TestChildEnvMirrorsHomeOnWindowsOnly(t *testing.T) {
	get := func(env []string, key string) (string, bool) {
		v, found := "", false
		for _, kv := range env {
			if k, val, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, key) {
				v, found = val, true
			}
		}
		return v, found
	}
	parent := []string{"PATH=x", "USERPROFILE=/parent", "APPDATA=/parent/a", "HOME=/child"}

	if got := childEnv(parent, "linux"); strings.Join(got, ";") != strings.Join(parent, ";") {
		t.Fatalf("linux env changed: %q", got)
	}
	if childEnv(nil, "windows") != nil {
		t.Fatal("a nil env (inherit) must stay nil")
	}
	got := childEnv(parent, "windows")
	if v, _ := get(got, "USERPROFILE"); v != "/child" {
		t.Fatalf("windows USERPROFILE = %q, want the child's HOME /child", v)
	}
	// filepath.Join writes \child on Windows; compare in slash form.
	if v, _ := get(got, "APPDATA"); !strings.HasPrefix(filepath.ToSlash(v), "/child") {
		t.Fatalf("windows APPDATA = %q, want it under /child", v)
	}
	noHome := childEnv([]string{"PATH=x", "USERPROFILE=/parent", "LocalAppData=/p/l"}, "windows")
	for _, k := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		if _, ok := get(noHome, k); ok {
			t.Fatalf("env without HOME kept %s: %q; a removed HOME means no home", k, noHome)
		}
	}
	if v, _ := get(noHome, "PATH"); v != "x" {
		t.Fatalf("PATH lost: %q", noHome)
	}
}
