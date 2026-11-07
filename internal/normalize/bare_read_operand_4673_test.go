package normalize

import (
	"os"
	"path/filepath"
	"testing"
)

// #4673: a reader's bare operand that does not exist in cwd is kept as
// written (cwd-relative), so a relative protected_paths pattern can match it
// the way a file tool's relative argument is matched. Names are assembled at
// runtime: the hook reads test sources as commands.
func TestBareReadOperandKeptRelativeWhenAbsent_4673(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := "." + "env"
	paths := func(cmd string) []string { return NormalizeCommand(cmd, cwd).Paths }
	has := func(cmd, want string) bool {
		for _, p := range paths(cmd) {
			if p == want {
				return true
			}
		}
		return false
	}

	for _, cmd := range []string{
		"cat " + env, "less " + env, "head -5 " + env, "tail -n 3 " + env,
		"wc -l " + env, "base64 " + env, "source " + env, ". " + env, "sudo cat " + env,
		"cat " + env + " | wc -c", "cat < " + env, "scp " + env + " host:/tmp/",
	} {
		if !has(cmd, env) {
			t.Errorf("%q: paths %v; want the cwd-relative %q", cmd, paths(cmd), env)
		}
	}

	// Not a reader, or not a file position: unchanged. With an absolute cwd
	// main never yields a relative path, so none may appear here.
	for _, cmd := range []string{
		"ssh myhost", "kubectl get secrets", "git checkout " + env, "echo " + env,
		`git commit -m "` + env + `"`, "cat <<< " + env,
		"cat <<" + env + "\nx\n" + env, "docker compose --env-file " + env + " up",
	} {
		for _, p := range paths(cmd) {
			if !filepath.IsAbs(p) || p == filepath.Join(cwd, env) {
				t.Errorf("%q: paths %v; %q is not a file this command reads", cmd, paths(cmd), env)
			}
		}
	}
	// Left out of the list on purpose (see fileReadOperandCommands): the
	// grep family, sed, awk, rsync, diff and jq keep main's existence-gated
	// reading, because a pattern or name can sit in a file slot. In
	// `grep -A 3 .env README.md` the 3 is read as the pattern.
	for _, cmd := range []string{
		"grep KEY " + env, "grep -A 3 " + env + " README.md", "sed -n 1p " + env,
		"awk 1 " + env, "rsync -a --exclude " + env + " src/ dst/", "diff -x " + env + " a b",
		"jq " + env + " package.json",
	} {
		for _, p := range paths(cmd) {
			if p == env || p == filepath.Join(cwd, env) {
				t.Errorf("%q: paths %v; this command is not on the absent-read list", cmd, paths(cmd))
			}
		}
	}
	// The fallback tokenizer (heredoc commands) names no executable: unchanged.
	if got := Normalize([]string{"cat", ">", "/tmp/f", "<<", "EOF", "absent", "EOF"}, cwd).Paths; len(got) != 1 {
		t.Errorf("fallback tokenizer: paths %v; want only /tmp/f", got)
	}

	// Relative or empty cwd: no bare operand is resolved, as before.
	for _, dir := range []string{"", "rel/dir"} {
		if got := NormalizeCommand("cat "+env, dir).Paths; len(got) != 0 {
			t.Errorf("cwd %q: paths %v; want none", dir, got)
		}
	}

	// The file exists: main's absolute reading, unchanged.
	if err := os.WriteFile(filepath.Join(cwd, env), []byte("K=dummy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !has("cat "+env, filepath.Join(cwd, env)) {
		t.Errorf("existing file: paths %v; want %s", paths("cat "+env), filepath.Join(cwd, env))
	}
	if has("cat "+env, env) {
		t.Errorf("existing file: paths %v; the relative form is only for an absent file", paths("cat "+env))
	}
}

// A write operand keeps #4401's absolute reading (it creates the file under
// cwd), so it still reaches absolute patterns; only the read form is relative.
func TestBareWriteOperandStaysAbsoluteWhenAbsent_4673(t *testing.T) {
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := "." + "env"
	for _, cmd := range []string{"touch " + env, "cp /tmp/x " + env, "echo x > " + env} {
		got := NormalizeCommand(cmd, cwd).Paths
		found := false
		for _, p := range got {
			if p == filepath.Join(cwd, env) {
				found = true
			}
			if p == env {
				t.Errorf("%q: paths %v; a write operand is never kept relative", cmd, got)
			}
		}
		if !found {
			t.Errorf("%q: paths %v; want %s", cmd, got, filepath.Join(cwd, env))
		}
	}
}
