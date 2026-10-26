package shellparse

import (
	"strings"
	"testing"
)

func TestInterpInertHeredocBoundaries(t *testing.T) {
	for _, suffix := range []string{"", "\n"} {
		for _, delimiter := range []string{"PY", "os.system(x)", `quote"marker`} {
			command := "python3 - <<'" + delimiter + "'\nprint('text')\n" + delimiter + suffix
			spans := InterpreterHeredocLiteralSpans(command)
			if len(spans) != 1 {
				t.Fatalf("spans=%v for %q", spans, command)
			}
			sp := spans[0]
			const body = "print('text')\n"
			if got := command[sp.Start:sp.BodyEnd]; got != body {
				t.Fatalf("body=%q want=%q", got, body)
			}
			actualChecked, legacyChecked := false, false
			if !CommandLineIsPure(command, func(lang, got string) bool {
				actualChecked = true
				return lang == "python3" && got == body
			}, func(lang, got string) bool {
				legacyChecked = true
				return lang == "python3" && got == command[sp.Start:sp.End]
			}) || !actualChecked || !legacyChecked {
				t.Fatalf("callbacks not both satisfied: %q", command)
			}
			if CommandLineIsPure(command, func(string, string) bool { return true }, func(string, string) bool { return false }) {
				t.Fatal("legacy rejection bypassed")
			}
		}
	}
}

func TestInterpInertSharedDeferredTargets(t *testing.T) {
	for name := range autoRunBasenames {
		for _, prefix := range []string{"", "~/", "$HOME/", "/tmp/../root/"} {
			if !IsDeferredExecTarget(prefix + name) {
				t.Errorf("startup path missed: %q", prefix+name)
			}
		}
		if IsDeferredExecTarget(name + ".bak") {
			t.Errorf("backup mistaken for startup path: %s", name)
		}
	}
	for _, p := range []string{".git/hooks/pre-commit", ".husky/pre-commit", "/etc/profile.d/test.sh", "/etc/cron.d/job", "/var/spool/cron/job", ".config/fish/config.fish"} {
		if !IsDeferredExecTarget(p) {
			t.Errorf("deferred target missed: %q", p)
		}
		if strings.HasPrefix(p, "/etc/") && !IsDeferredExecTarget(strings.Replace(p, "/etc/", "/tmp/../etc/", 1)) {
			t.Errorf("cleaned target missed: %q", p)
		}
	}
}
