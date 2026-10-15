package cli

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The release stamps the version with `-X '<package>.<Var>=…'`. If the package
// path is wrong, Go ignores the flag without an error and every released binary
// reports "0.1.0-dev", which is what the heartbeat sends to AI Agent Lens. That
// happened after the module moved to the AI-AgentLens org:
// .goreleaser.yaml kept the old path for six months. This pins every -X path in
// the build configs to go.mod's module and to a variable that exists here.
func TestReleaseLdflagsStampThisModule(t *testing.T) {
	root := filepath.Join("..", "..")
	module := modulePath(t, filepath.Join(root, "go.mod"))
	vars := map[string]bool{"Version": true, "GitCommit": true, "BuildDate": true}
	xFlag := regexp.MustCompile(`-X '([^'=]+)\.([A-Za-z0-9_]+)=`)

	cliPath := module + "/internal/cli"
	for _, cfg := range []string{".goreleaser.yaml", "Makefile"} {
		data, err := os.ReadFile(filepath.Join(root, cfg))
		if err != nil {
			t.Fatalf("read %s: %v", cfg, err)
		}
		found := 0
		for _, m := range xFlag.FindAllStringSubmatch(string(data), -1) {
			pkg, name := m[1], m[2]
			if !strings.HasSuffix(pkg, "/internal/cli") {
				continue // other binaries (shield-server's main.Version) are not this package
			}
			found++
			if pkg != cliPath {
				t.Errorf("%s stamps %s.%s, but go.mod's module is %s: the flag is ignored and releases report %q", cfg, pkg, name, module, Version)
			}
			if !vars[name] {
				t.Errorf("%s stamps %s.%s, which is not a variable in internal/cli", cfg, pkg, name)
			}
		}
		if found == 0 {
			t.Errorf("%s stamps nothing in internal/cli: the version would never be set", cfg)
		}
	}
}

func modulePath(t *testing.T, goMod string) string {
	t.Helper()
	f, err := os.Open(goMod)
	if err != nil {
		t.Fatalf("open go.mod: %v", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if line := strings.TrimSpace(s.Text()); strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	t.Fatal("no module line in go.mod")
	return ""
}
