package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// prGateWorkflow returns the workflow whose test step gates every PR in this
// tree.
//
// The private repo gates on ci-cd.yml. The public agentshield-oss tree ships
// without .github/ except oss-ci.yml (scripts/oss-excludes.sh). publish-oss.sh
// refuses a tree whose `go test ./...` fails, so this test must pass there too.
// Choosing by tree, rather than skipping when ci-cd.yml is missing, keeps a
// renamed workflow from turning this into a silent skip.
func prGateWorkflow() string {
	if ossbuild.PremiumPacksPresent() {
		return ".github/workflows/ci-cd.yml"
	}
	return ".github/workflows/oss-ci.yml"
}

var goTestCommand = regexp.MustCompile(`(^|\s)go test(\s|$)`)

// goTestTargets returns the package patterns of every `go test` command in a
// workflow file, following shell line continuations.
func goTestTargets(workflow string) []string {
	var targets []string
	lines := strings.Split(workflow, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "#") || !goTestCommand.MatchString(line) {
			continue
		}
		cmd := line
		for strings.HasSuffix(cmd, `\`) && i+1 < len(lines) {
			i++
			cmd = strings.TrimSuffix(cmd, `\`) + " " + strings.TrimSpace(lines[i])
		}
		for _, field := range strings.Fields(cmd) {
			if field == "./..." || strings.HasPrefix(field, "./") {
				targets = append(targets, field)
			}
		}
	}
	return targets
}

// coveredBy reports whether `go test <targets>` runs the package in dir
// (module-relative, slash-separated).
func coveredBy(dir string, targets []string) bool {
	for _, t := range targets {
		t = strings.TrimPrefix(t, "./")
		switch {
		case t == "...":
			return true
		case strings.HasSuffix(t, "/..."):
			root := strings.TrimSuffix(t, "/...")
			if dir == root || strings.HasPrefix(dir, root+"/") {
				return true
			}
		case dir == strings.TrimSuffix(t, "/"):
			return true
		}
	}
	return false
}

// packagesWithTests returns every module directory holding a _test.go file,
// skipping the directories `./...` skips.
func packagesWithTests(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), "_test.go") {
			rel, err := filepath.Rel(root, filepath.Dir(p))
			if err != nil {
				return err
			}
			seen[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// TestEveryTestedPackageRunsInCI: a test the PR gate never runs is an
// instruction, not a check. Until 2026-10-12, eight packages with 91 test
// functions (the data-label engine among them) were outside the hand-kept
// list in ci-cd.yml.
func TestEveryTestedPackageRunsInCI(t *testing.T) {
	root := moduleRoot(t)
	workflow := prGateWorkflow()
	raw, err := os.ReadFile(filepath.Join(root, workflow))
	if err != nil {
		t.Fatal(err)
	}
	targets := goTestTargets(string(raw))
	if len(targets) == 0 {
		t.Fatalf("no `go test` command with package targets found in %s: the parser or the workflow changed", workflow)
	}
	pkgs := packagesWithTests(t, root)
	if len(pkgs) < 25 {
		t.Fatalf("found %d packages with tests, want >= 25: the walker is not seeing the module", len(pkgs))
	}
	for _, p := range pkgs {
		if !coveredBy(p, targets) {
			t.Errorf("%s has tests that the PR gate never runs: %s runs `go test %s`", p, workflow, strings.Join(targets, " "))
		}
	}
}

func TestGoTestTargets_SelfTest(t *testing.T) {
	wf := "      - run: |\n" +
		"          # go test ./not/this/...\n" +
		"          go test -count=1 -timeout 40m \\\n" +
		"            ./internal/analyzer/... \\\n" +
		"            ./cmd/...\n" +
		"      - run: go vet ./...\n"
	if got, want := strings.Join(goTestTargets(wf), " "), "./internal/analyzer/... ./cmd/..."; got != want {
		t.Errorf("goTestTargets = %q, want %q", got, want)
	}
	cases := []struct {
		dir     string
		targets []string
		want    bool
	}{
		{"internal/datalabel", []string{"./internal/analyzer/..."}, false},
		{"internal/mcp/scenarios", []string{"./internal/mcp/..."}, true},
		{"internal/mcpx", []string{"./internal/mcp/..."}, false},
		{"internal/policy", []string{"./internal/policy"}, true},
		{"internal/policy/remediation", []string{"./internal/policy"}, false},
		{"anything/at/all", []string{"./..."}, true},
	}
	for _, c := range cases {
		if got := coveredBy(c.dir, c.targets); got != c.want {
			t.Errorf("coveredBy(%q, %q) = %v, want %v", c.dir, c.targets, got, c.want)
		}
	}
}
