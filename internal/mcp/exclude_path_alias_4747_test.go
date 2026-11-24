package mcp

import (
	"encoding/json"
	"testing"
)

// #4747: an exclude_args_match keyed on `path` also reads file_path, the
// name Claude Code's Write/Edit/MultiEdit give the file they write. These
// tests use a synthetic rule so the payloads stay innocuous; the pack rows
// for the ten affected rules live in the packs' own tests: blocks.

// aliasRule fires on content "TRIGGER-4747" unless the path is under docs/
// or a .md file, the shape of the ten #4747 rules' excludes.
func aliasRule() MCPStructuralMatch {
	return MCPStructuralMatch{
		ToolNameRegex: ".*",
		ArgsMatch: map[string]ArgFieldMatch{
			"content": {PatternAny: []string{"TRIGGER-4747"}},
		},
		ExcludeArgsMatch: map[string]ArgFieldMatch{
			"path": {PatternAny: []string{`(?i).*[/\\]docs[/\\].*`, `(?i)^docs[/\\].*`, `(?i).*\.md$`}},
		},
	}
}

func argsFromJSON(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExcludePathAlias_FilePathIsReadLikePath(t *testing.T) {
	cases := []struct {
		name  string
		args  string
		fires bool
	}{
		// The #4747 rows: on main these fire, because the exclude never sees file_path.
		{"Write to docs/ (relative)", `{"file_path":"docs/k8s-security.md","content":"TRIGGER-4747"}`, false},
		{"Write to docs/ (absolute, as Claude Code sends)", `{"file_path":"/Users/u/repo/docs/guide.txt","content":"TRIGGER-4747"}`, false},
		{"Write of a .md file", `{"file_path":"/Users/u/repo/NOTES.md","content":"TRIGGER-4747"}`, false},
		{"camelCase spelling folds to file_path", `{"filePath":"docs/a.txt","content":"TRIGGER-4747"}`, false},
		{"filepath spelling folds to file_path", `{"filepath":"docs/a.txt","content":"TRIGGER-4747"}`, false},

		// TPs: a file_path outside the excused locations still fires.
		{"Write outside docs/", `{"file_path":"/deploy/rbac.yaml","content":"TRIGGER-4747"}`, true},
		{"Write with no path at all", `{"content":"TRIGGER-4747"}`, true},

		// `path` alone decides exactly as main.
		{"path under docs/", `{"path":"docs/a.txt","content":"TRIGGER-4747"}`, false},
		{"path outside docs/", `{"path":"/deploy/a.yaml","content":"TRIGGER-4747"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchStructural("Write", argsFromJSON(t, tc.args), aliasRule()); got != tc.fires {
				t.Errorf("fires=%v, want %v for %s", got, tc.fires, tc.args)
			}
		})
	}
}

// TestExcludePathAlias_DecoyCannotSatisfyTheExclude is the check the alias
// must pass to be safe: a call carrying both names has its exclude met only
// when both are excused. Claude Code writes file_path; Copilot CLI and the
// MCP filesystem server write path. Each JSON key order is spelled out
// although Go maps have none, so a future ordered decoder cannot reopen it.
func TestExcludePathAlias_DecoyCannotSatisfyTheExclude(t *testing.T) {
	cases := []struct {
		name  string
		args  string
		fires bool
	}{
		// Real target file_path (Claude Code), decoy path. Main excused these:
		// it read path alone. Now they fire.
		{"decoy path first", `{"path":"docs/x.md","file_path":"/deploy/rbac.yaml","content":"TRIGGER-4747"}`, true},
		{"decoy path last", `{"file_path":"/deploy/rbac.yaml","content":"TRIGGER-4747","path":"docs/x.md"}`, true},
		// Real target path (Copilot, MCP), decoy file_path. Main fired; so does this.
		{"decoy file_path first", `{"file_path":"docs/x.md","path":"/deploy/rbac.yaml","content":"TRIGGER-4747"}`, true},
		{"decoy file_path last", `{"path":"/deploy/rbac.yaml","content":"TRIGGER-4747","file_path":"docs/x.md"}`, true},
		// A decoy nested where only main's path resolution looks.
		{"nested decoy path", `{"file_path":"/deploy/rbac.yaml","request":{"path":"docs/x.md"},"content":"TRIGGER-4747"}`, true},
		// Two spellings of file_path: both must be excused.
		{"two file_path spellings, one outside", `{"file_path":"docs/x.md","filePath":"/deploy/rbac.yaml","content":"TRIGGER-4747"}`, true},
		// Both excused: the exclude holds.
		{"both under docs/", `{"path":"docs/x.md","file_path":"docs/x.md","content":"TRIGGER-4747"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchStructural("Write", argsFromJSON(t, tc.args), aliasRule()); got != tc.fires {
				t.Errorf("fires=%v, want %v for %s", got, tc.fires, tc.args)
			}
		})
	}
}

// TestExcludePathAlias_FilePathMustPassCleaned: an unanchored `.*/docs/.*`
// exclude matches a path that climbs out of docs, so file_path is also read
// as path.Clean leaves it, and must pass both readings.
func TestExcludePathAlias_FilePathMustPassCleaned(t *testing.T) {
	for _, fp := range []string{
		"/etc/kubernetes/docs/../manifests/admin.yaml",
		"docs/../deploy/rbac.yaml",
		"/repo/docs/../../etc/x.yaml",
	} {
		args := map[string]interface{}{"file_path": fp, "content": "TRIGGER-4747"}
		if !matchStructural("Write", args, aliasRule()) {
			t.Errorf("file_path %q climbs out of docs/ and must not be excused", fp)
		}
	}
	// A path that stays inside docs after cleaning is still excused.
	args := map[string]interface{}{"file_path": "/repo/docs/a/../b.txt", "content": "TRIGGER-4747"}
	if matchStructural("Write", args, aliasRule()) {
		t.Error("file_path that stays under docs/ after cleaning should be excused")
	}
}

func TestExcludePathAlias_NonStringFilePathNeverPasses(t *testing.T) {
	for _, v := range []interface{}{
		[]interface{}{"docs/x.md"},
		map[string]interface{}{"path": "docs/x.md"},
		nil,
		float64(1),
	} {
		args := map[string]interface{}{"file_path": v, "content": "TRIGGER-4747"}
		if !matchStructural("Write", args, aliasRule()) {
			t.Errorf("non-string file_path %#v must not satisfy the exclude", v)
		}
	}
	// Values whose Go stringification WOULD pass the exclude (#4927 pass 1
	// mutation finding): reading a non-string through valueToString must
	// not excuse them either.
	excuse := aliasRule().ExcludeArgsMatch["path"]
	for _, v := range []interface{}{
		[]interface{}{"/repo/docs/x.md"},
		map[string]interface{}{"a": "/repo/docs/x.txt"},
	} {
		if !matchArgPatterns(valueToString(v), excuse) {
			t.Fatalf("control: %q should pass the exclude when stringified, or this row is vacuous", valueToString(v))
		}
		args := map[string]interface{}{"file_path": v, "content": "TRIGGER-4747"}
		if !matchStructural("Write", args, aliasRule()) {
			t.Errorf("non-string file_path %#v stringifies into an excused path but must not satisfy the exclude", v)
		}
	}
}

// TestExcludePathAlias_BackslashTraversalMustPassCleaned: path.Clean is
// POSIX-only, and the excludes treat `\` as a separator, so a file_path is
// also read with its backslashes turned to slashes and cleaned (#4927 pass
// 1, S1). The slash-normalised reading in evaluateReadings only covers
// drive-letter and UNC values; root-relative and relative ones relied on this.
func TestExcludePathAlias_BackslashTraversalMustPassCleaned(t *testing.T) {
	for _, fp := range []string{
		`\Users\u\repo\docs\..\docker-compose.yml`,
		`\Users\u\repo\docs\..\..\..\Windows\Temp\rbac.yaml`,
		`docs\..\..\deploy\rbac.yaml`,
		`/Users/u/repo/docs\..\deploy/rbac.yaml`,
		`C:\Users\u\repo\docs\..\..\..\Windows\Temp\rbac.yaml`,
	} {
		args := map[string]interface{}{"file_path": fp, "content": "TRIGGER-4747"}
		if !matchStructural("Write", args, aliasRule()) {
			t.Errorf("file_path %q climbs out of docs\\ and must not be excused", fp)
		}
	}
	// A plain Windows-style path inside docs, no `..`, is still excused.
	for _, fp := range []string{
		`C:\Users\u\repo\docs\guide.txt`,
		`\Users\u\repo\docs\guide.txt`,
		`docs\guide.txt`,
		`C:\Users\u\repo\docs\a\..\b.txt`,
	} {
		args := map[string]interface{}{"file_path": fp, "content": "TRIGGER-4747"}
		if matchStructural("Write", args, aliasRule()) {
			t.Errorf("file_path %q stays under docs\\ and should be excused", fp)
		}
	}
}

// TestExcludePathAlias_NestedFilePathMustBeExcusedToo: a file_path nested in
// an envelope, in a batch's items or in the plural file_paths is a target
// too, as nested and plural spellings of path already are. An excused
// top-level file_path does not excuse the call while one of them is not.
func TestExcludePathAlias_NestedFilePathMustBeExcusedToo(t *testing.T) {
	cases := []struct {
		name  string
		args  string
		fires bool
	}{
		{"envelope target outside", `{"file_path":"docs/a.txt","request":{"file_path":"/deploy/x.yaml"},"content":"TRIGGER-4747"}`, true},
		{"batch item outside", `{"file_path":"docs/a.txt","edits":[{"file_path":"/deploy/x.yaml"}],"content":"TRIGGER-4747"}`, true},
		{"plural outside", `{"file_path":"docs/a.txt","file_paths":["/deploy/x.yaml"],"content":"TRIGGER-4747"}`, true},
		{"envelope target inside", `{"file_path":"docs/a.txt","request":{"file_path":"docs/b.txt"},"content":"TRIGGER-4747"}`, false},
		{"batch item inside", `{"file_path":"docs/a.txt","edits":[{"file_path":"docs/b.txt"}],"content":"TRIGGER-4747"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchStructural("Write", argsFromJSON(t, tc.args), aliasRule()); got != tc.fires {
				t.Errorf("fires=%v, want %v for %s", got, tc.fires, tc.args)
			}
		})
	}
}

// TestExcludePathAlias_ExcludeWhenHasNoAlias: exclude_when reads the name
// it is given. The shipped mcp-struct-block-credential-path-access keys its
// exclude_when on path; a file_path naming the same file must not satisfy it.
func TestExcludePathAlias_ExcludeWhenHasNoAlias(t *testing.T) {
	clause := StructuralExcludeClause{ArgsMatch: map[string]ArgFieldMatch{
		"path": {PatternAny: []string{`(?i)^docs/`}},
	}}
	if !clause.matches("read_file", map[string]interface{}{"path": "docs/a.txt"}) {
		t.Fatal("control: exclude_when on path should hold for path")
	}
	if clause.matches("read_file", map[string]interface{}{"file_path": "docs/a.txt"}) {
		t.Error("exclude_when keyed on path must not read file_path")
	}

	var shipped *MCPStructuralRule
	for _, r := range loadAllMCPStructuralRules(t) {
		if r.ID == "mcp-struct-block-credential-path-access" {
			rr := r
			shipped = &rr
		}
	}
	if shipped == nil || shipped.Match.ExcludeWhen == nil {
		t.Fatal("mcp-struct-block-credential-path-access or its exclude_when is gone: update this pin")
	}
	file := "/home/u/.py" + "pirc"
	if !shipped.Match.ExcludeWhen.matches("read_file", map[string]interface{}{"path": file}) {
		t.Fatalf("control: the shipped exclude_when should hold for path %s", file)
	}
	if shipped.Match.ExcludeWhen.matches("read_file", map[string]interface{}{"file_path": file}) {
		t.Errorf("the shipped exclude_when must not read file_path")
	}
}

// TestExcludePathAlias_PositiveSideHasNoAlias: only the exclude reads
// file_path. A rule whose args_match keys on path still needs path.
func TestExcludePathAlias_PositiveSideHasNoAlias(t *testing.T) {
	m := MCPStructuralMatch{
		ToolNameRegex: ".*",
		ArgsMatch: map[string]ArgFieldMatch{
			"path":    {PatternAny: []string{`\.github/workflows/.*\.ya?ml$`}},
			"content": {PatternAny: []string{"TRIGGER-4747"}},
		},
	}
	if matchStructural("Write", map[string]interface{}{"file_path": "/r/.github/workflows/a.yml", "content": "TRIGGER-4747"}, m) {
		t.Error("args_match keyed on path must not read file_path (that would be a separate, raising change)")
	}
	if !matchStructural("Write", map[string]interface{}{"path": "/r/.github/workflows/a.yml", "content": "TRIGGER-4747"}, m) {
		t.Error("control: args_match on path should fire on path")
	}
}

// TestExcludePathAlias_OtherKeysUnchanged: the alias is only for an exclude
// keyed on path. An exclude keyed on content, or on file_path itself (the
// #3225 copies), is matchArgField as before, and file/filename are not
// aliases.
func TestExcludePathAlias_OtherKeysUnchanged(t *testing.T) {
	excuse := ArgFieldMatch{PatternAny: []string{`(?i)^docs[/\\].*`}}
	calls := []map[string]interface{}{
		{"file_path": "docs/a.txt"},
		{"file_path": "/deploy/a.yaml"},
		{"file": "docs/a.txt"},
		{"filename": "docs/a.txt"},
		{"path": "docs/a.txt", "file_path": "/deploy/a.yaml"},
		{"request": map[string]interface{}{"file_path": "docs/a.txt"}},
		{"content": "x"},
	}
	for _, key := range []string{"file_path", "file", "filename", "content", "config.path"} {
		for _, args := range calls {
			if got, want := excludeArgFieldMatches(args, key, excuse), matchArgField(args, key, excuse); got != want {
				t.Errorf("key %q on %v: excludeArgFieldMatches=%v, matchArgField=%v; want them equal", key, args, got, want)
			}
		}
	}
	// file and filename do not reach a path-keyed exclude.
	for _, args := range []map[string]interface{}{{"file": "docs/a.txt"}, {"filename": "docs/a.txt"}} {
		if excludeArgFieldMatches(args, "path", excuse) {
			t.Errorf("%v: file/filename are not path aliases", args)
		}
	}
}

// TestExcludePathAlias_NoFilePathMeansMain: without a file_path in the call,
// a path-keyed exclude is matchArgField exactly, over the resolution forms
// main reads (plural, nested, string-encoded JSON).
func TestExcludePathAlias_NoFilePathMeansMain(t *testing.T) {
	excuse := ArgFieldMatch{PatternAny: []string{`(?i)^docs[/\\].*`}}
	calls := []string{
		`{"path":"docs/a.txt"}`,
		`{"path":"/deploy/a.yaml"}`,
		`{"paths":["docs/a.txt","/deploy/a.yaml"]}`,
		`{"request":{"path":"docs/a.txt"}}`,
		`{"payload":"{\"path\":\"docs/a.txt\"}"}`,
		`{"Path":"docs/a.txt"}`,
		`{"file":"docs/a.txt"}`,
		`{"content":"x"}`,
		`{}`,
	}
	for _, s := range calls {
		args := argsFromJSON(t, s)
		if got, want := excludeArgFieldMatches(args, "path", excuse), matchArgField(args, "path", excuse); got != want {
			t.Errorf("%s: excludeArgFieldMatches=%v, matchArgField=%v; want them equal", s, got, want)
		}
	}
}
