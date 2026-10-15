package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/AI-AgentLens/agentshield"

// moduleRoot walks up from the test's working directory to the go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test directory")
		}
		dir = parent
	}
}

// skipDir reports whether Go tooling ignores this directory for `./...`.
func skipDir(name string) bool {
	return name == "testdata" || name == "vendor" || name == "node_modules" ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// goFile is one parsed .go file of the module.
type goFile struct {
	rel  string // slash-separated path from the module root
	pkg  string // directory from the module root, e.g. "internal/mcp"
	file *ast.File
}

// moduleFiles parses every non-test .go file in the module with the given
// parser mode.
//
// Build constraints are deliberately not evaluated. Every OS variant is
// parsed, so an import that exists only in a `!unix` file still counts.
// Only internal/logger carries constraints today.
func moduleFiles(t *testing.T, root string, mode parser.Mode) []goFile {
	t.Helper()
	fset := token.NewFileSet()
	var out []goFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == root {
				return nil
			}
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			// A nested module is not part of this one.
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, mode)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		out = append(out, goFile{rel: rel, pkg: pathpkg.Dir(rel), file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// internalImport is one import of a package from this module.
type internalImport struct {
	local string // the name the file uses: its alias, or the last path element
	rel   string // module-relative path, e.g. "internal/policy"
}

// internalImports returns the imports a file makes from this module.
func internalImports(f *ast.File) []internalImport {
	var out []internalImport
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !strings.HasPrefix(p, modulePath+"/") {
			continue
		}
		rel := strings.TrimPrefix(p, modulePath+"/")
		local := pathpkg.Base(rel)
		if spec.Name != nil {
			local = spec.Name.Name
		}
		out = append(out, internalImport{local: local, rel: rel})
	}
	return out
}
