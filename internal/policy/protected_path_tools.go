package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"gopkg.in/yaml.v3"
)

// Customer protected_paths on the agent's file tools (#4645).
//
// A pack's (or policy.yaml's) defaults.protected_paths BLOCKed a shell command
// naming the path, but the agent's own Read, Write and Edit tools never
// consulted it: those calls go through the MCP evaluator, which reads MCP
// policy only. The paths AgentShield ships reach those tools through MCP rules
// of their own (cmd/mcp-gen, the premium catch-alls), so only a path the
// customer added was missing.
//
// So the tool-call surfaces apply the CUSTOMER's protected paths, and only
// those: the merged shell policy's list minus every pattern AgentShield
// ships. A shipped pattern keeps exactly the tool-call behaviour it has on
// main. Applying the shipped list too would put a BLOCK on every Claude Code
// Read of ~/.kube/config in a community install, which is the AUDIT-with-rule
// call #4248 made for those paths. A customer pattern is a BLOCK the customer
// asked for.

// ProtectedPathRuleID is the rule id a protected_paths match decides a BLOCK
// with, on the shell and on the tool-call surfaces alike.
const ProtectedPathRuleID = "protected-path"

// shippedProtectedPaths is every protected_paths pattern AgentShield itself
// declares: DefaultPolicy, the configs/default_policy.yaml template, the
// community and premium shell packs, and the managed config directory.
// TestShippedProtectedPaths_MatchEveryShippedDeclaration holds it to those
// files in both directions, so a pack that ships a new pattern fails CI until
// it is listed here (or the pattern would start BLOCKing file tools).
var shippedProtectedPaths = map[string]bool{
	// DefaultPolicy and packs/community/secrets-pii.yaml
	"~/.ssh/**":           true,
	"~/.aws/**":           true,
	"~/.gnupg/**":         true,
	"~/.config/gcloud/**": true,
	"~/.kube/**":          true,
	// configs/default_policy.yaml
	"/etc/**":     true,
	"/System/**":  true,
	"/Library/**": true,
	// packs/community/secrets-pii.yaml
	"~/.docker/config.json":       true,
	"~/.npmrc":                    true,
	"~/.pypirc":                   true,
	"~/.netrc":                    true,
	"~/.git-credentials":          true,
	"~/.config/gh/**":             true,
	"~/.vault-token":              true,
	"~/.terraform.d/**":           true,
	"~/.config/op/**":             true,
	"~/.local/share/keyrings/**":  true,
	"~/.config/github-copilot/**": true,
	"~/.config/age/**":            true,
	"~/.age/**":                   true,
	"~/.cargo/credentials.toml":   true,
	"~/.gem/credentials":          true,
	"~/.m2/settings.xml":          true,
	"~/.gradle/gradle.properties": true,
	// packs/premium/supply-chain.yaml
	"~/.pip/**":            true,
	"~/.config/pip/**":     true,
	"~/.yarnrc":            true,
	"~/.cargo/config.toml": true,
	// a managed host's own config directory (#3620)
	ManagedConfigProtectedPath: true,
}

// IsShippedProtectedPath reports whether AgentShield itself declares pattern.
func IsShippedProtectedPath(pattern string) bool {
	return shippedProtectedPaths[pattern]
}

// CustomerProtectedPaths returns the patterns of paths that AgentShield does
// not ship, in order, without duplicates: the protected paths a customer
// added in policy.yaml or a pack.
func CustomerProtectedPaths(paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || shippedProtectedPaths[p] || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// MatchProtectedPath returns the first pattern that path matches, with the
// shell engine's matching (protectedPathMatchesIn): `~/` expanded against
// home, a relative pattern also matched against a path under cwd, and with
// foldCase the reading a case-insensitive volume gives (#4194). path should
// already be resolved the way the caller's surface resolves it.
func MatchProtectedPath(patterns []string, home, path, cwd string, foldCase bool) (string, bool) {
	if foldCase {
		cwd = pathnorm.FoldASCII(cwd)
	}
	for _, pattern := range patterns {
		if protectedPathMatchesIn(home, path, pattern, cwd, foldCase) {
			return pattern, true
		}
	}
	return "", false
}

// LoadDeclaredProtectedPaths returns the protected_paths the shell hook's
// policy declares outside the binary: the user policy file (layered over
// DefaultPolicy, as Load does) and every enabled pack LoadPacks reads from
// packsDir, in LoadPacks's order. The embedded community packs are left out:
// every pattern they declare is shipped, so CustomerProtectedPaths would drop
// it anyway.
//
// It exists for the tool-call path of the hook, which evaluates every Read,
// Write and Edit. LoadPacks parses each pack whole, about 50 ms for a premium
// install's packs, so this reads only defaults.protected_paths
// (declaredProtectedPaths). The infos carry a LoadError for a pack whose
// protected_paths could not be read, so the caller can report a degraded
// ruleset as the shell path does. err is set when the policy file cannot be
// parsed or packsDir cannot be listed; a missing file or directory is not an
// error. Either failure still returns what did load (DefaultPolicy's list in
// place of an unparsable policy file), so a broken layer never takes the
// other layer's paths with it.
func LoadDeclaredProtectedPaths(policyPath, packsDir string) ([]string, []PackInfo, error) {
	pol, loadErr := Load(policyPath)
	if loadErr != nil {
		pol = DefaultPolicy()
	}
	paths := append([]string(nil), pol.Defaults.ProtectedPaths...)
	if packsDir == "" {
		return paths, nil, loadErr
	}
	infos, err := walkShellPackTree(packsDir, PackLoadHooks[declaredPack]{
		Parse: func(data []byte, label string) (*declaredPack, error) {
			pp, err := declaredProtectedPaths(data)
			if err != nil {
				return nil, fmt.Errorf("failed to parse pack %s: %w", label, err)
			}
			return &declaredPack{paths: pp}, nil
		},
		Describe: func(*declaredPack) PackInfo { return PackInfo{} },
		Merge:    func(p *declaredPack) { paths = unionStrings(paths, p.paths) },
	})
	if err != nil && os.IsNotExist(err) {
		err = nil
	}
	return paths, infos, errors.Join(loadErr, err)
}

// declaredPack is one pack as LoadDeclaredProtectedPaths reads it.
type declaredPack struct{ paths []string }

// protectedPathsDoc is the one field of a pack declaredProtectedPaths decodes.
type protectedPathsDoc struct {
	Defaults struct {
		ProtectedPaths []string `yaml:"protected_paths"`
	} `yaml:"defaults"`
}

// defaultsHeader is a top-level `defaults:` key opening a block mapping.
var defaultsHeader = regexp.MustCompile(`^defaults[ \t]*:[ \t]*(#.*)?\r?\n?$`)

// declaredProtectedPaths returns a pack's defaults.protected_paths.
//
// The fast path decodes only the top-level `defaults:` block, so a 700 KB pack
// costs microseconds instead of a full YAML parse. It is taken only when the
// text has exactly one such header, no document marker, and the block decodes
// on its own; anything else (flow style, anchors, a quoted key, several
// documents) decodes the whole document, as LoadPacks does. A file that spells
// protected_paths only in comments, or not at all, declares none and is not
// parsed (so its LoadError, if it has one, is LoadPacks's to report).
//
// The fast path reads what a whole-document decode reads: a block mapping's
// entries end at the next line that starts in column 0 with anything but a
// comment, and nothing inside another key's value can start in column 0.
// TestDeclaredProtectedPaths_FastPathMatchesFullDecode holds the two to the
// same answer on every shipped pack and on the shapes listed above. One known
// difference: a pack whose rules fail to parse still contributes the
// protected paths its defaults block declares, where LoadPacks drops the
// whole pack (and reports it). That only adds a BLOCK the pack asked for.
func declaredProtectedPaths(data []byte) ([]string, error) {
	if !mentionsProtectedPathsOutsideComments(data) {
		return nil, nil
	}
	if block, ok := topLevelDefaultsBlock(data); ok {
		var doc protectedPathsDoc
		if err := yaml.Unmarshal(block, &doc); err == nil {
			return doc.Defaults.ProtectedPaths, nil
		}
	}
	var doc protectedPathsDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Defaults.ProtectedPaths, nil
}

// mentionsProtectedPathsOutsideComments reports whether protected_paths
// appears on a line that is not a whole-line comment. A key can never sit in
// one, so a pack that names it only in comments (the premium
// terminal-safety-advanced pack, 760 KB) declares none and is not parsed.
func mentionsProtectedPathsOutsideComments(data []byte) bool {
	key := []byte("protected_paths")
	for from := 0; ; {
		i := bytes.Index(data[from:], key)
		if i < 0 {
			return false
		}
		at := from + i
		lineStart := bytes.LastIndexByte(data[:at], '\n') + 1
		if trimmed := bytes.TrimLeft(data[lineStart:at], " \t"); len(trimmed) == 0 || trimmed[0] != '#' {
			return true
		}
		from = at + len(key)
	}
}

// topLevelDefaultsBlock returns the `defaults:` line and the lines of its
// block mapping, or false when the fast path does not apply.
func topLevelDefaultsBlock(data []byte) ([]byte, bool) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	start := -1
	for i, line := range lines {
		if bytes.HasPrefix(line, []byte("---")) || bytes.HasPrefix(line, []byte("...")) || bytes.HasPrefix(line, []byte("%")) {
			return nil, false
		}
		if defaultsHeader.Match(line) {
			if start >= 0 {
				return nil, false
			}
			start = i
		}
	}
	if start < 0 {
		return nil, false
	}
	var block bytes.Buffer
	block.Write(lines[start])
	for _, line := range lines[start+1:] {
		if len(line) > 0 && !isBlockContinuation(line[0]) {
			break
		}
		block.Write(line)
	}
	return block.Bytes(), true
}

// isBlockContinuation reports whether a line starting with c can belong to
// the block mapping above it: indentation, a comment, or an empty line.
func isBlockContinuation(c byte) bool {
	return c == ' ' || c == '\t' || c == '#' || c == '\n' || c == '\r'
}
