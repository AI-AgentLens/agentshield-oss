package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Self-protection for a harness's OWN file-write tools on a managed host
// (#4260). The shell path refuses any non-read command that touches
// ~/.agentshield (sp-block-config-touch on the text, the ~/.agentshield/**
// protected path on the materialized paths), but a non-shell tool call never
// reaches that layer: Claude Code's Write and Edit, and Copilot CLI's
// create/edit/apply_patch, rewrote policy.yaml and managed.json with exit 0.
// The only thing standing in the way of the same write through an MCP server
// was a premium pack rule keyed to MCP tool names.
//
// The protected set is the same as the shell path layer's — the whole
// directory — because nothing an agent writes there is legitimate on a managed
// host: the policy, the enrollment, the packs, the credentials and the audit
// log all belong to the admin or to AgentShield itself. Reads stay allowed,
// as they do on the shell path.

// selfProtectToolWriteRule names the block in the reason and the audit event.
const selfProtectToolWriteRule = "sp-block-config-tool-write"

// The receipt is split by target, like the shell rules' (Gary, 2026-10-30,
// #4670): a write onto the audit log cites ai-audit-trail-circumvention, and
// every other file in the directory cites security-tool-tampering, the node
// the MCP twin of this check (mcp-persist-block-agentshield-config-write)
// cites. "The log" is the community rule ts-block-agentshield-log-overwrite's
// path set (toolWriteTarget), so this path, sp-block-binary-replace and an
// unmanaged host's shell agree on which files are the log. The nodes are
// spTargetTaxonomy's.

// harnessWriteTools are the harness file-write tools, by the name the hook
// receives. The set is closed per harness, so it is a blocklist — a tool not
// listed here is not refused by this check, it goes on to MCP policy as
// before. Claude Code: Write, Edit, MultiEdit, NotebookEdit. Copilot CLI
// 1.0.93, captured live on 2026-10-07: create{path, file_text} and
// edit{path, old_str, new_str} natively, sent as Write and Edit with the same
// arguments in its Claude-compatible dialect; its GPT models edit through
// apply_patch. Gemini CLI and Codex do not reach here: their hooks are
// registered for the shell tool only.
var harnessWriteTools = map[string]bool{
	"Write":        true,
	"Edit":         true,
	"MultiEdit":    true,
	"NotebookEdit": true,
	"create":       true,
	"edit":         true,
	"apply_patch":  true,
}

// harnessWritePathKeys are the argument names those tools put the target in:
// Claude Code's file_path and notebook_path, Copilot's path.
var harnessWritePathKeys = []string{"file_path", "path", "notebook_path"}

// patchHeaderPrefixes are the apply_patch lines that name a file the patch
// writes. The grammar is fixed: add, update (optionally renamed), delete.
var patchHeaderPrefixes = []string{"*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"}

// harnessWriteTargets returns the file paths a harness write-tool call writes,
// or nil when the tool is not one. fromText marks a tool_input that arrived as
// a JSON string: only patch tools send one (stringToolInputArguments), so its
// patch is read whatever the tool is called — Copilot's compat dialect names
// apply_patch edits "Edit".
func harnessWriteTargets(toolName string, arguments map[string]interface{}, fromText bool) []string {
	if !harnessWriteTools[toolName] && !fromText {
		return nil
	}
	var out []string
	for _, k := range harnessWritePathKeys {
		if s, ok := arguments[k].(string); ok && s != "" {
			out = append(out, s)
		}
	}
	// The patch body, never a Write's content: only a patch tool's input is
	// the operation itself.
	if toolName == "apply_patch" || fromText {
		for _, k := range []string{"patch", "input"} {
			if s, ok := arguments[k].(string); ok && strings.HasPrefix(strings.TrimSpace(s), "*** Begin Patch") {
				out = append(out, patchTargets(s)...)
			}
		}
	}
	return out
}

// patchTargets returns every file an apply_patch body adds, updates, deletes
// or moves to.
//
// Inside an Update File section, a line that opens with a space, '+' or '-',
// a blank line, an @@ line and "*** End of File" are hunk content: the edited
// file's own text, never a header. Reading them as headers turned an unchanged
// README line that looked like one into a BLOCK on a README edit (Codex pass
// 1 on #4263). Every other line is matched as a header after trimming padding
// and ignoring case. A parser that tolerates either cannot then apply a write
// this did not see, and one that does not refuses the patch, so the lenient
// read costs nothing.
func patchTargets(patch string) []string {
	var out []string
	inUpdate := false
	for _, raw := range strings.Split(patch, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if inUpdate && (line == "" || strings.ContainsAny(line[:1], " +-") ||
			strings.HasPrefix(line, "@@") || strings.EqualFold(strings.TrimSpace(line), "*** End of File")) {
			continue
		}
		header := strings.TrimSpace(line)
		inUpdate = false
		for _, p := range patchHeaderPrefixes {
			if len(header) >= len(p) && strings.EqualFold(header[:len(p)], p) {
				if path := strings.TrimSpace(header[len(p):]); path != "" {
					out = append(out, path)
				}
				inUpdate = p == "*** Update File:" || p == "*** Move to:"
				break
			}
		}
	}
	return out
}

// inManagedConfigDir reports whether a write to p could land in
// ~/.agentshield. A relative path resolves against cwd and a leading ~ is
// expanded. Whether a harness normalises the path before writing is its own
// business, so both answers count:
//
//   - lexical: filepath.Clean(p) is in the directory. That is where a harness
//     that normalises the string first (as path.resolve does) writes.
//   - the OS's: p resolved the way the kernel resolves it, component by
//     component, a symlink replaced by its target before a following ".." is
//     applied (resolveWritePath). The directory is then found by file
//     identity, not by spelling (os.SameFile on the resolved path's
//     ancestors). That recognises a link into the directory, a link followed
//     by "..", a dangling link the write would create through, a case
//     variant on a case-insensitive volume (the macOS default), and a macOS
//     firmlink such as /System/Volumes/Data/Users/…, each only where the
//     filesystem really resolves it. On a case-sensitive volume
//     ~/.AgentShield is another directory and is not refused.
//
// The walk is over the RESOLVED path, which holds no "..". Walking the
// spelling's own prefixes treated a component the path merely passes through
// as an ancestor, so <config>/../outside.txt was blocked (Codex pass 2 on
// #4263).
//
// Honest limit: a file outside the directory that is a HARD link to one
// inside it is not recognised. Creating that link is a shell access to the
// config, so it is the shell layers' to refuse, with their own limits.
func inManagedConfigDir(p, cwd, home string) bool {
	_, ok := managedConfigDirRel(p, cwd, home)
	return ok
}

// managedConfigDirRel is inManagedConfigDir, and the path of the file the
// write lands on relative to the directory ("." for the directory itself),
// slash-separated. The relative path comes from the reading that found the
// directory: the cleaned spelling when that is in it, otherwise the resolved
// path below the ancestor that is the directory. ok is exactly
// inManagedConfigDir's answer.
func managedConfigDirRel(p, cwd, home string) (rel string, ok bool) {
	if p == "" || home == "" {
		return "", false
	}
	// Concatenated, not filepath.Join: Join cleans, and the OS reading needs
	// the path as written.
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = home + p[1:]
	}
	if !filepath.IsAbs(p) {
		if cwd == "" {
			cwd, _ = os.Getwd()
		}
		p = cwd + string(filepath.Separator) + p
	}
	dir := filepath.Join(home, ".agentshield")
	if clean := filepath.Clean(p); pathWithin(clean, dir) {
		return relSlash(dir, clean), true
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return "", false
	}
	return ancestorRel(resolveWritePath(p, 0), dirInfo)
}

// pathWithin reports whether p is d or below d, on cleaned paths.
func pathWithin(p, d string) bool {
	return p == d || strings.HasPrefix(p, strings.TrimSuffix(d, string(filepath.Separator))+string(filepath.Separator))
}

// ancestorRel walks a clean path p and its parents and reports whether any
// that exists is the same file as dir, with p relative to that ancestor.
func ancestorRel(p string, dir os.FileInfo) (string, bool) {
	for a := p; ; {
		if fi, err := os.Stat(a); err == nil && os.SameFile(fi, dir) {
			return relSlash(a, p), true
		}
		parent := filepath.Dir(a)
		if parent == a {
			return "", false
		}
		a = parent
	}
}

// relSlash is p relative to its ancestor base, slash-separated.
func relSlash(base, p string) string {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return "."
	}
	return filepath.ToSlash(rel)
}

// toolWriteTarget classifies a write that lands on rel inside the config
// directory: the log when the community overwrite rule matches a copy onto
// ~/.agentshield/<rel>, and config otherwise, including when that rule is
// missing from the embedded packs (TestAuditLogOverwriteSetComesFromCommunityPack
// fails the build then).
func toolWriteTarget(rel string) spTarget {
	return toolWriteTargetWith(rel, auditLogOverwriteSet())
}

// toolWriteTargetWith is the body, with the log-path set injected so the
// absent-rule fallback is testable (#4670 pass 1, F2–F4): a nil set means the
// write is tampering, never the log node.
func toolWriteTargetWith(rel string, overwrite *regexp.Regexp) spTarget {
	if overwrite != nil && rel != "." &&
		overwrite.MatchString("cp /dev/null ~/.agentshield/"+rel) {
		return spTargetLog
	}
	return spTargetConfig
}

// resolveWritePath returns the clean path of the file a write to p, spelled
// exactly as written, lands on. The longest existing prefix is resolved by
// filepath.EvalSymlinks, which applies a ".." to the resolved prefix as the
// kernel does. The rest is appended, and a dangling symlink at p is followed
// to the file the write would create. Prefixes are cut at the last separator,
// never cleaned, so each is the spelling the OS would see. depth bounds a
// chain of dangling links.
func resolveWritePath(p string, depth int) string {
	if depth > 8 {
		return filepath.Clean(p)
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	sep := string(filepath.Separator)
	i := strings.LastIndex(p, sep)
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(p)
		if err != nil || i < 0 {
			return filepath.Clean(p)
		}
		if !filepath.IsAbs(target) {
			target = p[:i] + sep + target
		}
		return resolveWritePath(target, depth+1)
	}
	if i <= 0 {
		return filepath.Clean(p)
	}
	return filepath.Join(resolveWritePath(p[:i], depth), p[i+1:])
}

// managedConfigToolWrite returns the BLOCK for a harness write-tool call that
// targets the config directory on a managed host, and false otherwise. Like
// the shell middleware, it runs before any policy is loaded and is not
// lowered by audit-only mode.
func managedConfigToolWrite(toolName string, arguments map[string]interface{}, fromText bool, cwd string) (mcp.MCPEvalResult, bool) {
	targets := harnessWriteTargets(toolName, arguments, fromText)
	if len(targets) == 0 {
		return mcp.MCPEvalResult{}, false
	}
	if m := enterprise.LoadManagedConfig(); m == nil || !m.Managed {
		return mcp.MCPEvalResult{}, false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return mcp.MCPEvalResult{}, false
	}
	// The reason names the first target in the directory, as before. The
	// receipt carries the node of every target in it, each once: a patch that
	// rewrites the log and the policy attests both.
	first := ""
	var classes spTarget
	for _, t := range targets {
		if rel, ok := managedConfigDirRel(t, cwd, home); ok {
			if first == "" {
				first = t
			}
			classes |= toolWriteTarget(rel)
		}
	}
	if first == "" {
		return mcp.MCPEvalResult{}, false
	}
	return mcp.MCPEvalResult{
		Decision:       policy.DecisionBlock,
		TriggeredRules: []string{"enterprise-self-protect"},
		Reasons: []string{"Blocked: attempt to modify AgentShield configuration (rule: " + selfProtectToolWriteRule +
			") — " + toolName + " targets " + first + " in the managed config directory"},
		TaxonomyRefs: spTargetRefs(classes),
	}, true
}
