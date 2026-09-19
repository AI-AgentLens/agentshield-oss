package analyzer

import (
	"regexp"
	"strings"
)

// File-access literals inside interpreter one-liners (#3620, general).
//
// Layer 2.5 materializes whole argv words. For an interpreter one-liner the
// whole word is the script — `print(open('~/.ssh/id_rsa').read())` — which is
// not a path, so the protected-path check never matched it. Measured through
// the real hook on 2026-09-02 with protected_paths ["~/.ssh/**"]:
//
//	P=$HOME/.ssh; python3 -c "print(open('$P/id_rsa').read())"     exit 0
//	python3 -c "print(open('$HOME/.ssh/id_rsa').read())"           exit 0
//	CFG=$HOME/.agentshield; python3 -c "open('$CFG/policy.yaml','w')…"  exit 0
//
// extractFileCallPaths pulls the quoted path literals out of a materialized
// word, but ONLY when they are arguments to a call that opens, reads, writes,
// copies, moves or deletes a file. That gate is what keeps this from
// re-creating the doc-text false positive the community rules were narrowed
// for: `python3 -c "print('see ~/.ssh/id_rsa')"` names the path and touches
// nothing, and it is not extracted; `sys.stdout.write('~/.ssh/id_rsa')` is
// not on the list either. The list is language-agnostic on purpose — one
// gate for Python, Perl, Ruby, Node, PHP and Deno spellings — and it is a
// closed allowlist: a name is added when a real bypass shows it is needed,
// not speculatively.
//
// Relative literals without a slash ('policy.yaml') are left to the
// normalizer, which already resolves them against a tracked `cd`.
var fileCallRe = regexp.MustCompile(
	`\b(?:open|io\.open|os\.open|fopen|pathlib\.Path|Path` +
		`|fs\.(?:readFile|writeFile|appendFile|createReadStream|createWriteStream|readFileSync|writeFileSync|appendFileSync|unlinkSync|renameSync|copyFileSync)` +
		`|readFileSync|writeFileSync|appendFileSync` +
		`|File\.(?:open|read|write|readlines|new|delete|rename|binread|binwrite)` +
		`|IO\.(?:read|readlines|write|foreach|binread)` +
		`|os\.(?:remove|unlink|rename|replace|chmod|chown|readlink|symlink|link)` +
		`|shutil\.(?:copy|copyfile|copy2|move|rmtree)` +
		`|Deno\.(?:readTextFile|writeTextFile|readFile|writeFile|remove)` +
		`|file_get_contents|file_put_contents|unlink)` +
		`\s*\(([^)]*)\)`)

var quotedLiteralRe = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)

// extractFileCallPaths returns the quoted literals that are arguments to a
// file-access call in s and look like filesystem paths (contain a slash or
// start with ~). Order is preserved; duplicates are kept for the caller to
// dedupe alongside the rest of MaterializedPaths.
func extractFileCallPaths(s string) []string {
	if !strings.Contains(s, "(") {
		return nil
	}
	var out []string
	for _, call := range fileCallRe.FindAllStringSubmatch(s, -1) {
		for _, lit := range quotedLiteralRe.FindAllStringSubmatch(call[1], -1) {
			v := lit[1]
			if v == "" {
				v = lit[2]
			}
			if v == "" {
				continue
			}
			if !strings.Contains(v, "/") && !strings.HasPrefix(v, "~") {
				continue
			}
			out = append(out, v)
		}
	}
	return out
}
