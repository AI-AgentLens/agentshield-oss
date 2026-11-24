package policy

import (
	"slices"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The consumer table's second question (#5021 P-c, pass 2): does the command
// read a protected file anywhere OTHER than the credential slots it credits?
//
// protectedPathConsumerOnly's count compares two lists that are not one per
// read. normalize's paths drop a `--name=value` reading whose path the segment
// already listed, so `kubectl --kubeconfig K create secret generic x
// --from-file=../.kube/config` and a slot written twice beside `cat config`
// left a slot's credit free for a real read; the substitution analyzer's paths
// were not in the count at all, so `D=$HOME; ssh -i K host; cp
// $D/.aws/credentials /tmp/o` was the consumer's AUDIT; and a slot normalize
// never lists (spelled `$HOME/...`) was a credit with no entry. Counting
// harder cannot close that: neither list says which word an entry came from.
//
// So the question is asked of the command with the credited slots taken out.
// Each word the table credits is replaced by an empty word (`--name=` keeps
// its option name), and the text is read the way the hook reads a command:
// normalize's paths and, with the analyzer pipeline, the substitution
// analyzer's materialized paths. A slot accounts for its own word and nothing
// else, whatever either reader does with duplicates, and every other read
// they see is a read the slots do not account for.
//
// It only ever makes a command not consumer-only, so it only raises. A
// command bash cannot parse keeps the count's decision (the zsh reading
// re-evaluates such a command as bash text).
//
// Not reached: a read normalize never lists, inside `bash -c`, `eval`, `xargs`
// or a `$(...)` body it does not read (finding Z). The same read alone is not
// a protected-path BLOCK either; that is the separate opaque-executor gap.

// slotFreeText returns command with every word the consumer table credits
// replaced by an empty word, and false when it cannot be built: bash does not
// parse the command, or a credited word's position is not in the text.
//
// Slots are found as protectedPathConsumerOnly's walk finds them: a call's
// words after its execution wrappers (shellparse.StripExecWrappers), the
// executable named as shellparse names it, a credential slot of that
// consumer (isConsumerSlot) whose word is a protected path (protectedToken).
// A call this reading cannot line up with its words is left as written, so
// its slots stay reads: a missed slot can only raise.
func (e *Engine) slotFreeText(command, cwd string, foldCase bool) (string, bool) {
	consumers := e.policy.Defaults.ProtectedPathConsumers
	file, err := shellparse.ParseText(command, syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	if err != nil {
		return "", false
	}
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	bad := false
	syntax.Walk(file, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, w := range call.Args {
			words[i] = shellparse.WordToString(w)
		}
		post := shellparse.StripExecWrappers(words)
		off := len(words) - len(post)
		if len(post) == 0 || off < 0 || !slices.Equal(post, words[off:]) {
			return true
		}
		c := consumerFor(consumers, shellparse.NormalizeExecName(post[0]))
		if c == nil {
			return true
		}
		for i := 1; i < len(post); i++ {
			if !isConsumerSlot(c, post, i) {
				continue
			}
			if _, hit := e.protectedToken(post[i], cwd, foldCase); !hit {
				continue
			}
			w := call.Args[off+i]
			start, end := int(w.Pos().Offset()), int(w.End().Offset())
			if start < 0 || end <= start || end > len(command) {
				bad = true
				return false
			}
			text := "''"
			if strings.HasPrefix(post[i], "-") {
				text = post[i][:strings.IndexByte(post[i], '=')+1] + "''"
			}
			edits = append(edits, edit{start, end, text})
		}
		return true
	})
	if bad {
		return "", false
	}
	// A slot inside another slot's word (`ssh -i "$(ssh -i K h cat k)" h`)
	// goes with the outer word.
	sort.Slice(edits, func(i, j int) bool {
		if edits[i].start != edits[j].start {
			return edits[i].start < edits[j].start
		}
		return edits[i].end > edits[j].end
	})
	var sb strings.Builder
	at := 0
	for _, ed := range edits {
		if ed.start < at {
			continue
		}
		sb.WriteString(command[at:ed.start])
		sb.WriteString(ed.text)
		at = ed.end
	}
	sb.WriteString(command[at:])
	return sb.String(), true
}

// slotFreeReads reports whether command, with its credited consumer slots
// taken out (slotFreeText), still names a protected path in normalize's
// reading, and false when that reading cannot be made.
func (e *Engine) slotFreeReads(command, cwd string, foldCase bool) (reads, ok bool) {
	text, ok := e.slotFreeText(command, cwd, foldCase)
	if !ok {
		return false, false
	}
	blocked, _ := e.checkProtectedPaths(normalize.NormalizeCommand(text, cwd).Paths, cwd, foldCase)
	return blocked, true
}

// slotFreePaths returns normalize's paths for command with its credited
// consumer slots taken out (slotFreeText): the reads no slot accounts for.
// nil when the command credits no slot, or the text cannot be built.
func (e *Engine) slotFreePaths(command, cwd string, foldCase bool) []string {
	text, ok := e.slotFreeText(command, cwd, foldCase)
	if !ok || text == command {
		return nil
	}
	return normalize.NormalizeCommand(text, cwd).Paths
}

// slotFreeMaterialized returns the paths the substitution analyzer
// materializes from command with its credited consumer slots taken out
// (slotFreeText): the variable-built reads no slot accounts for. nil without
// the analyzer pipeline, when the pipeline runs no substitution analyzer, or
// when the slot-free text cannot be built.
func (e *Engine) slotFreeMaterialized(command, cwd string, foldCase bool) []string {
	if e.registry == nil {
		return nil
	}
	var sub analyzer.Analyzer
	for _, a := range e.registry.Analyzers() {
		if a.Name() == "substitution" {
			sub = a
			break
		}
	}
	if sub == nil {
		return nil
	}
	text, ok := e.slotFreeText(command, cwd, foldCase)
	if !ok {
		return nil
	}
	ctx := &analyzer.AnalysisContext{RawCommand: text, Cwd: cwd, Home: e.homeDir}
	sub.Analyze(ctx)
	return ctx.MaterializedPaths
}
