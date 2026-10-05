package policy

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/mountspec"
	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// Designated consumers of protected paths (#3620 follow-up, 2026-09-02).
//
// protected_paths means "no command may name these paths". Measured on main
// with the shipped defaults, that blocked every legitimate consumer of a
// credential — `ssh -i ~/.ssh/id_ed25519 host`, `scp -i …`, `ssh-add …`,
// `kubectl --kubeconfig ~/.kube/config …`, `gpg --homedir ~/.gnupg …` — while
// the same tools read the same files implicitly (`kubectl get pods`) without
// a word. A consumer using its credential is not exfiltration; it is the
// event an attestation should record. So a protected path that appears ONLY
// as a designated consumer's credential slot is downgraded from BLOCK to a
// flagged AUDIT carrying rule id protected-path-consumer. Any other
// occurrence — a reader (`cat`), an interpreter call (`open()`), a copier
// with the key as a SOURCE operand (`scp ~/.ssh/id_rsa host:`), a redirect
// target — keeps the BLOCK.
//
// The slot is flag-position-aware because the same executable can be both:
// `scp -i key file host:` consumes the key, `scp key host:` copies it out.
// Positional use is opted into per consumer (ssh-add). The table is data
// (defaults.protected_path_consumers); users may add consumers, not remove.
//
// 2026-09-06 (#3630): a consumer's credential slot can also be an ENVIRONMENT
// variable — `export KUBECONFIG=~/.kube/config` is exactly what
// `kubectl --kubeconfig ~/.kube/config` is, spelled the way the tool
// documents it. Those names live in the same table's `env:` column and are
// handled by ProtectedEnvAssignment below. The two halves differ in one
// important way: a flag slot is a USE of the credential and can therefore
// substitute for a BLOCK, whereas an assignment is not a use at all, so it
// only ever ADDS a record — it can never downgrade someone else's block.

// ProtectedPathConsumer names executables that may legitimately take a
// protected path as a credential, and where that path may appear.
type ProtectedPathConsumer struct {
	// Executable is the base command name(s) this entry applies to.
	Executable []string `yaml:"executable"`
	// Flags whose value (next word, or `--flag=value`) is the credential.
	// Short flags match as the LAST letter of a cluster: `-vi key`.
	Flags []string `yaml:"flags,omitempty"`
	// Positional allows the credential as a bare operand (ssh-add ~/.ssh/id).
	Positional bool `yaml:"positional,omitempty"`
	// Env names environment variables that ARE this consumer's credential
	// slot — the same relationship as Flags, expressed the way the tool's
	// own documentation expresses it (`KUBECONFIG`, `GNUPGHOME`). An
	// assignment of a protected path to one of these is recorded, never
	// blocked (#3630). Unlike Flags this is not tied to Executable: the
	// assignment and the use are routinely separate commands, separate
	// scripts, or separate shells, so there is nothing to correlate against.
	Env []string `yaml:"env,omitempty"`
}

// ProtectedPathConsumerRuleID is the sentinel rule id on the AUDIT produced
// when a protected path is used only by its designated consumer.
const ProtectedPathConsumerRuleID = "protected-path-consumer"

// defaultProtectedPathConsumers is the shipped table. Keep it to tools whose
// ONLY relationship with the credential is consuming it through the named
// slot; a tool that can also copy the file out (scp, rsync) must not get
// Positional.
func defaultProtectedPathConsumers() []ProtectedPathConsumer {
	return []ProtectedPathConsumer{
		{Executable: []string{"ssh", "scp", "sftp", "ssh-copy-id"}, Flags: []string{"-i", "-F"}},
		{Executable: []string{"ssh-keygen"}, Flags: []string{"-f"}},
		{Executable: []string{"ssh-add"}, Positional: true},
		{Executable: []string{"kubectl", "helm"}, Flags: []string{"--kubeconfig"}, Env: []string{"KUBECONFIG"}},
		{Executable: []string{"gpg", "gpg2", "gpgconf"}, Flags: []string{"--homedir"}, Env: []string{"GNUPGHOME"}},
		// Cloud CLIs express the same credential slot ONLY through the
		// environment — there is no `aws --credentials-file`. Executable is
		// listed for documentation; it contributes no flag slot.
		{Executable: []string{"aws"}, Env: []string{"AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"}},
		{Executable: []string{"gcloud"}, Env: []string{"GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG"}},
	}
}

// ProtectedEnvAssignment reports the environment credential slot an
// assignment in this command filled with a protected path, if any (#3630).
//
// Why this is an AUDIT and not a BLOCK: the assignment reads nothing.
// `P=~/.kube/config` on its own has always been allowed and still is —
// blocking it would break every kubeconfig-switching workflow while stopping
// no read (the read, `cat $KUBECONFIG`, is caught by the materialized-path
// post-pass and still BLOCKs). What the assignment DOES establish is the
// same relationship the flag form establishes: this path is about to be used
// as this tool's credential. #3625 records that as an event; before this it
// was an anonymous AUDIT with no rule id and therefore nothing an
// attestation could cite.
//
// Only variables named in the table qualify. A protected path assigned to an
// unlisted variable stays ignored rather than becoming a BLOCK — which is
// what makes the table's contents a coverage decision instead of a noise
// decision.
func (e *Engine) ProtectedEnvAssignment(assignments []analyzer.Assignment) (string, bool) {
	return e.protectedEnvAssignment(assignments, false)
}

// protectedEnvAssignment is ProtectedEnvAssignment with #4194's folded
// reading selectable (see isProtectedToken).
func (e *Engine) protectedEnvAssignment(assignments []analyzer.Assignment, foldCase bool) (string, bool) {
	consumers := e.policy.Defaults.ProtectedPathConsumers
	if len(consumers) == 0 || len(assignments) == 0 {
		return "", false
	}
	for _, a := range assignments {
		if a.Name == "" || !envIsCredentialSlot(consumers, a.Name) {
			continue
		}
		if e.isProtectedToken(a.Value, foldCase) {
			return a.Name, true
		}
		// A credential slot can hold a LIST. KUBECONFIG is documented as
		// colon-separated and kubectl merges every entry, so a protected path
		// in the second position is exactly the relationship the first
		// position establishes — but `/tmp/a:~/.kube/config` is one word and
		// matches no glob, so the record was silently skipped (#3706). Only
		// ever adds an AUDIT record; it can never produce or suppress a BLOCK.
		if !strings.Contains(a.Value, ":") {
			continue
		}
		for _, part := range strings.Split(a.Value, ":") {
			if part == "" {
				continue
			}
			if e.isProtectedToken(part, foldCase) {
				return a.Name, true
			}
		}
	}
	return "", false
}

// envIsCredentialSlot reports whether name is declared as some consumer's
// environment credential slot. Matched case-sensitively: shell variables are
// case-sensitive and `kubeconfig=` is not `KUBECONFIG=`.
func envIsCredentialSlot(consumers []ProtectedPathConsumer, name string) bool {
	for i := range consumers {
		for _, env := range consumers[i].Env {
			if env == name {
				return true
			}
		}
	}
	return false
}

// protectedPathConsumerOnly reports whether every word in the command that
// resolves to a protected path sits in a designated consumer's credential
// slot, and at least one does. exe names the consumer for the audit reason.
// Anything that cannot be classified counts against the command: a segment
// whose words cannot be tokenized, a redirect target, a path reached through
// a variable the consumer slot does not spell out.
func (e *Engine) protectedPathConsumerOnly(command string, parsed *analyzer.ParsedCommand, foldCase bool) (ok bool, exe string) {
	consumers := e.policy.Defaults.ProtectedPathConsumers
	if len(consumers) == 0 {
		return false, ""
	}
	if parsed == nil {
		parsed = shellparse.Parse(command, 2)
	}
	if parsed == nil {
		return false, ""
	}

	consumerHits, otherHits := 0, 0
	var walk func(p *analyzer.ParsedCommand)
	walk = func(p *analyzer.ParsedCommand) {
		for _, seg := range p.Segments {
			c := consumerFor(consumers, seg.Executable)
			words := segmentWords(seg.Raw)
			if words == nil {
				// Could not tokenize in order: fall back to the flattened view,
				// where no flag position is known, so nothing is a consumer slot.
				for _, a := range seg.Args {
					if e.isProtectedToken(a, foldCase) {
						otherHits++
					}
				}
				continue
			}
			for i := 1; i < len(words); i++ {
				if !e.isProtectedToken(words[i], foldCase) {
					continue
				}
				if c != nil && isConsumerSlot(c, words, i) {
					consumerHits++
					exe = seg.Executable
				} else {
					otherHits++
				}
			}
			// A container bind mount is never a designated consumer's
			// credential slot — the image is arbitrary code. Counting its
			// source here is what stops `ssh -i key host && docker run -v
			// <creddir>:/mnt img` from reaching otherHits == 0 and having
			// the mount downgraded along with the ssh (#3630). The token
			// loop above cannot see it: the spec `<creddir>:/mnt` is one
			// word and matches no glob.
			if mountspec.IsContainerRuntime(seg.Executable) {
				for _, src := range mountspec.Sources(words[1:]) {
					if e.isProtectedToken(src, foldCase) {
						otherHits++
					}
				}
			}
			for _, r := range seg.Redirects {
				if e.isProtectedToken(r.Path, foldCase) {
					otherHits++
				}
			}
		}
		for _, sub := range p.Subcommands {
			walk(sub)
		}
	}
	walk(parsed)
	return otherHits == 0 && consumerHits > 0, exe
}

func consumerFor(consumers []ProtectedPathConsumer, executable string) *ProtectedPathConsumer {
	for i := range consumers {
		for _, name := range consumers[i].Executable {
			if name == executable {
				return &consumers[i]
			}
		}
	}
	return nil
}

// isConsumerSlot reports whether words[i] is a credential slot of c: the
// value of one of c's flags (as the next word, or inline `--flag=value`), or
// any bare operand when c allows positional use.
func isConsumerSlot(c *ProtectedPathConsumer, words []string, i int) bool {
	w := words[i]
	if strings.HasPrefix(w, "-") {
		// `--kubeconfig=path`: the flag is the word itself.
		if eq := strings.IndexByte(w, '='); eq > 0 {
			return containsFlag(c.Flags, w[:eq])
		}
		return false
	}
	if i > 0 && flagTakesThisWord(c.Flags, words[i-1]) {
		return true
	}
	return c.Positional
}

// flagTakesThisWord reports whether prev is one of the consumer's flags,
// allowing a short flag to be the last letter of a cluster (`-vi`).
func flagTakesThisWord(flags []string, prev string) bool {
	if !strings.HasPrefix(prev, "-") || strings.Contains(prev, "=") {
		return false
	}
	if containsFlag(flags, prev) {
		return true
	}
	if !strings.HasPrefix(prev, "--") && len(prev) > 2 {
		last := "-" + prev[len(prev)-1:]
		return containsFlag(flags, last)
	}
	return false
}

func containsFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

// isProtectedToken resolves one command word the way a shell would spell the
// path — quote splices removed, a leading $HOME or ${HOME} read as ~ (the
// substitution analyzer folds the same), ~ expanded — and reports whether it
// falls under a protected_paths glob. Relative words are not candidates: every
// shipped glob is anchored at the home directory or the filesystem root.
//
// foldCase (#4194) compares with ASCII letter case folded on both sides. Set
// only inside EvaluateCaseFold's folded evaluation, so the consumer table can
// recognise a case-variant credential slot there (a variant `ssh -i <key>`
// stays AUDIT, as its canonical is) without ever acting on the as-written
// evaluation, where widening a BLOCK-to-AUDIT exemption could lower a verdict.
func (e *Engine) isProtectedToken(word string, foldCase bool) bool {
	cand := word
	if strings.HasPrefix(cand, "-") {
		eq := strings.IndexByte(cand, '=')
		if eq < 0 {
			return false
		}
		cand = cand[eq+1:]
	}
	cand = pathnorm.StripShellQuotes(cand)
	cand = strings.Trim(cand, `"'`)
	cand = pathnorm.FoldHomeVar(cand)
	expanded := e.expandPath(cand)
	if !filepath.IsAbs(expanded) {
		return false
	}
	expanded = filepath.Clean(expanded)
	if foldCase {
		expanded = pathnorm.FoldASCII(expanded)
	}
	for _, pattern := range e.policy.Defaults.ProtectedPaths {
		expandedPattern := e.expandPath(pattern)
		if foldCase {
			expandedPattern = pathnorm.FoldASCII(expandedPattern)
		}
		if matchGlob(expanded, expandedPattern) {
			return true
		}
	}
	return false
}

// segmentWords returns the words of one simple command in order, quotes kept
// (isProtectedToken strips them). nil when the segment does not parse or has
// no command word.
func segmentWords(raw string) []string {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(raw), "")
	if err != nil {
		return nil
	}
	var call *syntax.CallExpr
	syntax.Walk(file, func(n syntax.Node) bool {
		if call != nil {
			return false
		}
		if c, ok := n.(*syntax.CallExpr); ok {
			call = c
			return false
		}
		return true
	})
	if call == nil || len(call.Args) == 0 {
		return nil
	}
	printer := syntax.NewPrinter()
	words := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		var sb strings.Builder
		if err := printer.Print(&sb, w); err != nil {
			return nil
		}
		words = append(words, sb.String())
	}
	return words
}
