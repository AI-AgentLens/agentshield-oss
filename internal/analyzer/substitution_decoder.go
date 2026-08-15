package analyzer

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Constant-decoder pipeline folding for Layer 2.5 (#1699).
//
// AgentShield's protected-path policy is defeated by the trivial obfuscation
// of feeding a base64- or hex-encoded path through a decoder in a command
// substitution:
//
//	cat $(echo fi8uc3NoL2lkX3JzYQ== | base64 -d)
//
// The structural and substitution layers see only an opaque CmdSubst — the
// decoded value (`~/.ssh/id_rsa`) never appears as a literal token. This file
// adds in-process folding for a whitelisted set of decoder pipelines whose
// input is statically constant. We deliberately stay narrow: the goal is to
// surface the decoded path so the existing protected-path policy can act,
// not to build a general-purpose shell evaluator.
//
// The whitelist is small on purpose. Each entry is a hand-coded reduction
// that mirrors the runtime semantics of one tool, with no flags or modes
// beyond the canonical decode form. If a real attack surfaces using `tr`,
// `rev`, or `printf '\xNN'`, extend this whitelist with the same care —
// every wrong fold becomes a false BLOCK that breaks legitimate scripts.
//
// Non-constant decoder inputs (e.g., piping a file or unknown var into a
// decoder) are handled separately by the Guardian companion heuristic, which
// raises AUDIT — see #1699 plus the Guardian rule.

// decoderName captures the recognized decoders. Centralizing the set lets
// the Guardian companion heuristic key off the same names without
// duplicating the parser.
var recognizedDecoders = map[string]decodeFunc{
	// `base64 -d` (GNU, BSD/macOS w/ -d), `base64 --decode` (GNU long form),
	// `base64 -D` (BSD short form). All three decode standard base64.
	"base64": decodeBase64,
	// `xxd -r -p` reverses a plain (no-address, no-ASCII) hex dump back to
	// bytes. The -r flag is reverse, -p is plain.
	"xxd": decodeHex,
}

// IsRecognizedDecoder reports whether a command name is in the decoder
// whitelist. Exported so the Guardian companion analyzer can detect
// decoder-fed sinks without duplicating this list.
func IsRecognizedDecoder(name string) bool {
	_, ok := recognizedDecoders[name]
	return ok
}

type decodeFunc func(input string) (string, bool)

// tryFoldDecoderPipeline attempts to evaluate a CmdSubst as a constant
// decoder pipeline. Supported shape:
//
//	$( <source> | <decoder> )
//
// where <source> is `echo CONST`, `echo -n CONST`, or `printf '%s' CONST`
// (CONST may itself reference a known var via the symbol table), and
// <decoder> is one of the entries in recognizedDecoders.
//
// Single-command shapes (`$(base64 -d <<< CONST)`) are deliberately not
// supported in v1 — herestrings add another parse path and the pipe form is
// what every demo of this attack uses. If the fold fails for any reason,
// returns ok=false and the caller stays with the existing "can't materialize
// this CmdSubst" behavior.
func tryFoldDecoderPipeline(cs *syntax.CmdSubst, syms map[string]string) (string, bool) {
	if cs == nil || len(cs.Stmts) != 1 {
		// Multi-statement substitution like `$(a; b)` is too far from a
		// decoder pipeline to fold safely.
		return "", false
	}
	stmt := cs.Stmts[0]
	if stmt == nil || stmt.Cmd == nil {
		return "", false
	}

	bin, ok := stmt.Cmd.(*syntax.BinaryCmd)
	if !ok || bin.Op != syntax.Pipe {
		// Not a pipeline. Other shapes (single decoder reading from
		// herestring, redirect from file) aren't supported in v1.
		return "", false
	}
	if bin.X == nil || bin.Y == nil {
		return "", false
	}

	// Only handle exactly two-stage pipelines for now. `echo X | rot | dec`
	// would require chaining multiple decode rounds; v1 stays narrow.
	if _, isNested := bin.X.Cmd.(*syntax.BinaryCmd); isNested {
		return "", false
	}

	source, ok := evalConstSource(bin.X, syms)
	if !ok {
		return "", false
	}
	decoded, ok := applyDecoderStmt(bin.Y, source)
	if !ok {
		return "", false
	}
	return decoded, true
}

// evalConstSource extracts a constant input string from the source side of
// the pipeline. Recognized:
//
//	echo CONST
//	echo -n CONST
//	echo -ne CONST   # -e is no-op for our purposes (no escapes in plain str)
//	printf '%s' CONST
//	printf '%b' CONST
//
// Multiple positional args are concatenated with spaces (matching `echo`'s
// runtime behavior). The CONST itself goes through materializeWord, so
// `echo $B64` works when B64 is in the symbol table.
//
// We do NOT execute interpreted escapes in `echo -e CONST` or `printf '%b'`
// — those would require a tiny bash-escape parser, and treating them as
// literal is the safe (false-negative) direction. If a real attack uses
// printf '%b' to hide bytes, we'll add escape handling then.
func evalConstSource(stmt *syntax.Stmt, syms map[string]string) (string, bool) {
	if stmt == nil {
		return "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return "", false
	}
	// Reject any redirects on the source — they change semantics.
	if len(stmt.Redirs) > 0 {
		return "", false
	}
	if len(call.Assigns) > 0 {
		// `FOO=bar echo X` — env override, weird in this position, bail.
		return "", false
	}
	if len(call.Args) == 0 {
		return "", false
	}
	cmdName, ok := materializeWord(call.Args[0], syms)
	if !ok {
		return "", false
	}

	args, ok := materializeWords(call.Args[1:], syms)
	if !ok {
		return "", false
	}

	switch cmdName {
	case "echo":
		// Strip leading -n / -e / -ne / -E flag bundles. We treat them all
		// as a single "consume one flag arg" — the differences (newline
		// suppression, escape interpretation) don't change the bytes
		// downstream decoders care about.
		args = stripEchoFlags(args)
		return strings.Join(args, " "), true
	case "printf":
		// `printf '%s' X` or `printf '%b' X` — first arg is format, rest
		// are data. We only handle the format strings that pass through
		// the data unchanged.
		if len(args) < 2 {
			return "", false
		}
		switch args[0] {
		case "%s", "%b":
			return strings.Join(args[1:], ""), true
		}
		return "", false
	}
	return "", false
}

// stripEchoFlags drops leading flag args (-n, -e, -E, -nE, -ne, etc.). echo
// in bash is wonky — bash's builtin treats "-n" as a flag, but most external
// echo binaries don't. For our purposes (passing the rest as bytes to a
// decoder), the flags don't matter.
func stripEchoFlags(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		if len(a) < 2 || a[0] != '-' {
			break
		}
		// Must be entirely flag characters (n, e, E) to count as a flag bundle.
		// Anything else (like `-foo` or `-`) is treated as data.
		isFlag := true
		for _, c := range a[1:] {
			if c != 'n' && c != 'e' && c != 'E' {
				isFlag = false
				break
			}
		}
		if !isFlag {
			break
		}
		args = args[1:]
	}
	return args
}

// materializeWords reduces a slice of Words to their concrete strings. If
// any word fails to materialize, returns ok=false — the caller bails on the
// whole pipeline rather than silently producing partial input.
func materializeWords(words []*syntax.Word, syms map[string]string) ([]string, bool) {
	out := make([]string, 0, len(words))
	for _, w := range words {
		val, ok := materializeWord(w, syms)
		if !ok {
			return nil, false
		}
		out = append(out, val)
	}
	return out, true
}

// applyDecoderStmt applies a decoder command (the right-hand side of the
// pipe) to the source input. The decoder must be a CallExpr whose first arg
// is a recognized decoder name AND whose flags match the canonical decode
// form for that decoder. Any unrecognized flag bails — narrowing the surface
// is the whole point.
func applyDecoderStmt(stmt *syntax.Stmt, input string) (string, bool) {
	if stmt == nil {
		return "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return "", false
	}
	if len(stmt.Redirs) > 0 {
		// `... | base64 -d > /tmp/x` writes to a file rather than producing
		// the decoded value into the CmdSubst — different semantics, bail.
		return "", false
	}
	if len(call.Args) == 0 {
		return "", false
	}
	name, ok := materializeWord(call.Args[0], nil)
	if !ok {
		return "", false
	}
	dec, ok := recognizedDecoders[name]
	if !ok {
		return "", false
	}

	flags, _ := materializeWords(call.Args[1:], nil)
	if !flagsMatchDecoder(name, flags) {
		return "", false
	}
	return dec(input)
}

// flagsMatchDecoder enforces the canonical-form-only rule per decoder. A
// pipeline that spells the decoder differently (e.g., `base64` with no
// flags = encode) is intentionally rejected.
func flagsMatchDecoder(name string, flags []string) bool {
	set := make(map[string]struct{}, len(flags))
	for _, f := range flags {
		set[f] = struct{}{}
	}
	switch name {
	case "base64":
		// Accept any of: -d, --decode, -D (BSD short form). Reject the
		// no-flag form (that's encode, not decode).
		if _, ok := set["-d"]; ok {
			return len(set) == 1
		}
		if _, ok := set["--decode"]; ok {
			return len(set) == 1
		}
		if _, ok := set["-D"]; ok {
			return len(set) == 1
		}
		return false
	case "xxd":
		// `xxd -r -p` is the canonical reverse-plain-hex form. Both flags
		// are required: -r alone reads address-prefixed hex, -p alone is
		// still encode. Accept the combined `-rp` and `-pr` forms too.
		hasR := false
		hasP := false
		for f := range set {
			switch f {
			case "-r":
				hasR = true
			case "-p":
				hasP = true
			case "-rp", "-pr":
				hasR = true
				hasP = true
			default:
				return false
			}
		}
		return hasR && hasP
	}
	return false
}

// decodeBase64 decodes standard base64 with optional padding leniency. The
// runtime tools are forgiving about whitespace and padding; we mirror that.
func decodeBase64(input string) (string, bool) {
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, input)
	out, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		// Try the URL-safe variant before giving up — some scripts encode
		// with -url flavor even when piping to vanilla base64 -d.
		out, err = base64.URLEncoding.DecodeString(cleaned)
		if err != nil {
			// Try raw (no padding) variants.
			if alt, e := base64.RawStdEncoding.DecodeString(cleaned); e == nil {
				return string(alt), true
			}
			if alt, e := base64.RawURLEncoding.DecodeString(cleaned); e == nil {
				return string(alt), true
			}
			return "", false
		}
	}
	return string(out), true
}

// decodeHex decodes plain hex. xxd's -p mode tolerates whitespace inside
// the hex stream (it's how multi-line dumps are reversed).
func decodeHex(input string) (string, bool) {
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, input)
	out, err := hex.DecodeString(cleaned)
	if err != nil {
		return "", false
	}
	return string(out), true
}
