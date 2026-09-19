// Package main implements a CI guardrail that closes the Unicode-separator
// exact-key-lookup class BY CONSTRUCTION rather than by another sweep.
//
// THE CLASS (#3691 -> #3712 -> #3720). An MCP argument NAME is the one kind of
// identifier in this system the attacker both DECLARES and RESOLVES: the server
// advertises the parameter in its inputSchema, the model copies that key
// verbatim into tools/call, and the server reads it back. Nothing has to
// survive a parser, so `url` + U+00A0 is a working parameter that costs the
// attacker nothing — and an exact-key map index never finds it.
// unicode.RecoverRenderedText folds such a separator to an ASCII space, so even
// after recovery `"url "` becomes `"url "`, not `"url"`. Only
// normalizeFieldName (which STRIPS separators) resolves it, and resolveField is
// the ladder that applies it.
//
// WHY A LINT AND NOT A NINTH SWEEP. This exact shape — a fixed argument name
// indexed straight into the args map — has now been found at EIGHT live sites
// across four nights of review:
//
//	#3691 (PR #3711)  classifyArgNames                                    1 site
//	#3712 (PR #3714)  checkToolCallArgsAltFormSSRF, ScanDelegationContent,
//	                  ScanEmailWriteInjection                             3 sites
//	#3720 (this)      firstNonEmptyStringArg, firstURLOrigin,
//	                  extractSkillIdentity, argString                     4 sites
//
// Each sweep's PR described itself as closing the class; #3714's test file
// literally said "the fourth and last instance". Per the triple-defense
// convention (a violation recurring twice earns a gate, not another point fix),
// site nine should fail the build rather than wait for accident number five.
//
// WHAT IS FLAGGED. An index expression `M[K]` where M is an MCP arguments map
// and K is either a string literal or a plain identifier.
//
// "Arguments map" is decided by NAME plus shape, not by full type checking:
// an args-like field selector (`.Args`, `.Arguments`, or anything ending in
// Args/Arguments — #3727 pass-2 finding 3, so `.RawArgs`/`.toolArguments` is not
// a hiding place), a `map[string]interface{}` /
// `map[string]any` parameter or local whose name is args-like (args,
// arguments, or anything ending in Args/Arguments), or a local assigned
// straight from one of those (`a := params.Arguments`). That is the same
// boundary the issue's own sweep used (`grep -rnE 'args\[|Arguments\['`),
// with the AST supplying the write/self-iteration discrimination grep cannot.
//
// ONE step beyond name (#3727 finding 4b): a `map[string]any` PARAMETER whose
// name is NOT args-like is still flagged when it is indexed by a string
// PARAMETER of the same function — the pass-through lookup-helper shape
// `func lookup(m map[string]any, k string) any { return m[k] }`. A key that
// arrives as a parameter came from OUTSIDE the map, which is the whole class, so
// renaming the map to `m` must not launder the lookup past the gate. Such a map
// indexed by a LITERAL or a range variable is left alone, so JSON-Schema
// traversal (node["properties"], node[kw] over a keyword slice) stays clean.
//
// The map may also be asserted INLINE at the index position (#3740 finding 4):
// `args.(map[string]interface{})[key]`. An MCP arguments map arrives as
// interface{} often enough that this is a natural spelling, and it is the one
// shape carrying neither an identifier nor a selector where the gate looks — the
// two-statement form `m := args.(map[string]any); m[key]` was already caught by
// the alias pass, so dropping the local must not launder it. Both halves are
// checked: the asserted TYPE must be the arguments-map type (so
// `args.([]interface{})[i]` is a slice index, not a key lookup) and the OPERAND
// must be args-like by the same naming convention (so
// `node.(map[string]interface{})[keyword]` stays clean, for the JSON-Schema
// reason below).
//
// The alternative — flagging every `map[string]interface{}` index — was tried
// and rejected: it reports 19 sites, 12 of which are JSON Schema traversal
// (schema_walk.go, annotation_schema_coherence.go, description_scanner.go)
// where the keys are JSON Schema KEYWORDS. Respelling `properties` with a
// separator buys an attacker nothing, because then nothing downstream treats
// it as `properties` either. Twelve exemptions for a non-class would dilute
// the three that are real. The cost of the narrower boundary is stated
// honestly: a lookup through an args map held in a variable named neither
// args-like nor assigned from one is not seen.
//
// WHAT IS NOT, and why each exclusion is load-bearing:
//
//   - WRITES. `args[k] = v` builds a map; it resolves nothing. handler.go and
//     types.go both do this legitimately.
//   - SELF-ITERATION. `for k := range args { … args[k] … }` enumerates the
//     map's OWN keys, so a respelled key is visited under its own spelling.
//     hasPayloadArg is the canonical example. Only an index by a key that came
//     from somewhere else can miss. Recognised LEXICALLY (#3727 finding 4c): the
//     index must sit inside the body of the range over THAT map, so a later safe
//     `for k := range args` cannot excuse an earlier `for k := range names {
//     args[k] }` that happens to reuse the key name `k`.
//   - COMPUTED INDEXES are FLAGGED, never skipped. `args["u"+"rl"]`,
//     `args[key()]`, `args[strings.ToLower(k)]` — and, since #3727 pass-2,
//     `args[normalizeFieldName(k)]` too: normalizing the LOOKUP key does not
//     normalize the STORED key, so a normalized index still misses a disguised
//     key. The only correct mitigation is a resolver CALL (resolveField /
//     argFieldRecovered), not an index.
//
// THE ESCAPE HATCH, and why it is narrow. Three live sites are raw map indexes
// ON PURPOSE, and folding them would make things worse, not better:
//
//	structural.go        arguments["method"] — a presence probe that decides
//	                     whether to SYNTHESIZE a method from the tool name.
//	                     Resolving a respelled key here would let an attacker's
//	                     `method<NBSP>: "GET"` suppress the POST synthesis that
//	                     http_post implies.
//	sequence.go          call.Args[arg] under ArgumentNotContains — a NEGATIVE
//	                     predicate. Resolving MORE keys makes the exclusion match
//	                     more often, which switches the rule OFF. Same inversion
//	                     toolNameForms documents for ToolNameRegexExclude.
//	argfield_recover.go  args[key] — the EXACT fast path of argFieldRecovered,
//	                     the narrow exact-then-render-recovery resolver the four
//	                     #3720 sites (and extractNumericArg) now share. The raw
//	                     exact index IS the resolution here; the render-recovery
//	                     fallback in the same function closes the separator class
//	                     without importing resolveField's case-insensitive/
//	                     camelCase ladder, which would break ASCII parity (#3727).
//
// extractNumericArg (policy.go) USED to be the third exemption — a raw index
// with a recovery fallback that compared the recovered name with `==`, so it
// still missed a Unicode separator (`amount`+U+00A0). It was fixed to route
// through argFieldRecovered (#3727 finding 2) and no longer needs an exemption.
//
// So a site may opt out with `argmaplookup:allow <reason>` in a comment on the
// same line or immediately above. The reason is mandatory and its absence is an
// error: an undocumented exemption is the defect this whole family started as.
//
// Usage:
//
//	go run ./cmd/check-arg-map-lookups          # exit 1 on any unexcused site
//	go run ./cmd/check-arg-map-lookups -v       # also list the exemptions
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// allowDirective opts a single lookup out. It must be followed by a reason.
const allowDirective = "argmaplookup:allow"

// argsFieldNames are struct field names that hold an MCP arguments map. A
// selector on one of these is treated as an arguments map without needing the
// field's declared type, which would require full type checking.
var argsFieldNames = map[string]bool{
	"Args":      true,
	"Arguments": true,
}

// Finding is one unexcused raw arguments-map lookup.
type Finding struct {
	File string
	Line int
	Expr string
	Kind string // "string literal key" | "identifier key"
}

// Exemption is one lookup carrying a documented argmaplookup:allow directive.
type Exemption struct {
	File   string
	Line   int
	Expr   string
	Reason string
}

func main() {
	dir := flag.String("dir", "internal/mcp", "package directory to scan (non-recursive)")
	verbose := flag.Bool("v", false, "list documented exemptions as well as findings")
	flag.Parse()

	findings, exemptions, err := Check(os.DirFS("."), *dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-arg-map-lookups: %v\n", err)
		os.Exit(2)
	}

	if *verbose && len(exemptions) > 0 {
		fmt.Printf("%d documented exemption(s):\n", len(exemptions))
		for _, e := range exemptions {
			fmt.Printf("  %s:%d  %s  — %s\n", e.File, e.Line, e.Expr, e.Reason)
		}
		fmt.Println()
	}

	if len(findings) == 0 {
		fmt.Printf("check-arg-map-lookups: OK — no raw fixed-key arguments-map lookups in %s\n", *dir)
		return
	}

	fmt.Fprintf(os.Stderr, "check-arg-map-lookups: %d raw arguments-map lookup(s) — see #3691/#3712/#3720\n\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(os.Stderr, "  %s:%d  %s  (%s)\n", f.File, f.Line, f.Expr, f.Kind)
	}
	fmt.Fprintf(os.Stderr, `
An MCP argument NAME is attacker-declared AND attacker-resolved, so a key
carrying a Unicode separator ("url" + U+00A0) is a working parameter that an
exact-key map index silently misses — the rule then does not fire at all.

Fix: resolve through resolveField(args, name) (internal/mcp/structural.go),
which runs the exact -> case-insensitive -> normalizeFieldName ladder.

If a raw index is deliberate (a presence probe, a negative predicate, or a
deliberately narrower ladder), say so at the site:

    // %s <why a raw index is correct here>

`, allowDirective)
	os.Exit(1)
}

// Check scans every non-test .go file directly under dir (relative to fsys)
// and returns the unexcused lookups plus the documented exemptions.
func Check(fsys fs.FS, dir string) ([]Finding, []Exemption, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var (
		findings   []Finding
		exemptions []Exemption
	)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := fs.ReadFile(fsys, filepath.Join(dir, name))
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", name, err)
		}
		fileFindings, fileExemptions, err := CheckSource(filepath.Join(dir, name), src)
		if err != nil {
			return nil, nil, err
		}
		findings = append(findings, fileFindings...)
		exemptions = append(exemptions, fileExemptions...)
	}

	// A scan that parsed nothing is a vacuous gate, not a clean tree.
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no files under %s — refusing to report a vacuous pass", dir)
	}

	sortFindings(findings)
	return findings, exemptions, nil
}

// CheckSource analyses one Go source file. Exported so the self-test can drive
// it on synthetic sources without writing files into the tree.
func CheckSource(path string, src []byte) ([]Finding, []Exemption, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}

	allowed := allowedLines(fset, file)

	var (
		findings   []Finding
		exemptions []Exemption
	)

	// Each function (or function literal) gets its own scope of args-like
	// identifiers, so an unrelated `m` in another function cannot bleed in.
	ast.Inspect(file, func(n ast.Node) bool {
		var body *ast.BlockStmt
		var params *ast.FieldList
		switch fn := n.(type) {
		case *ast.FuncDecl:
			body, params = fn.Body, fn.Type.Params
		case *ast.FuncLit:
			body, params = fn.Body, fn.Type.Params
		default:
			return true
		}
		if body == nil {
			return true
		}

		names := argsMapIdents(params, body)
		helperMaps := helperMapParamIdents(params, names)
		keyParams := keyParamIdents(params, body)
		for _, hit := range rawLookups(fset, body, names, helperMaps, keyParams) {
			if reason, ok := allowed[hit.line]; ok {
				exemptions = append(exemptions, Exemption{
					File: path, Line: hit.line, Expr: hit.expr, Reason: reason,
				})
				continue
			}
			findings = append(findings, Finding{
				File: path, Line: hit.line, Expr: hit.expr, Kind: hit.kind,
			})
		}
		// Function literals are visited on their own; recursing here would
		// double-report their bodies under the enclosing function's scope.
		return true
	})

	return findings, exemptions, nil
}

// argsLikeName reports whether an identifier names an MCP arguments map by
// this package's convention: args, arguments, or any camelCase spelling ending
// in them (toolArgs, rawArguments, …).
func argsLikeName(name string) bool {
	lower := strings.ToLower(name)
	return lower == "args" || lower == "arguments" ||
		strings.HasSuffix(lower, "args") || strings.HasSuffix(lower, "arguments")
}

// isArgsMapType reports whether e is map[string]interface{} or map[string]any.
func isArgsMapType(e ast.Expr) bool {
	m, ok := e.(*ast.MapType)
	if !ok {
		return false
	}
	if k, ok := m.Key.(*ast.Ident); !ok || k.Name != "string" {
		return false
	}
	switch v := m.Value.(type) {
	case *ast.InterfaceType:
		return len(v.Methods.List) == 0
	case *ast.Ident:
		return v.Name == "any"
	}
	return false
}

// argsMapIdents collects the identifiers in one function that hold an MCP
// arguments map: an args-like-named parameter or local of the args map type,
// plus any local assigned straight from a known arguments map (so
// `a := params.Arguments` is tracked even though `a` is not args-like).
func argsMapIdents(params *ast.FieldList, body *ast.BlockStmt) map[string]bool {
	names := map[string]bool{}

	if params != nil {
		for _, f := range params.List {
			if !isArgsMapType(f.Type) {
				continue
			}
			for _, n := range f.Names {
				if argsLikeName(n.Name) {
					names[n.Name] = true
				}
			}
		}
	}

	// Two passes: aliases can only be resolved once the sources are known, and
	// an alias of an alias is one more pass. Two is enough for this package and
	// the loop is bounded, which matters more than chasing a fixed point.
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.ValueSpec:
				if isArgsMapType(s.Type) {
					for _, n := range s.Names {
						if argsLikeName(n.Name) {
							names[n.Name] = true
						}
					}
				}
			case *ast.AssignStmt:
				if len(s.Rhs) != 1 || len(s.Lhs) == 0 {
					return true
				}
				id, ok := s.Lhs[0].(*ast.Ident)
				if !ok {
					return true
				}
				// An alias of a known arguments map is an arguments map,
				// whatever it is called.
				if isArgsMapExpr(s.Rhs[0], names) {
					names[id.Name] = true
					return true
				}
				if !argsLikeName(id.Name) {
					return true
				}
				var typ ast.Expr
				switch rhs := s.Rhs[0].(type) {
				case *ast.TypeAssertExpr:
					typ = rhs.Type
				case *ast.CompositeLit:
					typ = rhs.Type
				case *ast.CallExpr:
					if fn, ok := rhs.Fun.(*ast.Ident); ok && fn.Name == "make" && len(rhs.Args) > 0 {
						typ = rhs.Args[0]
					}
				}
				if typ != nil && isArgsMapType(typ) {
					names[id.Name] = true
				}
			case *ast.TypeSwitchStmt:
				// switch m := x.(type) { case map[string]interface{}: … }
				assign, ok := s.Assign.(*ast.AssignStmt)
				if !ok || len(assign.Lhs) != 1 {
					return true
				}
				id, ok := assign.Lhs[0].(*ast.Ident)
				if !ok || !argsLikeName(id.Name) {
					return true
				}
				for _, stmt := range s.Body.List {
					clause, ok := stmt.(*ast.CaseClause)
					if !ok {
						continue
					}
					for _, t := range clause.List {
						if isArgsMapType(t) {
							names[id.Name] = true
						}
					}
				}
			}
			return true
		})
	}

	return names
}

// isArgsMapExpr reports whether e denotes an arguments map: a known identifier,
// a selector on an Args/Arguments field, or either of those asserted to the
// arguments-map type inline.
func isArgsMapExpr(e ast.Expr, names map[string]bool) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return names[x.Name]
	case *ast.SelectorExpr:
		// An arguments map carried on a struct field is recognised by the SAME
		// args-like naming convention as a local (args, arguments, or anything
		// ending in Args/Arguments) — not just the exact Args/Arguments. A field
		// named .RawArgs / .toolArguments is an arguments map that .Args-only
		// matching would miss (#3727 pass-2 finding 3), while a cache keyed by a
		// tool name (.cache, .SentinelRules) is left alone.
		return argsFieldNames[x.Sel.Name] || argsLikeName(x.Sel.Name)
	case *ast.TypeAssertExpr:
		// `args.(map[string]interface{})[key]` — an MCP arguments map arrives as
		// interface{} often enough that asserting it INLINE and indexing the
		// result is a natural spelling, and it is the one shape with no
		// identifier and no selector at the index position (#3740 finding 4).
		// `m := args.(map[string]any); m[key]` was already caught by the alias
		// pass in argsMapIdents; dropping the local must not launder the lookup.
		//
		// Two conditions, and both are load-bearing. The asserted TYPE must be
		// the arguments-map type, so `args.([]interface{})[i]` — an index into a
		// slice, not a key lookup — stays clean. And the OPERAND must be
		// args-like by the same naming convention used above, so JSON-Schema
		// traversal (`node.(map[string]interface{})[keyword]`, the schema_walk.go
		// family) stays clean: respelling a JSON Schema keyword buys an attacker
		// nothing, because then nothing downstream reads it as that keyword
		// either.
		if x.Type == nil || !isArgsMapType(x.Type) {
			return false // `x.(type)` in a type switch, or a non-map assertion
		}
		switch operand := x.X.(type) {
		case *ast.Ident:
			return names[operand.Name] || argsLikeName(operand.Name)
		case *ast.SelectorExpr:
			return argsFieldNames[operand.Sel.Name] || argsLikeName(operand.Sel.Name)
		}
		return false
	}
	return false
}

type lookup struct {
	line int
	expr string
	kind string
}

// rawLookups finds every read of an arguments map by a string literal, a plain
// identifier that is not the map's own range key, or a computed index that is
// not a recognized normalization.
//
//   - names        args-named maps, .Args/.Arguments selectors, and their aliases.
//   - helperMaps   map[string]any PARAMETERS that are NOT args-named — the
//     pass-through-lookup-helper shape (#3727 finding 4b). A key
//     that arrives as a parameter is a key that came from outside
//     the map, exactly the class this gate is for, so a lookup
//     helper cannot launder it past the gate by naming its map `m`.
//     Indexes into these are flagged ONLY when the index is itself a
//     string PARAMETER of the same function, which is what keeps
//     JSON-Schema traversal (node["properties"], node[kw] over a
//     literal keyword slice) clean — those keys are literals or
//     range vars, never a pass-through key parameter.
//   - keyParams    string-typed parameters of the function.
func rawLookups(fset *token.FileSet, body *ast.BlockStmt, names, helperMaps, keyParams map[string]bool) []lookup {
	if len(names) == 0 && len(helperMaps) == 0 && !bodyIndexesAnArgsMapWithoutALocal(body) {
		return nil
	}

	// Assignment targets: `args[k] = v` writes, it does not resolve.
	writes := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			if ix, ok := lhs.(*ast.IndexExpr); ok {
				writes[ix] = true
			}
		}
		return true
	})

	// Self-iteration must be recognised LEXICALLY: an index `args[k]` is safe
	// only when it sits INSIDE the body of a `for k := range args` over THAT
	// map. Collecting (key, over) pairs function-wide let a later safe
	// `for k := range args` mask an earlier vulnerable `for k := range names {
	// args[k] }` reusing the key name `k` (#3727 finding 4c). Each range keeps
	// its body's position span so containment can be checked.
	type rangeScope struct {
		key       string
		over      string
		bodyStart token.Pos
		bodyEnd   token.Pos
	}
	var ranges []rangeScope
	ast.Inspect(body, func(n ast.Node) bool {
		rs, ok := n.(*ast.RangeStmt)
		if !ok || rs.Key == nil || rs.Body == nil {
			return true
		}
		key, ok := rs.Key.(*ast.Ident)
		if !ok {
			return true
		}
		ranges = append(ranges, rangeScope{
			key:       key.Name,
			over:      render(fset, rs.X),
			bodyStart: rs.Body.Pos(),
			bodyEnd:   rs.Body.End(),
		})
		return true
	})
	isSelfIteration := func(idxName, over string, pos token.Pos) bool {
		for _, r := range ranges {
			if r.key == idxName && r.over == over && pos >= r.bodyStart && pos < r.bodyEnd {
				return true
			}
		}
		return false
	}

	var out []lookup
	ast.Inspect(body, func(n ast.Node) bool {
		ix, ok := n.(*ast.IndexExpr)
		if !ok || writes[ix] {
			return true
		}
		isArgs := isArgsMapExpr(ix.X, names)
		isHelper := false
		if !isArgs {
			if id, ok := ix.X.(*ast.Ident); ok && helperMaps[id.Name] {
				isHelper = true
			}
		}
		if !isArgs && !isHelper {
			return true
		}
		over := render(fset, ix.X)

		var kind string
		switch idx := ix.Index.(type) {
		case *ast.BasicLit:
			if idx.Kind != token.STRING {
				return true
			}
			if isHelper {
				// A string literal on a non-args-named map is JSON-Schema keyword
				// traversal, not the class — only args maps are flagged on a
				// literal key.
				return true
			}
			kind = "string literal key"
		case *ast.Ident:
			if isSelfIteration(idx.Name, over, ix.Pos()) {
				return true // self-iteration over this very map — safe
			}
			if isHelper && !keyParams[idx.Name] {
				// A non-args map indexed by a range var / local that is not a
				// pass-through key parameter is schema traversal (node[kw]).
				return true
			}
			kind = "identifier key"
		default:
			// A computed index on an arguments map is ALWAYS flagged — including
			// args[normalizeFieldName(k)] (#3727 pass-2 finding 3). Normalizing the
			// LOOKUP key does not normalize the STORED key, so a normalized index
			// still misses a disguised key; the only correct mitigation is a
			// resolver CALL (resolveField / argFieldRecovered), not an index.
			// args["u"+"rl"], args[key()], args[strings.ToLower(k)] are flagged for
			// the same reason (#3727 finding 4a). Skipped for helper maps, where a
			// computed index is out of scope, same as a literal.
			if isHelper {
				return true
			}
			kind = "computed key"
		}

		out = append(out, lookup{
			line: fset.Position(ix.Pos()).Line,
			expr: render(fset, ix),
			kind: kind,
		})
		return true
	})
	return out
}

// keyParamIdents returns the identifiers that hold a pass-through lookup KEY:
// the function's string-typed parameters, plus any local aliased from one of
// them (`k := key`). Tracking the alias closes the bypass where a key parameter
// is copied to a local before the index (#3727 pass-2 finding 3), so
// `m[k]`/`t.store[k]` is still recognised as an outside key indexed into a map.
func keyParamIdents(params *ast.FieldList, body *ast.BlockStmt) map[string]bool {
	keys := map[string]bool{}
	if params != nil {
		for _, f := range params.List {
			id, ok := f.Type.(*ast.Ident)
			if !ok || id.Name != "string" {
				continue
			}
			for _, n := range f.Names {
				keys[n.Name] = true
			}
		}
	}
	if len(keys) == 0 || body == nil {
		return keys
	}
	// Follow single-hop string aliases. Two passes so an alias of an alias is
	// caught; the loop is bounded, which matters more than a fixed point here.
	for pass := 0; pass < 2; pass++ {
		ast.Inspect(body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			lhs, ok := as.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			if rhs, ok := as.Rhs[0].(*ast.Ident); ok && keys[rhs.Name] {
				keys[lhs.Name] = true
			}
			return true
		})
	}
	return keys
}

// helperMapParamIdents returns the names of map[string]any parameters that are
// NOT already tracked as args maps by name — the lookup-helper shape a
// non-args-like name (`m`, `fields`) would otherwise hide (#3727 finding 4b).
func helperMapParamIdents(params *ast.FieldList, names map[string]bool) map[string]bool {
	out := map[string]bool{}
	if params == nil {
		return out
	}
	for _, f := range params.List {
		if !isArgsMapType(f.Type) {
			continue
		}
		for _, n := range f.Names {
			if !names[n.Name] {
				out[n.Name] = true
			}
		}
	}
	return out
}

// bodyIndexesAnArgsMapWithoutALocal reports whether the body indexes an
// arguments map that owns no args-map-typed local — a .Args/.Arguments selector,
// or an inline type assertion (`args.(map[string]interface{})[key]`, #3740
// finding 4). Without this pre-scan such a function is skipped wholesale,
// because argsMapIdents finds nothing to put in names: in the type-assertion
// shape the parameter's declared type is interface{}, not the map type. It
// delegates to isArgsMapExpr with a nil name set so the two stay in step —
// a shape recognised there but not here would be silently unreachable.
func bodyIndexesAnArgsMapWithoutALocal(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if ix, ok := n.(*ast.IndexExpr); ok && isArgsMapExpr(ix.X, nil) {
			found = true
		}
		return !found
	})
	return found
}

// allowedLines maps a source line to the reason given for exempting it. A
// directive covers its own comment lines and the line immediately after the
// comment group, which is how a leading `// argmaplookup:allow …` above the
// statement is spelled.
func allowedLines(fset *token.FileSet, file *ast.File) map[int]string {
	allowed := map[int]string{}
	for _, group := range file.Comments {
		reason := ""
		for _, c := range group.List {
			i := strings.Index(c.Text, allowDirective)
			if i < 0 {
				continue
			}
			reason = strings.TrimSpace(c.Text[i+len(allowDirective):])
		}
		if reason == "" {
			// A directive with no reason is not an exemption. Leaving the site
			// unexcused (rather than erroring here) makes it fail the gate with
			// the ordinary message, which already asks for a reason.
			continue
		}
		start := fset.Position(group.Pos()).Line
		end := fset.Position(group.End()).Line
		for l := start; l <= end+1; l++ {
			allowed[l] = reason
		}
	}
	return allowed
}

func render(fset *token.FileSet, e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, e); err != nil {
		return "<unprintable>"
	}
	return buf.String()
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].File != f[j].File {
			return f[i].File < f[j].File
		}
		return f[i].Line < f[j].Line
	})
}
