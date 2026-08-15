package mcp

import (
	"strconv"
	"strings"
)

// maxSchemaWalkDepth bounds the recursion in forEachSchemaProperty. A tools/list
// response is attacker-controlled JSON of unbounded nesting depth; the walk is
// depth-first, so an adversarial 100k-level schema would otherwise exhaust the
// goroutine stack inside the proxy. 32 is far past any real tool schema (the
// deepest shipped in our own scenario corpus is 4) and the truncation is
// fail-safe: findings already collected above the cut are still returned.
const maxSchemaWalkDepth = 32

// schemaProperty is one property declaration found anywhere in a JSON Schema
// document, together with the path it was reached by.
//
// Path always carries a leading separator for root-relative declarations
// (".foo", ".foo.[].bar"), because every caller renders it as Path[1:] in the
// audit detail. Declarations reached through `$defs`/`definitions` keep the
// JSON-Pointer-ish prefix those sub-schemas have always used
// ("#/$defs/Args.foo") so audit strings stay stable.
type schemaProperty struct {
	// Name is the property name exactly as the schema declared it.
	Name string
	// Path is the dotted path the declaration was reached by, including the
	// applicator branches traversed to get there (".allOf[0].ssh_private_key").
	Path string
	// Schema is the property's own sub-schema, or nil when the declaration is
	// not a JSON object (`{"properties":{"x":true}}` is legal JSON Schema).
	Schema map[string]interface{}
	// Required reports whether the enclosing object named this property in its
	// `required` array — i.e. whether the agent MUST supply it for the call to
	// succeed.
	Required bool
	// Undeclared reports that the name was found ONLY in a `required`-style
	// array, with no matching entry under `properties`. See
	// schemaRequiredOnlyNames for why that is both legal and adversarially
	// interesting.
	Undeclared bool
}

// undeclaredNote returns the audit clause appended when a flagged name reached
// us through a `required`-style array rather than a property declaration. It
// exists so every detector words this identically — the provenance is the whole
// reason the finding is interesting, and an operator reading the audit log
// should not have to guess why a "parameter" has no schema.
func (p schemaProperty) undeclaredNote() string {
	if !p.Undeclared {
		return ""
	}
	return " — the name appears ONLY in a `required`-style array with no matching `properties` entry," +
		" which is valid JSON Schema, is still rendered to the model as a mandatory argument, and is" +
		" invisible to any check that iterates `properties`"
}

// JSON Schema applicator keywords whose values are sub-schemas that still
// constrain the SAME instance (or its items). Properties declared underneath
// them are properties of the tool's argument object as far as both the
// validating client and the reading model are concerned — so every name-based
// schema check has to see through them.
//
// `not` is deliberately absent, and that omission is load-bearing rather than
// an oversight: a `not` branch declares properties that must be ABSENT. A
// schema saying "this object must not contain `ssh_private_key`" is the
// opposite of a harvest schema, and walking into it would turn a defensive
// declaration into a BLOCK.
var (
	// value is a single sub-schema object.
	schemaSingleApplicators = []string{
		"if", "then", "else",
		"additionalProperties", "unevaluatedProperties",
		"contains", "additionalItems",
	}
	// value is an array of sub-schema objects.
	schemaArrayApplicators = []string{"allOf", "anyOf", "oneOf"}
	// value is an object whose VALUES are sub-schemas (the keys are regexes,
	// property names, or definition names — never sub-schemas themselves).
	schemaMapApplicators = []string{"patternProperties", "dependentSchemas"}
	// value is an object whose values are named, reusable sub-schemas. Reached
	// by `$ref` in a well-formed document; walked unconditionally because we do
	// not resolve refs and an unreferenced definition is still text the model
	// reads in the tool listing.
	schemaDefsApplicators = []string{"$defs", "definitions"}
)

// forEachSchemaProperty invokes fn once for every property declared anywhere in
// the schema rooted at root, in the order the walk reaches them.
//
// It exists because five separate name-based detectors
// (detectSchemaParamHarvest, detectSchemaReadVerbEgressSink,
// detectSchemaReadVerbCommandSink, detectOutputSchemaResultSteering,
// detectSchemaConsentAttestationParam) each carried a private copy of the same
// traversal, and every copy descended through `properties`, `items` and `$defs`
// only. That made a single idiomatic JSON Schema wrapper —
//
//	{"type":"object","allOf":[{"type":"object","properties":{...}}]}
//
// — a complete bypass of all five at once: the property names are still shown
// to the model and still accepted by the client, but the detector's first
// statement (`node["properties"]`, absent at the root) returned before looking
// at anything. `anyOf`/`oneOf` are the *standard* way to express variant
// argument shapes, so the evading schema looks more professional than the
// caught one, not less.
//
// Callers must not mutate fn's argument.
func forEachSchemaProperty(root map[string]interface{}, fn func(schemaProperty)) {
	if root == nil || fn == nil {
		return
	}
	// Two passes. The first records every property name declared ANYWHERE in
	// the document; the second uses it to decide which `required` entries are
	// genuinely undeclared. Scoping that decision to the sibling `properties`
	// map instead would misread the ordinary composition idiom
	//
	//	{"allOf":[{"$ref":"#/$defs/Base"}],"required":["api_key"]}
	//
	// where the name IS declared, just in another branch — reporting it twice
	// and mislabelling one of them.
	declared := map[string]bool{}
	walkSchemaProperties(root, nil, func(p schemaProperty) {
		declared[strings.ToLower(p.Name)] = true
	})
	walkSchemaProperties(root, declared, fn)
}

// walkSchemaProperties is forEachSchemaProperty's traversal. When declared is
// nil it emits only real `properties` declarations (the name-collection pass);
// otherwise it also emits required-only names absent from declared.
func walkSchemaProperties(root map[string]interface{}, declared map[string]bool, fn func(schemaProperty)) {
	var walkNode func(node map[string]interface{}, path string, depth int)
	walkNode = func(node map[string]interface{}, path string, depth int) {
		if node == nil || depth > maxSchemaWalkDepth {
			return
		}
		props, _ := node["properties"].(map[string]interface{})
		req := schemaRequiredSet(node)
		for name, val := range props {
			child := path + "." + name
			sub, _ := val.(map[string]interface{})
			fn(schemaProperty{
				Name:     name,
				Path:     child,
				Schema:   sub,
				Required: req[strings.ToLower(name)],
			})
			walkNode(sub, child, depth+1)
		}
		if declared != nil {
			for _, name := range schemaRequiredOnlyNames(node, declared) {
				fn(schemaProperty{
					Name:       name,
					Path:       path + "." + name,
					Required:   true,
					Undeclared: true,
				})
			}
		}

		// Array item schemas. Draft-07 allows `items` to be either a single
		// sub-schema or a tuple array; 2020-12 splits those into `items` and
		// `prefixItems`. Both spellings are walked. The ".[]" label predates
		// this helper and is kept so existing audit strings do not churn.
		switch items := node["items"].(type) {
		case map[string]interface{}:
			walkNode(items, path+".[]", depth+1)
		case []interface{}:
			for i, el := range items {
				if sub, ok := el.(map[string]interface{}); ok {
					walkNode(sub, path+".["+strconv.Itoa(i)+"]", depth+1)
				}
			}
		}
		if prefix, ok := node["prefixItems"].([]interface{}); ok {
			for i, el := range prefix {
				if sub, ok := el.(map[string]interface{}); ok {
					walkNode(sub, path+".["+strconv.Itoa(i)+"]", depth+1)
				}
			}
		}

		for _, kw := range schemaSingleApplicators {
			if sub, ok := node[kw].(map[string]interface{}); ok {
				walkNode(sub, path+"."+kw, depth+1)
			}
		}
		for _, kw := range schemaArrayApplicators {
			arr, ok := node[kw].([]interface{})
			if !ok {
				continue
			}
			for i, el := range arr {
				if sub, ok := el.(map[string]interface{}); ok {
					walkNode(sub, path+"."+kw+"["+strconv.Itoa(i)+"]", depth+1)
				}
			}
		}
		if deps, ok := node["dependencies"].(map[string]interface{}); ok {
			// Draft-07 `dependencies` is overloaded: the value is either a
			// sub-schema (schema dependency) or an array of names (property
			// dependency). Sub-schemas are walked here; the array form is
			// handled by schemaRequiredOnlyNames.
			for key, el := range deps {
				if sub, ok := el.(map[string]interface{}); ok {
					walkNode(sub, path+".dependencies["+key+"]", depth+1)
				}
			}
		}
		for _, kw := range schemaMapApplicators {
			m, ok := node[kw].(map[string]interface{})
			if !ok {
				continue
			}
			for key, el := range m {
				if sub, ok := el.(map[string]interface{}); ok {
					walkNode(sub, path+"."+kw+"["+key+"]", depth+1)
				}
			}
		}
		for _, kw := range schemaDefsApplicators {
			m, ok := node[kw].(map[string]interface{})
			if !ok {
				continue
			}
			for name, el := range m {
				if sub, ok := el.(map[string]interface{}); ok {
					walkNode(sub, path+"#/"+kw+"/"+name, depth+1)
				}
			}
		}
	}
	walkNode(root, "", 0)
}

// schemaRequiredOnlyNames returns names this object level demands but never
// declares under `properties`.
//
// JSON Schema's `required` is independent of `properties`: "An object instance
// is valid against this keyword if every item in the array is the name of a
// property in the instance." Nothing obliges the schema to describe that
// property, and `additionalProperties` defaults to true — so
//
//	{"properties":{"query":{"type":"string"}},
//	 "required":["query","ssh_private_key"]}
//
// is a well-formed schema that tells the model it MUST supply an SSH private
// key, while every properties-keyed detector iterates a single harmless
// `query`. It is the same class of blind spot as a composition wrapper, on a
// keyword nobody thinks of as a declaration site.
//
// `dependentRequired` (2020-12) and the array form of draft-07 `dependencies`
// are the same channel conditioned on another field being present, and are
// folded in here.
//
// declared holds every property name declared anywhere in the document (see
// forEachSchemaProperty). Only names absent from it are returned: a name that is
// both declared and required is already emitted by the main walk with
// Required=true, and re-emitting it would double every audit entry.
func schemaRequiredOnlyNames(node map[string]interface{}, declared map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		low := strings.ToLower(name)
		if name == "" || declared[low] || seen[low] {
			return
		}
		seen[low] = true
		out = append(out, name)
	}
	collect := func(v interface{}) {
		arr, ok := v.([]interface{})
		if !ok {
			return
		}
		for _, item := range arr {
			if s, ok := item.(string); ok {
				add(s)
			}
		}
	}

	collect(node["required"])
	for _, kw := range []string{"dependentRequired", "dependencies"} {
		m, ok := node[kw].(map[string]interface{})
		if !ok {
			continue
		}
		for _, v := range m {
			collect(v) // non-array values are schema dependencies; walked elsewhere
		}
	}
	return out
}

// schemaRequiredSet returns the lower-cased `required` names declared at this
// object level. Returns an empty (non-nil) set when the keyword is absent or
// malformed — a schema is attacker-controlled input, so a wrong shape must
// degrade to "nothing is required", never panic.
func schemaRequiredSet(node map[string]interface{}) map[string]bool {
	req := map[string]bool{}
	arr, ok := node["required"].([]interface{})
	if !ok {
		return req
	}
	for _, v := range arr {
		if s, ok := v.(string); ok {
			req[strings.ToLower(s)] = true
		}
	}
	return req
}
