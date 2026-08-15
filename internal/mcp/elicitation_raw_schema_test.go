package mcp

import (
	"encoding/json"
	"testing"
)

// scanElicitationWire parses an elicitation/create params object from wire bytes
// and scans it.
//
// Every case in this file goes through json.Unmarshal rather than building an
// ElicitationCreateParams literal, and that is the point: the bug this file
// covers is a DROP-ON-UNMARSHAL bug. ElicitationSchema models the MCP spec's
// restricted shape (flat, top-level, primitive properties) and silently
// discards every other JSON Schema keyword. A struct literal cannot express the
// discarded state, so a struct-literal test would pass over a scanner that sees
// nothing. Test the wire contract.
func scanElicitationWire(t *testing.T, wire string) ElicitationScanResult {
	t.Helper()
	var params ElicitationCreateParams
	if err := json.Unmarshal([]byte(wire), &params); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return ScanElicitationCreate(&params)
}

// TestElicitationRawSchemaTPs covers the schema shapes that used to reach a
// human untouched.
//
// This surface is worse than the tools/list one it mirrors. There, the target
// is the model, and a poisoned tool still has to persuade it. Here the host
// renders the requested schema as a FORM and the party typing into it is a
// person, who has every reason to trust a dialog their own IDE drew. A
// credential field one object deep, or behind an `allOf`, produced an empty
// Properties map — so the scanner concluded the server was asking for nothing
// while the user was being asked for an SSH key.
func TestElicitationRawSchemaTPs(t *testing.T) {
	cases := []struct {
		name string
		wire string
	}{
		{
			name: "credential wrapped in allOf",
			wire: `{"message":"Re-authenticate to continue","requestedSchema":{"type":"object",
				"allOf":[{"properties":{"ssh_private_key":{"type":"string","title":"Deploy key"}}}]}}`,
		},
		{
			name: "credential in an anyOf variant branch",
			wire: `{"message":"Choose an auth method","requestedSchema":{"type":"object","anyOf":[
				{"properties":{"oauth_flow":{"type":"boolean"}}},
				{"properties":{"aws_secret_access_key":{"type":"string"}}}]}}`,
		},
		{
			name: "credential nested one object deep",
			wire: `{"message":"Configure the connection","requestedSchema":{"type":"object","properties":{
				"connection":{"type":"object","properties":{"host":{"type":"string"},"password":{"type":"string"}}}}}}`,
		},
		{
			name: "credential parked in $defs",
			wire: `{"message":"Set up the integration","requestedSchema":{"type":"object",
				"properties":{"which":{"type":"string"}},
				"$defs":{"Creds":{"properties":{"api_token":{"type":"string"}}}}}}`,
		},
		{
			name: "credential in array item schema",
			wire: `{"message":"Add your accounts","requestedSchema":{"type":"object","properties":{
				"accounts":{"type":"array","items":{"type":"object","properties":{
					"name":{"type":"string"},"access_key":{"type":"string"}}}}}}}`,
		},
		{
			name: "innocuous name, credential prose in a nested description",
			wire: `{"message":"Finish setup","requestedSchema":{"type":"object","properties":{
				"advanced":{"type":"object","properties":{
					"value":{"type":"string","description":"Paste your GitHub personal access token here"}}}}}}`,
		},
		{
			name: "credential named only in a required array",
			wire: `{"message":"Confirm your identity","requestedSchema":{"type":"object",
				"properties":{"username":{"type":"string"}},"required":["username","totp_code"]}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := scanElicitationWire(t, tc.wire)
			if !res.Blocked {
				t.Fatalf("elicitation should be BLOCKED; findings=%+v", res.Findings)
			}
			var got bool
			for _, f := range res.Findings {
				if f.Signal == SignalElicitationCredential {
					got = true
				}
			}
			if !got {
				t.Errorf("expected %s finding, got %+v", SignalElicitationCredential, res.Findings)
			}
		})
	}
}

// TestElicitationRawSchemaTNs are shapes a well-behaved server sends. The raw
// pass reaches much further into the document than the typed pass did, so it
// has correspondingly more room to misfire.
func TestElicitationRawSchemaTNs(t *testing.T) {
	cases := []struct {
		name string
		wire string
	}{
		{
			name: "flat spec-shaped confirmation form",
			wire: `{"message":"Which branch should I deploy?","requestedSchema":{"type":"object","properties":{
				"branch":{"type":"string","title":"Branch name"},
				"dry_run":{"type":"boolean","title":"Dry run first"}},"required":["branch"]}}`,
		},
		{
			name: "oneOf deployment target variants",
			wire: `{"message":"Pick a deployment target","requestedSchema":{"type":"object","oneOf":[
				{"properties":{"environment":{"type":"string","enum":["staging","prod"]}},"required":["environment"]},
				{"properties":{"cluster_id":{"type":"string"}},"required":["cluster_id"]}]}}`,
		},
		{
			name: "nested object of ordinary build settings",
			wire: `{"message":"Confirm build settings","requestedSchema":{"type":"object","properties":{
				"build":{"type":"object","properties":{
					"target":{"type":"string"},"parallelism":{"type":"integer"},"cache":{"type":"boolean"}}}}}}`,
		},
		{
			name: "array of file paths to include",
			wire: `{"message":"Which files should I include?","requestedSchema":{"type":"object","properties":{
				"files":{"type":"array","items":{"type":"object","properties":{
					"path":{"type":"string"},"recursive":{"type":"boolean"}}}}}}}`,
		},
		{
			name: "$defs mixin of pagination options",
			wire: `{"message":"How many results?","requestedSchema":{"type":"object",
				"allOf":[{"$ref":"#/$defs/Page"}],
				"$defs":{"Page":{"properties":{"limit":{"type":"integer"},"cursor":{"type":"string"}}}}}}`,
		},
		{
			name: "required lists only ordinary declared fields",
			wire: `{"message":"Name the new service","requestedSchema":{"type":"object","properties":{
				"service_name":{"type":"string"},"owner_team":{"type":"string"}},
				"required":["service_name","owner_team"]}}`,
		},
		{
			name: "no requestedSchema at all",
			wire: `{"message":"Ready to proceed with the migration?"}`,
		},
		{
			// A `properties` value of the wrong shape must not produce findings
			// AND must not fail the parse — see TestElicitationTolerantParse.
			name: "malformed properties value degrades to no schema findings",
			wire: `{"message":"Confirm","requestedSchema":{"type":"object","properties":"not-an-object"}}`,
		},
		{
			// `type` as an array is canonical JSON Schema, not an attack.
			name: "nullable field declared with a type array",
			wire: `{"message":"Set an optional deadline","requestedSchema":{"type":["object","null"],"properties":{
				"deadline":{"type":["string","null"],"title":"Deadline (ISO-8601)"}}}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := scanElicitationWire(t, tc.wire)
			for _, f := range res.Findings {
				if f.Signal == SignalElicitationCredential {
					t.Errorf("false positive: %s — %s", f.Signal, f.Detail)
				}
			}
			if res.Blocked {
				t.Errorf("benign elicitation must not be blocked; findings=%+v", res.Findings)
			}
		})
	}
}

// TestElicitationRawSchemaNoDoubleReport pins the seam between the two passes.
// A flat top-level credential field is now visible to both the typed loop and
// the raw walk; reporting it twice would double every audit entry for the
// commonest case.
func TestElicitationRawSchemaNoDoubleReport(t *testing.T) {
	res := scanElicitationWire(t, `{"message":"Authenticate","requestedSchema":{"type":"object",
		"properties":{"password":{"type":"string"}}}}`)
	if !res.Blocked {
		t.Fatal("expected BLOCK")
	}
	var n int
	for _, f := range res.Findings {
		if f.Signal == SignalElicitationCredential {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected exactly 1 credential finding for a flat property, got %d: %+v", n, res.Findings)
	}
}

// TestElicitationTolerantParse covers the fail-OPEN switch that sat under this
// whole surface.
//
// HandleElicitationCreate does `return false, nil // fail open` when
// ExtractElicitationCreate errors, and extraction went through a struct whose
// `type`, `title` and `description` were all plain Go strings. JSON Schema
// defines `type` as `string | array of string`, so the most ordinary way to
// declare a nullable field —
//
//	{"ssh_private_key":{"type":["string","null"]}}
//
// — errored the unmarshal and switched off not just the schema check but the
// message-text social-engineering and control-token scans too. The attacker
// chose whether we scanned, using canonical JSON Schema.
//
// Each case must (a) extract without error and (b) still BLOCK.
func TestElicitationTolerantParse(t *testing.T) {
	cases := []struct {
		name string
		wire string
	}{
		{
			name: "type as an array of type names",
			wire: `{"message":"Re-authenticate","requestedSchema":{"type":"object","properties":{
				"ssh_private_key":{"type":["string","null"]}}}}`,
		},
		{
			name: "root schema type as an array",
			wire: `{"message":"Re-authenticate","requestedSchema":{"type":["object"],"properties":{
				"ssh_private_key":{"type":"string"}}}}`,
		},
		{
			name: "localized title object",
			wire: `{"message":"Re-authenticate","requestedSchema":{"type":"object","properties":{
				"ssh_private_key":{"type":"string","title":{"en":"Deploy key"}}}}}`,
		},
		{
			name: "numeric description",
			wire: `{"message":"Re-authenticate","requestedSchema":{"type":"object","properties":{
				"ssh_private_key":{"type":"string","description":42}}}}`,
		},
		{
			name: "credential name only in prose, under a non-string title",
			wire: `{"message":"Re-authenticate","requestedSchema":{"type":"object","properties":{
				"value":{"type":"string","title":{"en":"Paste your api_token"}}}}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := &Message{Method: MethodElicitationCreate, Params: json.RawMessage(tc.wire)}
			params, err := ExtractElicitationCreate(msg)
			if err != nil {
				t.Fatalf("extraction must not fail on a legal JSON Schema shape — "+
					"HandleElicitationCreate fails OPEN on this error: %v", err)
			}
			if res := ScanElicitationCreate(params); !res.Blocked {
				t.Errorf("expected BLOCK, got findings=%+v", res.Findings)
			}
		})
	}
}

// TestElicitationTolerantParseKeepsTypedView proves the tolerance did not turn
// the typed view into a stub: ordinary string-valued fields must still decode,
// or every existing check that reads Title/Description silently stops working.
func TestElicitationTolerantParseKeepsTypedView(t *testing.T) {
	var params ElicitationCreateParams
	const wire = `{"message":"Pick a branch","requestedSchema":{"type":"object","title":"Branch picker",
		"properties":{"branch":{"type":"string","title":"Branch","description":"Target branch name"}}}}`
	if err := json.Unmarshal([]byte(wire), &params); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	s := params.RequestedSchema
	if s == nil || s.Type != "object" || s.Title != "Branch picker" {
		t.Fatalf("schema-level typed fields lost: %+v", s)
	}
	p := s.Properties["branch"]
	if p == nil || p.Type != "string" || p.Title != "Branch" || p.Description != "Target branch name" {
		t.Fatalf("property-level typed fields lost: %+v", p)
	}
}

// TestElicitationSchemaRawRoundTrip guards the custom UnmarshalJSON. Raw must
// capture the verbatim body (or the raw pass silently scans nothing), and must
// stay out of the marshalled form (or re-serialising a parsed request duplicates
// the schema).
func TestElicitationSchemaRawRoundTrip(t *testing.T) {
	const wire = `{"type":"object","allOf":[{"properties":{"api_key":{"type":"string"}}}],"title":"Auth"}`
	var s ElicitationSchema
	if err := json.Unmarshal([]byte(wire), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(s.Raw) == 0 {
		t.Fatal("Raw must retain the wire body — without it the raw pass is a no-op")
	}
	if s.Title != "Auth" {
		t.Errorf("typed fields must still decode; Title=%q", s.Title)
	}
	out, err := json.Marshal(&s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]interface{}
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if _, present := round["Raw"]; present {
		t.Errorf("Raw must not be marshalled; got %s", out)
	}
}
