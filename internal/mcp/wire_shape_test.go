package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeLenient_CleanDecodeReportsNoAnomaly(t *testing.T) {
	var p CallToolParams
	shape, err := decodeLenient([]byte(`{"name":"read_file","arguments":{"path":"/tmp/x"}}`), &p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if shape != nil {
		t.Fatalf("clean document produced an anomaly: %+v", shape)
	}
	if p.Name != "read_file" {
		t.Fatalf("name = %q", p.Name)
	}
}

// TestDecodeLenient_KeepsSiblingFields is the property the whole fix rests on:
// encoding/json saves the first type error and CONTINUES, so every field other
// than the offending one survives. If this ever stops being true the lenient
// decode still fails safe (we scan a smaller document, never a larger one),
// but the measured bypass closure would silently shrink — hence the explicit
// assertion rather than trusting the stdlib comment.
func TestDecodeLenient_KeepsSiblingFields(t *testing.T) {
	var p CallToolParams
	shape, err := decodeLenient(
		[]byte(`{"name":"read_file","arguments":{"path":"/home/u/.ssh/id_rsa","poison":1e400,"tail":"kept"}}`), &p)
	if err != nil {
		t.Fatalf("type error should be tolerated, got: %v", err)
	}
	if shape == nil {
		t.Fatal("expected an anomaly")
	}
	if p.Name != "read_file" {
		t.Errorf("name lost: %q", p.Name)
	}
	if got := p.Arguments["path"]; got != "/home/u/.ssh/id_rsa" {
		t.Errorf("payload-bearing sibling BEFORE the poison was lost: %v", got)
	}
	if got := p.Arguments["tail"]; got != "kept" {
		t.Errorf("sibling AFTER the poison was lost: %v", got)
	}
}

// TestDecodeLenient_SyntaxErrorStaysFatal pins the half of the classification
// that must NOT change. Bytes that are not JSON are a statement about the
// document: no peer can act on them, so there is nothing to scan and nothing
// to tolerate. Widening leniency to cover syntax errors would hand callers a
// half-populated struct built from garbage.
func TestDecodeLenient_SyntaxErrorStaysFatal(t *testing.T) {
	for _, raw := range []string{`{"name":`, `not json at all`, `{"name":"x",}`} {
		var p CallToolParams
		shape, err := decodeLenient([]byte(raw), &p)
		if err == nil {
			t.Errorf("%q: expected fatal error, got nil (anomaly=%+v)", raw, shape)
		}
		if shape != nil {
			t.Errorf("%q: fatal error must not also report an anomaly", raw)
		}
	}
}

// TestAnomalyFromTypeError pins the classifier, INCLUDING the case the first
// cut got wrong: encoding/json spells a fractional-into-integer failure the
// same way it spells a magnitude overflow ("number <literal>"), because both
// paths fail ParseInt. Reading the spelling alone reported every Python float
// as an unrepresentable number and asserted, in the audit line, that no
// conforming serializer produces one. Caught by adversarial review of #3914.
func TestAnomalyFromTypeError(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		want  WireShapeSignal
		field string
	}{
		{"magnitude overflow", `{"name":"x","arguments":{"n":1e400}}`, SignalWireNumericOverflow, "arguments"},
		{"400-digit integer", `{"name":"x","arguments":{"n":1` + strings.Repeat("0", 400) + `}}`, SignalWireNumericOverflow, "arguments"},
		{"kind mismatch: number into string", `{"name":5}`, SignalWireTypeConfusion, "name"},
		{"kind mismatch: array into string", `{"name":["x"]}`, SignalWireTypeConfusion, "name"},
		{"kind mismatch: array into object", `{"name":"x","arguments":[1,2]}`, SignalWireTypeConfusion, "arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p CallToolParams
			shape, err := decodeLenient([]byte(tc.raw), &p)
			if err != nil {
				t.Fatalf("should have been tolerated: %v", err)
			}
			if shape == nil {
				t.Fatal("expected an anomaly")
			}
			if shape.Signal != tc.want {
				t.Errorf("signal = %q, want %q (json Value=%q)", shape.Signal, tc.want, shape.Value)
			}
			if shape.Field != tc.field {
				t.Errorf("field = %q, want %q", shape.Field, tc.field)
			}
			if shape.Detail == "" {
				t.Error("anomaly has no detail — the audit receipt would be empty")
			}
		})
	}

	// Direct unit check on the stdlib contract the classifier reads, so a
	// change is attributable to encoding/json rather than to our plumbing.
	var v struct {
		N float64 `json:"n"`
	}
	var te *json.UnmarshalTypeError
	if !errors.As(json.Unmarshal([]byte(`{"n":1e400}`), &v), &te) {
		t.Fatal("overflow no longer reported as *json.UnmarshalTypeError")
	}
	if !strings.HasPrefix(te.Value, "number ") || te.Value == "number" {
		t.Errorf("overflow Value spelling changed: %q — anomalyFromTypeError's discriminator is stale", te.Value)
	}
	var w struct {
		N string `json:"n"`
	}
	te = nil
	if !errors.As(json.Unmarshal([]byte(`{"n":5}`), &w), &te) {
		t.Fatal("kind mismatch no longer reported as *json.UnmarshalTypeError")
	}
	if te.Value != "number" {
		t.Errorf("kind-mismatch Value spelling changed: %q", te.Value)
	}
}

// TestRepresentableNumberIsBenignNonConformance pins the suppression, and the
// reason for it. `json.dumps` renders every Python float with a trailing `.0`,
// so a server computing `max_tokens` arithmetically sends `2048.0` on EVERY
// sampling request. That is a serializer being loose, not an attacker probing
// for a parser off-switch, and an AUDIT line emitted once per request is an
// AUDIT line nobody reads.
//
// The decode stays lenient either way — the message is still SCANNED. Only the
// receipt is withheld, and only where the literal round-trips as a real float64
// and therefore names a value a real serializer could have produced.
func TestRepresentableNumberIsBenignNonConformance(t *testing.T) {
	benign := []struct{ name, raw string }{
		{"python float into int", `{"maxTokens":2048.0}`},
		{"fractional into int", `{"maxTokens":1.5}`},
		{"negative fractional", `{"maxTokens":-3.25}`},
		{"exponent form still representable", `{"maxTokens":2.048e3}`},
		{"float64 max", `{"maxTokens":1.7976931348623157e308}`},
	}
	for _, tc := range benign {
		t.Run("benign/"+tc.name, func(t *testing.T) {
			var p SamplingCreateMessageParams
			shape, err := decodeLenient([]byte(tc.raw), &p)
			if err != nil {
				t.Fatalf("must still be tolerated: %v", err)
			}
			if shape != nil {
				t.Fatalf("representable number produced a receipt: %+v", shape)
			}
		})
	}

	evidence := []struct{ name, raw string }{
		{"beyond float64", `{"maxTokens":1e400}`},
		{"negative beyond float64", `{"maxTokens":-1e400}`},
		{"400-digit integer", `{"maxTokens":1` + strings.Repeat("0", 400) + `}`},
	}
	for _, tc := range evidence {
		t.Run("evidence/"+tc.name, func(t *testing.T) {
			var p SamplingCreateMessageParams
			shape, err := decodeLenient([]byte(tc.raw), &p)
			if err != nil {
				t.Fatalf("must be tolerated: %v", err)
			}
			if shape == nil || shape.Signal != SignalWireNumericOverflow {
				t.Fatalf("unrepresentable number must still be recorded: %+v", shape)
			}
			// The prose must not claim more than the classifier checked.
			if strings.Contains(shape.Detail, "declared numeric type cannot represent") {
				t.Error("detail still uses the pre-review wording, which was false for representable literals")
			}
		})
	}
}
