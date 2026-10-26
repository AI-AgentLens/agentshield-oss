package redact

import (
	"encoding/json"
	"testing"
)

func TestRedactArguments_NumericValueUnderSecretKey(t *testing.T) {
	in := map[string]interface{}{
		"password":   float64(123456),
		"nested":     map[string]interface{}{"api_key": json.Number("99887766")},
		"pins":       map[string]interface{}{"password": []interface{}{float64(1234)}},
		"max_tokens": float64(2048),
		"limit":      float64(10),
	}
	out := RedactArguments(in)
	if out["password"] != redactedPlaceholder {
		t.Errorf("numeric password kept: %v", out["password"])
	}
	if out["nested"].(map[string]interface{})["api_key"] != redactedPlaceholder {
		t.Errorf("json.Number api_key kept")
	}
	if out["pins"].(map[string]interface{})["password"].([]interface{})[0] != redactedPlaceholder {
		t.Errorf("array element under secret key kept")
	}
	if out["max_tokens"] != float64(2048) || out["limit"] != float64(10) {
		t.Errorf("benign numbers redacted: %v %v", out["max_tokens"], out["limit"])
	}
	if in["password"] != float64(123456) {
		t.Errorf("input mutated")
	}
}
