package datalabel

import "testing"

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{name: "valid visa", text: "4532015112830366", want: true},
		{name: "valid mastercard", text: "5425233430109903", want: true},
		{name: "valid amex", text: "374245455400126", want: true},
		{name: "invalid single digit change", text: "4532015112830367", want: false},
		{name: "valid with spaces", text: "4532 0151 1283 0366", want: true},
		{name: "valid with dashes", text: "4532-0151-1283-0366", want: true},
		{name: "too short", text: "1", want: false},
		{name: "empty", text: "", want: false},
		{name: "all zeros", text: "0000000000", want: true}, // technically valid Luhn
		{name: "random digits", text: "1234567890123456", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := luhnCheck(tt.text)
			if got != tt.want {
				t.Errorf("luhnCheck(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestValidate_UnknownValidator(t *testing.T) {
	// BUG-DL-005: unknown validator names fail closed at runtime. Init
	// should prevent this state; runtime fallback is defense in depth.
	if Validate("unknown-validator", "any text") {
		t.Error("unknown validator should return false (fail closed)")
	}
}

func TestIsKnownValidator(t *testing.T) {
	if !IsKnownValidator("") {
		t.Error("empty validator name should be treated as 'no validator'")
	}
	if !IsKnownValidator("luhn") {
		t.Error("luhn should be recognized")
	}
	if IsKnownValidator("lhun") { // typo
		t.Error("typo should not be recognized")
	}
}

func TestValidate_Luhn(t *testing.T) {
	if !Validate("luhn", "4532015112830366") {
		t.Error("valid card should pass Luhn validation")
	}
	if Validate("luhn", "4532015112830367") {
		t.Error("invalid card should fail Luhn validation")
	}
}
