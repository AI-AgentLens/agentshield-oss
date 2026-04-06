package datalabel

import "unicode"

// validators maps validator names to check functions.
// A validator returns true if the matched text is confirmed valid
// (e.g., a credit card number that passes the Luhn check).
var validators = map[string]func(string) bool{
	"luhn": luhnCheck,
}

// Validate runs the named validator against text.
// Returns true if the validator confirms the match, or if the
// validator name is unknown (fail-open: don't discard matches
// for unrecognized validators).
func Validate(name, text string) bool {
	fn, ok := validators[name]
	if !ok {
		return true // unknown validator — don't discard
	}
	return fn(text)
}

// luhnCheck implements the Luhn algorithm for credit card validation.
// It extracts only digit characters from text before checking.
func luhnCheck(text string) bool {
	// Extract digits only
	digits := make([]int, 0, len(text))
	for _, r := range text {
		if unicode.IsDigit(r) {
			digits = append(digits, int(r-'0'))
		}
	}

	if len(digits) < 2 {
		return false
	}

	sum := 0
	odd := len(digits) % 2
	for i, d := range digits {
		if i%2 == odd {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
