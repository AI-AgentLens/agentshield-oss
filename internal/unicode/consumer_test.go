package unicode

import (
	"fmt"
	"strings"
	"testing"
)

func TestRecoverConsumerProseASCIISeparators(t *testing.T) {
	// Enumerate the contract independently of the implementation's predicate.
	for _, interval := range [][2]byte{{0, 8}, {11, 11}, {14, 31}, {127, 127}} {
		for b := interval[0]; b <= interval[1]; b++ {
			t.Run(fmt.Sprintf("%02x", b), func(t *testing.T) {
				in := "alpha" + string([]byte{b}) + "bravo"
				if got, changed := RecoverConsumerProse(in); got != "alpha bravo" || !changed {
					t.Fatalf("got %q, %v", got, changed)
				}
				// The new reading must not alter identifier/shell consumers.
				if got, changed := RecoverRenderedText(in); got != in || changed {
					t.Fatalf("legacy rendered recovery changed: %q, %v", got, changed)
				}
				if got, changed := FoldUnicodeSeparators(in); got != in || changed {
					t.Fatalf("legacy separator fold changed: %q, %v", got, changed)
				}
			})
		}
	}
}

func TestRecoverConsumerProseDeletions(t *testing.T) {
	for _, r := range []rune{0x200b, 0xe000, 0xf0000, 0x100000, 0x0378, 0xfdd0, 0x10ffff, 0xfffd} {
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			in := "al" + string(r) + "pha"
			if got, changed := RecoverConsumerProse(in); got != "alpha" || !changed {
				t.Fatalf("got %q, %v", got, changed)
			}
			if got, changed := StripConsumerIgnorables(in); got != "alpha" || !changed {
				t.Fatalf("name deletion got %q, %v", got, changed)
			}
		})
	}
}

func TestRecoverConsumerProseCompatibility(t *testing.T) {
	for r := rune(0xff01); r <= 0xff5e; r++ {
		want := string(r - 0xfee0)
		if got, changed := RecoverConsumerProse(string(r)); got != want || !changed {
			t.Errorf("U+%04X: got %q, %v; want %q", r, got, changed, want)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"\ufe50\ufe52\ufe54\ufe55\ufe56\ufe57\ufe59\ufe5a\ufe5b\ufe5c\ufe5f\ufe60\ufe61\ufe62\ufe63\ufe64\ufe65\ufe66\ufe68\ufe69\ufe6a\ufe6b", ",.;:?!(){}#&*+-<>=\\$%@"},
		{"\u2160\u2161\u2162\u2163\u2164\u2165\u2166\u2167\u2168\u2169\u216a\u216b\u216c\u216d\u216e\u216f", "IIIIIIIVVVIVIIVIIIIXXXIXIILCDM"},
		{"\u2170\u2171\u2172\u2173\u2174\u2175\u2176\u2177\u2178\u2179\u217a\u217b\u217c\u217d\u217e\u217f", "iiiiiiivvviviiviiiixxxixiilcdm"},
		{"\ufb00\ufb01\ufb02\ufb03\ufb04\ufb05\ufb06", "fffiflffifflstst"},
		{"\u2070\u00b9\u00b2\u00b3\u2074\u2075\u2076\u2077\u2078\u2079\u2071\u207f", "0123456789in"},
		{"\u2080\u2081\u2082\u2083\u2084\u2085\u2086\u2087\u2088\u2089\u2090\u2091\u2092\u2093\u2095\u2096\u2097\u2098\u2099\u209a\u209b\u209c", "0123456789aeoxhklmnpst"},
		{"\u02b0\u02b2\u02b3\u02b7\u02b8\u02e1\u02e2\u02e3\u1d2c\u1d30\u1d49", "hjrwylsxADe"},
		// Composition of old and new axes.
		{"\uff21\ue000\u00ad\u0430\x00\ufb03\u2163", "Aa ffiIV"},
	} {
		if got, changed := RecoverConsumerProse(tc.in); got != tc.want || !changed {
			t.Errorf("%q: got %q, %v; want %q", tc.in, got, changed, tc.want)
		}
		if got, changed := RecoverConsumerProse(tc.want); got != tc.want || changed {
			t.Errorf("not a fixpoint: %q, %v", got, changed)
		}
	}
}

func TestRecoverConsumerProsePreservesOrdinaryText(t *testing.T) {
	for _, in := range []string{"", "alpha bravo\tcharlie\ndelta\r\fecho", "caf\u00e9", "\u4e2d\u6587"} {
		if got, changed := RecoverConsumerProse(in); got != in || changed {
			t.Errorf("%q: got %q, %v", in, got, changed)
		}
	}
	plain := strings.Repeat("printf '%s' alpha\n", 20)
	if allocs := testing.AllocsPerRun(100, func() {
		if got, changed := RecoverConsumerProse(plain); changed || got != plain {
			t.Fatal("plain ASCII changed")
		}
	}); allocs != 0 {
		t.Fatalf("plain ASCII allocated: %v", allocs)
	}
}
