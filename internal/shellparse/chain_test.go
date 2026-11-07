package shellparse

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestParse_ChainOperandsAndOperatorsInPosition pins walkBinaryChain's
// output: each operand's segments in source order, every operator in place
// (an operand's own inner operators included, #2889), and each operand's
// subcommands in source order.
func TestParse_ChainOperandsAndOperatorsInPosition(t *testing.T) {
	cases := []struct {
		cmd   string
		execs []string
		ops   []string
	}{
		{"a | b | c | d", []string{"a", "b", "c", "d"}, []string{"|", "|", "|"}},
		{"a | b && c | d || e", []string{"a", "b", "c", "d", "e"}, []string{"|", "&&", "|", "||"}},
		{"a && b | c | d", []string{"a", "b", "c", "d"}, []string{"&&", "|", "|"}},
		{"a && (b || c) | d", []string{"a", "b", "c", "d"}, []string{"&&", "||", "|"}},
		{"a | b; c && d", []string{"a", "b", "c", "d"}, []string{"|", ";", "&&"}},
	}
	for _, tc := range cases {
		p := Parse(tc.cmd, 2)
		var execs []string
		for _, s := range p.Segments {
			execs = append(execs, s.Executable)
		}
		if !slices.Equal(execs, tc.execs) || !slices.Equal(p.Operators, tc.ops) {
			t.Errorf("%q: segments %v operators %v, want %v %v", tc.cmd, execs, p.Operators, tc.execs, tc.ops)
		}
	}

	p := Parse(`bash -c 'x | y' | sh -c 'z' && bash -c 'w'`, 2)
	var inner []string
	for _, sub := range p.Subcommands {
		for _, s := range sub.Segments {
			inner = append(inner, s.Executable)
		}
	}
	if want := []string{"x", "y", "z", "w"}; !slices.Equal(inner, want) {
		t.Errorf("subcommands' segments %v, want %v in source order", inner, want)
	}
}

// TestParse_ChainCostIsLinear is the fitness function for #4772. A chain's
// segments used to be copied into every enclosing level, so a pipeline of n
// stages cost O(n²): 32 KiB of `a|a|…` outran Copilot CLI's 30 s hook
// timeout, after which the harness runs the command unevaluated. Bytes
// allocated are deterministic where wall time on a shared runner is not
// (#3505): 4× the stages must cost well under 16× the bytes. Measured on
// the quadratic walk: 15.2× for |, && and || alike (2.6 GB for 4000
// stages); on this one: 4.1×.
func TestParse_ChainCostIsLinear(t *testing.T) {
	for _, op := range []string{"|", " && ", " || "} {
		small := allocatedBy(func() { Parse(chainOf(op, 1000), 2) })
		large := allocatedBy(func() { Parse(chainOf(op, 4000), 2) })
		if ratio := float64(large) / float64(small); ratio > 6 {
			t.Errorf("%q chain: 4000 stages allocated %.1f× what 1000 did (%d vs %d bytes); want about 4× (linear)",
				op, ratio, large, small)
		}
	}
}

func chainOf(op string, n int) string {
	return strings.TrimSuffix(strings.Repeat("a"+op, n), op)
}

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
