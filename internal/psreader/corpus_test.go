package psreader

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// testEnv is a Windows user profile in the shape the hook will pass.
var testEnv = Env{
	Home: `C:\Users\alice`,
	Vars: map[string]string{
		"USERPROFILE":  `C:\Users\alice`,
		"APPDATA":      `C:\Users\alice\AppData\Roaming`,
		"LOCALAPPDATA": `C:\Users\alice\AppData\Local`,
		"TEMP":         `C:\Users\alice\AppData\Local\Temp`,
	},
}

// TestReadPaths_CoverEveryParserValue checks the Paths and Mentions fields
// themselves: for every input PowerShell accepts, each value in the parser's
// own facts (resolved the reader's way) that is path-like as a whole is in
// Read's Paths, and every other path-like spelling in it is in Paths or
// Mentions. The differential compares values; this checks that the fields
// the back end reads lost none of them, and that a whole value never lands
// among the mentions.
func TestReadPaths_CoverEveryParserValue(t *testing.T) {
	var checked, inputs int
	for _, c := range corpusSpecs {
		rows, truth := loadCorpus(t, "testdata", c.name, 76)
		text := map[string]string{}
		for _, r := range rows {
			text[idKey(r.ID)] = r.Command
		}
		res := newResolver(testEnv)
		for _, tr := range truth {
			if len(tr.ParseErrors) > 0 {
				continue
			}
			inputs++
			f := Read(text[idKey(tr.ID)], testEnv)
			paths, either := map[string]bool{}, map[string]bool{}
			for _, p := range f.Paths {
				paths[p], either[p] = true, true
			}
			for _, p := range f.Mentions {
				either[p] = true
			}
			want := func(v string) {
				if v == facts.Expr || v == facts.Dynamic {
					return
				}
				res.valuePaths(v, func(p string) {
					checked++
					if !paths[p] && !wordsAreWholeValues(res, v, paths) {
						t.Errorf("%s %s: whole value %q (parser value %q) not in Paths", c.name, idKey(tr.ID), p, v)
					}
				}, func(p string) {
					checked++
					if !either[p] {
						t.Errorf("%s %s: path %q (from parser value %q) in neither Paths nor Mentions", c.name, idKey(tr.ID), p, v)
					}
				})
			}
			for _, s := range tr.Strings {
				want(s)
			}
			for _, cmd := range tr.Commands {
				want(cmd.Name)
				for _, a := range cmd.Args {
					want(a)
				}
			}
		}
	}
	if inputs < 440 || checked < 1000 {
		t.Fatalf("checked %d paths over %d inputs, want >= 1000 over >= 440", checked, inputs)
	}
	t.Logf("%d parser path spellings over %d inputs, all in Paths or Mentions", checked, inputs)
}

// TestReadNotes_CorpusRates records how often the reader is unsure, because
// every note puts an AUDIT floor under the decision (ADR-001, D4). On input
// PowerShell accepts, a parse_error is a false alarm; on input it rejects,
// it is the reader agreeing. The ceilings hold today's numbers.
func TestReadNotes_CorpusRates(t *testing.T) {
	counts := map[string]int{}
	var accepted, rejected int
	for _, c := range corpusSpecs {
		rows, truth := loadCorpus(t, "testdata", c.name, 76)
		text := map[string]string{}
		for _, r := range rows {
			text[idKey(r.ID)] = r.Command
		}
		for _, tr := range truth {
			f := Read(text[idKey(tr.ID)], testEnv)
			kinds := map[facts.NoteKind]bool{}
			for _, n := range f.Notes {
				kinds[n.Kind] = true
			}
			if len(tr.ParseErrors) > 0 {
				rejected++
				if kinds[facts.NoteParseError] {
					counts["rejected_with_parse_error"]++
				}
				continue
			}
			accepted++
			for k := range kinds {
				counts["accepted_with_"+string(k)]++
				if k == facts.NoteParseError {
					for _, n := range f.Notes {
						if n.Kind == k {
							t.Logf("parse_error on accepted input %s %s: %s", c.name, idKey(tr.ID), n.Detail)
							break
						}
					}
				}
			}
			if len(f.Nested) > 0 {
				counts["accepted_with_nested"]++
			}
		}
	}
	t.Logf("accepted %d: parse_error %d, dynamic_name %d, dynamic_nested %d, decode_failed %d, nested %d",
		accepted, counts["accepted_with_parse_error"], counts["accepted_with_dynamic_name"],
		counts["accepted_with_dynamic_nested"], counts["accepted_with_decode_failed"], counts["accepted_with_nested"])
	t.Logf("rejected %d: parse_error %d", rejected, counts["rejected_with_parse_error"])
}

// wordsAreWholeValues reports a parser value that is a `--%` remainder, which
// the parser reports as one value and the reader reads word by word, as the
// native program receives it: every word that is path-like is in paths.
func wordsAreWholeValues(res *resolver, v string, paths map[string]bool) bool {
	words := splitWindowsArgs(v)
	if len(words) < 2 {
		return false
	}
	for _, w := range words {
		if p, ok := res.wholeValue(w); ok && !paths[p] {
			return false
		}
	}
	return true
}
