package psreader

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/AI-AgentLens/agentshield/internal/facts"
)

// The expected-facts differential (ADR-001, "Fitness functions": reader
// differential). Pure Go: no pwsh and no .NET.
//
// testdata/corpora/corpus-<name>.jsonl holds inputs {id, command}.
// testdata/truth76/<name>-truth.jsonl holds what PowerShell 7.6's parser
// ([Parser]::ParseInput) reported for each input, and
// testdata/truth51/<name>-truth51.jsonl what Windows PowerShell 5.1's did.
// Both were produced once by the #4245 experiment's truth.ps1. A new row is
// written by hand: add the input to a corpus and its expected facts to the
// truth file in the same shape (a developer with pwsh may cross-check it with
// truth.ps1, but nothing requires it). Inputs the truth parser rejects
// (parse_errors non-empty) are counted and skipped, as in the experiment.
//
// The metrics are compare.py's, ported below:
//   names     the ordered list of command names is identical
//   commands  names, invocation operators, parameters and argument values
//   strings   the multiset of expression strings is identical
//   paths     the set of path-like values (pyPathLike) is identical, split into
//             none missed (the parser has it and the reader does not: a
//             possible fail-open) and none extra (a possible false positive)
//
// Held out of the repo: the experiment's heldout and stress corpora are
// third-party scripts (PowerShell's own modules, vendor installers), so they
// run only from a local copy of the experiment; see
// TestReaderDifferential_ExperimentCorpora.

type corpusSpec struct {
	name string
	// floors on the inputs the truth parser accepts: a corpus that shrinks
	// or stops loading fails instead of passing on nothing
	floor76, floor51 int // floor51 0: no 5.1 truth for this corpus
}

var corpusSpecs = []corpusSpec{
	{"agent-oneliners", 183, 183},
	{"agent-scripts", 62, 62},
	{"attack", 12, 0}, // not run on 5.1: the box's Defender would see the shapes
	{"blind-agent", 119, 114},
	{"real", 4, 4},
	{"synthetic", 63, 59},
}

type corpusRow struct {
	ID      json.RawMessage `json:"id"`
	Command string          `json:"command"`
}

type truthCommand struct {
	Name   string   `json:"name"`
	Op     string   `json:"op"`
	Params []string `json:"params"`
	Args   []string `json:"args"`
}

type truthRow struct {
	ID          json.RawMessage `json:"id"`
	ParseErrors []string        `json:"parse_errors"`
	Commands    []truthCommand  `json:"commands"`
	Strings     []string        `json:"strings"`
}

// observed is what a reader reports for one input, in the truth file's shape.
type observed struct {
	commands []truthCommand
	strings  []string
}

type observeFunc func(text string) (observed, error)

// observeRead is the reader under test: names, parameters, arguments and
// strings are taken from Read's facts.Facts, the contract the back end
// consumes. The invocation operator is not part of the contract, so it comes
// from the same reader's internal record, which must line up one to one.
func observeRead(text string) (observed, error) {
	f := Read(text, Env{})
	r := &reader{s: []rune(text)}
	r.statements(0)
	if len(r.cmds) != len(f.Commands) {
		return observed{}, fmt.Errorf("Read reported %d commands, the reader %d", len(f.Commands), len(r.cmds))
	}
	var o observed
	for i, c := range f.Commands {
		o.commands = append(o.commands, truthCommand{Name: c.Written, Op: r.cmds[i].op, Params: c.Params, Args: c.Args})
	}
	o.strings = f.Strings
	return o, nil
}

func idKey(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func readJSONL[T any](t testing.TB, path string) []T {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var out []T
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for n := 1; sc.Scan(); n++ {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var row T
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatalf("%s:%d: %v", path, n, err)
		}
		out = append(out, row)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// --- compare.py, ported ------------------------------------------------------

var pyEnv = []struct {
	re  *regexp.Regexp
	rep string
}{
	{regexp.MustCompile(`^\$\{?env:userprofile\}?`), "~"},
	{regexp.MustCompile(`^\$\{?home\}?`), "~"},
	{regexp.MustCompile(`^~`), "~"},
	{regexp.MustCompile(`^\$\{?env:appdata\}?`), "~/appdata/roaming"},
	{regexp.MustCompile(`^\$\{?env:localappdata\}?`), "~/appdata/local"},
	{regexp.MustCompile(`^\$\{?env:(temp|tmp)\}?`), "<temp>"},
}

var pyDrive = regexp.MustCompile(`^[a-z]:`)

// pySplit is Python's str.split(): runs of whitespace, where Python's
// whitespace also covers the separators U+001C to U+001F.
func pySplit(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r >= 0x1c && r <= 0x1f })
}

// pyPathLike is compare.py's path_like.
func pyPathLike(t string, out map[string]bool) {
	for _, w := range append([]string{t}, pySplit(t)...) {
		w = strings.ToLower(strings.ReplaceAll(strings.Trim(w, `'"`), `\`, "/"))
		for _, e := range pyEnv {
			w = e.re.ReplaceAllString(w, e.rep)
		}
		if strings.Contains(w, "/") || strings.HasPrefix(w, "~") || pyDrive.MatchString(w) {
			if w != "/" && w != "//" {
				out[w] = true
			}
		}
	}
}

// pyFactsPaths is compare.py's facts_paths.
func pyFactsPaths(cmds []truthCommand, strs []string) map[string]bool {
	vals := append([]string{}, strs...)
	for _, c := range cmds {
		vals = append(vals, c.Name)
		vals = append(vals, c.Args...)
	}
	out := map[string]bool{}
	for _, v := range vals {
		if v != facts.Expr && v != facts.Dynamic {
			pyPathLike(v, out)
		}
	}
	return out
}

// --- the differential ----------------------------------------------------------

var metrics = []string{"names", "commands", "strings", "paths_none_missed", "paths_none_extra"}

type diffReport struct {
	n, rejected   int
	ok            map[string]int
	truthCommands int // denominators of the field comparisons
	truthStrings  int
	truthPaths    int
	diffs         []string
}

func (r diffReport) pct(m string) float64 {
	if r.n == 0 {
		return 0
	}
	return 100 * float64(r.ok[m]) / float64(r.n)
}

func (r diffReport) summary(name string) string {
	return fmt.Sprintf("%-16s n=%-4d rejected=%-3d names %5.1f%%  commands %5.1f%%  strings %5.1f%%  paths: none-missed %5.1f%%  none-extra %5.1f%%  (truth commands %d, strings %d, paths %d)",
		name, r.n, r.rejected, r.pct("names"), r.pct("commands"), r.pct("strings"),
		r.pct("paths_none_missed"), r.pct("paths_none_extra"), r.truthCommands, r.truthStrings, r.truthPaths)
}

func names(cmds []truthCommand) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.Name
	}
	return out
}

func sortedCopy(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

// normCommands treats a nil and an empty list alike, as JSON does.
func normCommands(cmds []truthCommand) []truthCommand {
	out := make([]truthCommand, len(cmds))
	for i, c := range cmds {
		out[i] = truthCommand{Name: c.Name, Op: c.Op, Params: append([]string{}, c.Params...), Args: append([]string{}, c.Args...)}
	}
	return out
}

func setMinus(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func differential(t testing.TB, rows []corpusRow, truth []truthRow, observe observeFunc) diffReport {
	t.Helper()
	inputs := map[string]string{}
	for _, r := range rows {
		inputs[idKey(r.ID)] = r.Command
	}
	rep := diffReport{ok: map[string]int{}}
	for _, tr := range truth {
		key := idKey(tr.ID)
		text, found := inputs[key]
		if !found {
			t.Fatalf("truth row %s has no input in the corpus", key)
		}
		if len(tr.ParseErrors) > 0 {
			rep.rejected++
			continue
		}
		rep.n++
		g, err := observe(text)
		if err != nil {
			t.Fatalf("input %s: %v", key, err)
		}
		tc, gc := normCommands(tr.Commands), normCommands(g.commands)
		tp, gp := pyFactsPaths(tr.Commands, tr.Strings), pyFactsPaths(g.commands, g.strings)
		rep.truthCommands += len(tc)
		rep.truthStrings += len(tr.Strings)
		rep.truthPaths += len(tp)
		missed, extra := setMinus(tp, gp), setMinus(gp, tp)
		res := map[string]bool{
			"names":             reflect.DeepEqual(names(tc), names(gc)),
			"commands":          reflect.DeepEqual(tc, gc),
			"strings":           reflect.DeepEqual(sortedCopy(tr.Strings), sortedCopy(g.strings)),
			"paths_none_missed": len(missed) == 0,
			"paths_none_extra":  len(extra) == 0,
		}
		var bad []string
		for _, m := range metrics {
			if res[m] {
				rep.ok[m]++
			} else {
				bad = append(bad, m)
			}
		}
		if len(bad) > 0 && len(rep.diffs) < 8 {
			d := fmt.Sprintf("%s %v", key, bad)
			if !res["commands"] {
				for i := 0; i < len(tc) || i < len(gc); i++ {
					var a, b any
					if i < len(tc) {
						a = tc[i]
					}
					if i < len(gc) {
						b = gc[i]
					}
					if !reflect.DeepEqual(a, b) {
						d += fmt.Sprintf("\n      cmd[%d] parser=%v\n      cmd[%d] reader=%v", i, a, i, b)
						break
					}
				}
			}
			if len(missed)+len(extra) > 0 {
				d += fmt.Sprintf("\n      paths missed=%q extra=%q", missed, extra)
			}
			rep.diffs = append(rep.diffs, d)
		}
	}
	return rep
}

func loadCorpus(t testing.TB, dir, name string, version int) ([]corpusRow, []truthRow) {
	t.Helper()
	rows := readJSONL[corpusRow](t, filepath.Join(dir, "corpora", "corpus-"+name+".jsonl"))
	var truthPath string
	if version == 51 {
		truthPath = filepath.Join(dir, "truth51", name+"-truth51.jsonl")
	} else {
		truthPath = filepath.Join(dir, "truth76", name+"-truth.jsonl")
	}
	return rows, readJSONL[truthRow](t, truthPath)
}

// requireExact fails unless every metric is 100% on every accepted input.
func requireExact(t *testing.T, name string, rep diffReport, floor int) {
	t.Helper()
	t.Log(rep.summary(name))
	if rep.n < floor {
		t.Errorf("%s: %d inputs the parser accepts, want >= %d: the corpus shrank or stopped loading", name, rep.n, floor)
	}
	for _, m := range metrics {
		if rep.ok[m] != rep.n {
			t.Errorf("%s: %s matched on %d of %d inputs", name, m, rep.ok[m], rep.n)
		}
	}
	for _, d := range rep.diffs {
		t.Errorf("  - %s", d)
	}
}

func TestReaderDifferential_PowerShell76(t *testing.T) {
	var total diffReport
	for _, c := range corpusSpecs {
		rows, truth := loadCorpus(t, "testdata", c.name, 76)
		rep := differential(t, rows, truth, observeRead)
		requireExact(t, c.name, rep, c.floor76)
		total.n += rep.n
		total.truthCommands += rep.truthCommands
		total.truthStrings += rep.truthStrings
		total.truthPaths += rep.truthPaths
	}
	// The field comparisons must compare something: an extractor that
	// returned nothing for both sides would pass every metric above.
	if total.truthCommands < 2100 || total.truthStrings < 1600 || total.truthPaths < 950 {
		t.Errorf("denominators too small: %d commands, %d strings, %d paths compared", total.truthCommands, total.truthStrings, total.truthPaths)
	}
}

func TestReaderDifferential_WindowsPowerShell51(t *testing.T) {
	for _, c := range corpusSpecs {
		if c.floor51 == 0 {
			continue
		}
		rows, truth := loadCorpus(t, "testdata", c.name, 51)
		requireExact(t, c.name+"/5.1", differential(t, rows, truth, observeRead), c.floor51)
	}
}

// TestReaderDifferential_ExperimentCorpora runs the corpora that are not in
// the repo (third-party scripts) from a local copy of the #4245 experiment:
//
//	PSREADER_EXPERIMENT_DIR=~/dev/docs/pwsh-reader-experiment-4245 go test -run ExperimentCorpora ./internal/psreader/
func TestReaderDifferential_ExperimentCorpora(t *testing.T) {
	dir := os.Getenv("PSREADER_EXPERIMENT_DIR")
	if dir == "" {
		t.Skip("PSREADER_EXPERIMENT_DIR not set")
	}
	for _, name := range []string{"heldout", "stress"} {
		rows := readJSONL[corpusRow](t, filepath.Join(dir, "corpora", "corpus-"+name+".jsonl"))
		t76 := readJSONL[truthRow](t, filepath.Join(dir, "out76", name+"-truth.jsonl"))
		requireExact(t, name, differential(t, rows, t76, observeRead), 1)
		t51 := readJSONL[truthRow](t, filepath.Join(dir, "out51", name+"-truth51.jsonl"))
		requireExact(t, name+"/5.1", differential(t, rows, t51, observeRead), 1)
	}
}

// TestReaderDifferential_PositiveControls proves the differential can fail:
// deliberately broken readers, and a mutated expected file, each drop the
// metric they break below 100%.
func TestReaderDifferential_PositiveControls(t *testing.T) {
	rows, truth := loadCorpus(t, "testdata", "agent-oneliners", 76)
	wrap := func(mut func(o *observed)) observeFunc {
		return func(text string) (observed, error) {
			o, err := observeRead(text)
			if err == nil {
				mut(&o)
			}
			return o, err
		}
	}
	controls := []struct {
		name    string
		observe observeFunc
		truth   []truthRow
		breaks  []string
	}{
		{
			// The bash Segment model: command arguments only. ADR-001 says
			// why Strings is not optional; this is the measurement.
			name:    "reader that drops expression strings",
			observe: wrap(func(o *observed) { o.strings = nil }),
			breaks:  []string{"strings", "paths_none_missed"},
		},
		{
			name: "reader that lower-cases command names",
			observe: wrap(func(o *observed) {
				for i := range o.commands {
					o.commands[i].Name = strings.ToLower(o.commands[i].Name)
				}
			}),
			breaks: []string{"names", "commands"},
		},
		{
			name: "reader that loses the last parameter of each command",
			observe: wrap(func(o *observed) {
				for i, c := range o.commands {
					if len(c.Params) > 0 {
						o.commands[i].Params = c.Params[:len(c.Params)-1]
					}
				}
			}),
			breaks: []string{"commands"},
		},
		{
			name: "reader that invents a path",
			observe: wrap(func(o *observed) {
				o.strings = append(o.strings, `C:\invented\by\the\reader`)
			}),
			breaks: []string{"strings", "paths_none_extra"},
		},
		{
			name:    "expected file whose first path argument names another file",
			observe: observeRead,
			truth:   mutateFirstPathArg(t, truth),
			breaks:  []string{"commands", "paths_none_missed", "paths_none_extra"},
		},
	}
	for _, c := range controls {
		tr := truth
		if c.truth != nil {
			tr = c.truth
		}
		rep := differential(t, rows, tr, c.observe)
		for _, m := range c.breaks {
			if rep.ok[m] == rep.n {
				t.Errorf("%s: %s still 100%% (%d/%d): the differential cannot see this break", c.name, m, rep.ok[m], rep.n)
			}
		}
		t.Logf("%-62s %s", c.name+":", rep.summary("agent-oneliners"))
	}
}

// mutateFirstPathArg returns a copy of truth whose first path-like argument
// is changed to another path: the reader, unchanged, now misses one path and
// invents another.
func mutateFirstPathArg(t *testing.T, truth []truthRow) []truthRow {
	t.Helper()
	out := make([]truthRow, len(truth))
	done := false
	for i, tr := range truth {
		out[i] = tr
		if done || len(tr.ParseErrors) > 0 {
			continue
		}
		cmds := normCommands(tr.Commands)
		for ci, c := range cmds {
			for ai, a := range c.Args {
				if done {
					break
				}
				m := map[string]bool{}
				pyPathLike(a, m)
				if len(m) > 0 {
					cmds[ci].Args[ai] = `D:\mutated\elsewhere.txt`
					out[i].Commands = cmds
					done = true
				}
			}
		}
	}
	if !done {
		t.Fatal("no path argument to mutate")
	}
	return out
}
