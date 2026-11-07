package policy

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/AI-AgentLens/agentshield/packs"
	"gopkg.in/yaml.v3"
)

// fullDecodeLabels is what the full load reads from one file: the whole
// document decoded as a pack (LoadPacks, LoadEmbeddedShellPacks) or as a
// policy file (Load).
func fullDecodeLabels(data []byte, asPolicy bool) ([]DataLabel, error) {
	if asPolicy {
		var p Policy
		err := yaml.Unmarshal(data, &p)
		return p.DataLabels, err
	}
	var p Pack
	err := yaml.Unmarshal(data, &p)
	return p.DataLabels, err
}

// labelsShapeDoc carries a label in every field the scrubber reads, so a
// decode that drops or changes one is visible.
const labelsShapeBody = `- id: "codename"
  name: "Codename"
  decision: "BLOCK"
  confidence: 0.9
  reason: "codename # not a comment"
  patterns:
    - keywords: ["FALCON", "OSPREY"]
      case_sensitive: true
    - regex: 'CUST-[0-9]{6}'
      context: "customer|cust"
    - regex: '\b\d{15,16}\b'
      validator: "luhn"
  scan_scope:
    tools: ["write_*"]
    directions: ["outbound"]
    max_scan_bytes: 4096
    shell: true
`

func indent(s, by string) string {
	lines := strings.SplitAfter(s, "\n")
	for i, l := range lines {
		if l != "" && l != "\n" {
			lines[i] = by + l
		}
	}
	return strings.Join(lines, "")
}

// TestDeclaredDataLabels_FastPathMatchesFullDecode (#4805): the labels the
// fail-safe record is scrubbed with are the labels the full load merges. On
// every shipped shell pack and policy template, on the test policies that
// declare labels, and on the shapes that make the block read stand aside,
// declaredDataLabels returns exactly what decoding the whole document
// returns.
func TestDeclaredDataLabels_FastPathMatchesFullDecode(t *testing.T) {
	var files []string
	for _, glob := range []string{
		filepath.Join("..", "..", "packs", "*", "*.yaml"),
		filepath.Join("..", "..", "configs", "*.yaml"),
		filepath.Join("..", "rulecount", "testdata", "packs", "*", "*.yaml"),
	} {
		m, _ := filepath.Glob(glob)
		if len(m) == 0 {
			t.Errorf("vacuity: %s matches no file", glob)
		}
		files = append(files, m...)
	}
	labelled := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, asPolicy := range []bool{false, true} {
			want, wantErr := fullDecodeLabels(data, asPolicy)
			if wantErr != nil {
				continue // not this kind of file; the full load would refuse it
			}
			got, err := declaredDataLabels(data)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("%s (as policy %v): fast %+v (%v), full %+v", f, asPolicy, got, err, want)
			}
			if len(want) > 0 && !asPolicy {
				labelled++
			}
		}
	}
	// Vacuity floor: every glob matches a file (above), and at least one file's
	// labels are read. No shipped pack declares labels today; the rulecount
	// fixture does. Not a file count: the OSS tree ships no packs/premium/ and
	// has 9 of these files, and the OSS publish runs this test.
	if labelled < 1 {
		t.Errorf("read %d files, %d with labels; want >= 1 with labels", len(files), labelled)
	}

	block := "data_labels:\n" + labelsShapeBody
	indented := "data_labels:\n" + indent(labelsShapeBody, "  ")
	for _, c := range []struct {
		name, doc string
		block     bool // the block is extracted (it is used only when it decodes alone)
	}{
		{"test policy with two labels", dlTestPolicyYAML, true},
		{"compact sequence, labels last", "version: x\nrules: []\n" + block, true},
		{"compact sequence, labels first", block + "rules:\n- id: r\n  decision: AUDIT\n", true},
		{"indented sequence", "rules: []\n" + indented + "defaults:\n  decision: AUDIT\n", true},
		{"column-0 comments inside the block", "data_labels:\n# one\n- id: a\n# two\n  patterns:\n  - keywords: [X]\n- id: b\nrules: []\n", true},
		{"crlf", strings.ReplaceAll(block+"rules: []\n", "\n", "\r\n"), true},
		{"no trailing newline", "rules: []\ndata_labels:\n- id: a\n  patterns:\n  - keywords: [X]", true},
		{"header comment", "data_labels: # labels\n- id: a\n", true},
		{"empty flow list", "data_labels: []\n", false},
		{"flow list", "data_labels: [{id: a, patterns: [{keywords: [X]}]}]\n", false},
		{"flow list over lines", "data_labels: [\n  {id: a},\n  {id: b}\n]\n", false},
		{"null value", "data_labels:\nrules: []\n", true},
		{"quoted key", "\"data_labels\":\n- id: a\n", false},
		{"document marker", "---\ndata_labels:\n- id: a\n", false},
		{"second document ignored", "data_labels:\n- id: a\n---\ndata_labels:\n- id: b\n", false},
		{"anchor outside the block (the block does not decode alone)", "x: &l\n  id: a\ndata_labels:\n- *l\n", true},
		{"anchor inside the block, alias outside", "data_labels:\n- &l\n  id: a\ny: *l\n", true},
		{"block scalar inside a label", "data_labels:\n- id: a\n  reason: |\n    line one\n    data_labels:\n    - id: evil\n", true},
		{"rule body mentions data_labels", "data_labels:\n- id: a\nrules:\n- id: r\n  reason: |\n    data_labels:\n    - id: evil\n", true},
		{"named only in a value", "rules:\n- id: r\n  reason: \"no data_labels here\"\n", false},
		{"named only in comments", "# data_labels:\n#- id: x\n  # data_labels\nrules: []\n", false},
		// A line the block read cannot place ends it unread: the block read
		// refuses, so a broken document like this one is an error.
		{"key with a dash prefix after the block", "data_labels:\n- id: a\n-x: 1\n", false},
		{"lone dash at the end of the file", "rules: []\ndata_labels:\n-", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, asPolicy := range []bool{false, true} {
				want, wantErr := fullDecodeLabels([]byte(c.doc), asPolicy)
				got, err := declaredDataLabels([]byte(c.doc))
				if wantErr != nil {
					// A document the full load refuses: the fast read may
					// still return the labels its block declares, never an
					// error-free empty answer that hides them.
					continue
				}
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("as policy %v: fast %+v (%v), full %+v", asPolicy, got, err, want)
				}
			}
			if _, ok := topLevelDataLabelsBlock([]byte(c.doc)); ok != c.block && countKeyOutsideComments([]byte(c.doc), "data_labels") > 0 {
				t.Errorf("block read applies = %v, want %v", ok, c.block)
			}
		})
	}
	if got, err := declaredDataLabels([]byte("rules: []\n")); got != nil || err != nil {
		t.Errorf("a file that never spells the key: %v %v, want nothing", got, err)
	}
}

// TestDeclaredDataLabels_BrokenElsewhereStillReadsTheBlock: a policy file the
// full load refuses for a reason outside data_labels still gives up its
// labels (#4805: "a config that fails the full load but has a readable
// data_labels block gets scrubbed"). A broken data_labels block is an error.
func TestDeclaredDataLabels_BrokenElsewhereStillReadsTheBlock(t *testing.T) {
	block := "data_labels:\n" + labelsShapeBody
	want, err := fullDecodeLabels([]byte(block), true)
	if err != nil || len(want) != 1 {
		t.Fatalf("control: the block alone decodes to %v (%v)", want, err)
	}
	for _, c := range []struct{ name, doc string }{
		{"unclosed flow list after the block", block + "rules: [\n"},
		{"unclosed flow list before the block", "rules: [\n" + block},
		{"type error in rules", "rules: \"not a list\"\n" + block},
		{"tab-indented garbage elsewhere", "defaults:\n\tdecision: AUDIT\n" + block},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, c.doc)); err == nil {
				t.Fatalf("control: the full load accepts this document")
			}
			got, err := declaredDataLabels([]byte(c.doc))
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("fast %+v (%v), want the block's %+v", got, err, want)
			}
		})
	}
	// A file broken elsewhere that names data_labels only in comments, or
	// not at all, declares none: no labels and no error, so its failure
	// never withholds a record.
	for _, doc := range []string{"# data_labels: see the team pack\nrules: [\n", "rules: [\n"} {
		if got, err := declaredDataLabels([]byte(doc)); got != nil || err != nil {
			t.Errorf("%q: %v (%v), want nothing", doc, got, err)
		}
	}
	for _, c := range []struct{ name, doc string }{
		{"keywords is a scalar", "data_labels:\n- id: a\n  patterns:\n  - keywords: FALCON\n"},
		{"unclosed flow inside the block", "data_labels:\n- id: a\n  patterns: [\n"},
		{"a mapping, not a list", "data_labels:\n  id: a\n"},
		{"flow list that does not parse", "data_labels: [ {id: a\n"},
		// Two top-level keys: the full load refuses the file, and reading
		// either list alone would leave the other's values unscrubbed.
		{"the key twice", "data_labels:\n- id: a\n  patterns:\n  - keywords: [A]\nrules: []\ndata_labels:\n- id: b\n"},
	} {
		t.Run("broken block: "+c.name, func(t *testing.T) {
			got, err := declaredDataLabels([]byte(c.doc))
			if err == nil {
				t.Errorf("fast %+v with no error; a broken data_labels block must be an error", got)
			}
		})
	}
}

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadDeclaredDataLabels_MatchesTheFullLoad: the labels, and their order,
// are the full load's (Load, then the embedded packs, then LoadPacks) on a
// tree with labels in the policy file, a flat pack, a subdirectory pack, a
// disabled pack and a disabled subdirectory.
func TestLoadDeclaredDataLabels_MatchesTheFullLoad(t *testing.T) {
	dir := t.TempDir()
	packsDir := filepath.Join(dir, "packs")
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pack := func(id string) string {
		return "name: p-" + id + "\nrules: []\ndata_labels:\n- id: " + id + "\n  decision: BLOCK\n  patterns:\n  - keywords: [K" + id + "]\n"
	}
	write("policy.yaml", dlTestPolicyYAML)
	write("packs/b-flat.yaml", pack("flat-b"))
	write("packs/a-flat.yml", pack("flat-a"))
	write("packs/regex/sub.yaml", pack("sub"))
	write("packs/_off.yaml", pack("off"))
	write("packs/_offdir/x.yaml", pack("offdir"))
	write("packs/mcp/mcp-x.yaml", "tools: [this is not a shell pack\n")
	write("packs/mcp-flat.yaml", "tools: [this is not a shell pack\n")
	write("packs/notes.txt", "data_labels:\n- id: not-a-pack\n")
	policyPath := filepath.Join(dir, "policy.yaml")

	full, err := Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	full, _, _ = LoadEmbeddedShellPacks(full)
	full, _, err = LoadPacks(packsDir, full)
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadDeclaredDataLabels(policyPath, packsDir)
	if err != nil {
		t.Fatalf("LoadDeclaredDataLabels: %v", err)
	}
	if !reflect.DeepEqual(got, full.DataLabels) {
		t.Fatalf("fast read %v\nfull load %v", ids(got), ids(full.DataLabels))
	}
	if want := []string{"pii-ssn", "internal-codename", "flat-a", "flat-b", "sub"}; !reflect.DeepEqual(ids(got), want) {
		t.Errorf("ids %v, want %v (control: the tree must exercise each source)", ids(got), want)
	}

	// Missing sources declare nothing and are not errors.
	if got, err := LoadDeclaredDataLabels(filepath.Join(dir, "absent.yaml"), filepath.Join(dir, "absent")); err != nil || len(got) != 0 {
		t.Errorf("absent sources: %v (%v), want none and no error", ids(got), err)
	}
}

func ids(labels []DataLabel) []string {
	out := []string{}
	for _, l := range labels {
		out = append(out, l.ID)
	}
	return out
}

// TestLoadDeclaredDataLabels_UnreadableSourceIsAnError: every source that
// could declare labels and could not be read is an error naming it, and the
// labels that could be read still come back. A broken DISABLED pack is not
// an error: its labels are never in force.
func TestLoadDeclaredDataLabels_UnreadableSourceIsAnError(t *testing.T) {
	good := "data_labels:\n- id: good\n  patterns:\n  - keywords: [G]\n"
	broken := "data_labels:\n- id: x\n  patterns: [\n"
	for _, c := range []struct {
		name   string
		setup  func(t *testing.T, dir string) (policyPath, packsDir string)
		source string // a substring of the error's source; "" means no error
	}{
		{"broken policy data_labels", func(t *testing.T, dir string) (string, string) {
			return writeIn(t, dir, "policy.yaml", broken), filepath.Join(dir, "packs")
		}, "policy.yaml"},
		{"policy path is a directory", func(t *testing.T, dir string) (string, string) {
			p := filepath.Join(dir, "policy.yaml")
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p, filepath.Join(dir, "packs")
		}, "policy.yaml"},
		{"packs path is a file", func(t *testing.T, dir string) (string, string) {
			writeIn(t, dir, "packs", "not a directory\n")
			return writeIn(t, dir, "policy.yaml", good), filepath.Join(dir, "packs")
		}, "packs"},
		{"enabled pack with broken data_labels", func(t *testing.T, dir string) (string, string) {
			writeIn(t, dir, "packs/bad.yaml", broken)
			return writeIn(t, dir, "policy.yaml", good), filepath.Join(dir, "packs")
		}, "bad.yaml"},
		{"disabled pack with broken data_labels", func(t *testing.T, dir string) (string, string) {
			writeIn(t, dir, "packs/_bad.yaml", broken)
			return writeIn(t, dir, "policy.yaml", good), filepath.Join(dir, "packs")
		}, ""},
		{"pack broken outside data_labels", func(t *testing.T, dir string) (string, string) {
			writeIn(t, dir, "packs/rules-broken.yaml", "rules: [\n")
			return writeIn(t, dir, "policy.yaml", good), filepath.Join(dir, "packs")
		}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			policyPath, packsDir := c.setup(t, t.TempDir())
			labels, err := LoadDeclaredDataLabels(policyPath, packsDir)
			if c.source == "" {
				if err != nil {
					t.Fatalf("error %v, want none", err)
				}
				return
			}
			var de *DeclaredLabelsError
			if !errors.As(err, &de) || !strings.Contains(err.Error(), c.source) {
				t.Fatalf("error %v, want a DeclaredLabelsError naming %q", err, c.source)
			}
			if c.name != "broken policy data_labels" && c.name != "policy path is a directory" {
				if !reflect.DeepEqual(ids(labels), []string{"good"}) {
					t.Errorf("labels %v, want the readable policy's [good] alongside the error", ids(labels))
				}
			}
		})
	}
}

func writeIn(t *testing.T, dir, rel, body string) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadDeclaredDataLabels_ReadsTheEmbeddedPacks: the embedded community
// packs are a source too, merged before the disk packs, a disabled one
// skipped. No shipped community pack declares labels, so the corpus test
// above cannot see this source; the default must be the files
// LoadEmbeddedShellPacks merges.
func TestLoadDeclaredDataLabels_ReadsTheEmbeddedPacks(t *testing.T) {
	def, shipped := embeddedShellFiles(), packs.ShellFiles()
	if len(def) == 0 || !reflect.DeepEqual(def, shipped) {
		t.Fatalf("default embedded files: %d, want packs.ShellFiles' %d", len(def), len(shipped))
	}
	prev := embeddedShellFiles
	t.Cleanup(func() { embeddedShellFiles = prev })
	embeddedShellFiles = func() map[string][]byte {
		return map[string][]byte{
			"community-labels.yaml": []byte("name: c\nrules: []\ndata_labels:\n- id: embedded\n  patterns:\n  - keywords: [E]\n"),
			"_off.yaml":             []byte("data_labels:\n- id: embedded-off\n"),
			"no-labels.yaml":        []byte("rules: []\n"),
		}
	}
	dir := t.TempDir()
	disk := writeIn(t, dir, "packs/d.yaml", "data_labels:\n- id: disk\n")
	got, err := LoadDeclaredDataLabels(filepath.Join(dir, "absent.yaml"), filepath.Dir(disk))
	if err != nil || !reflect.DeepEqual(ids(got), []string{"embedded", "disk"}) {
		t.Fatalf("labels %v (%v), want [embedded disk]", ids(got), err)
	}
	embeddedShellFiles = func() map[string][]byte {
		return map[string][]byte{"bad.yaml": []byte("data_labels:\n- id: x\n  patterns: [\n")}
	}
	if _, err := LoadDeclaredDataLabels(filepath.Join(dir, "absent.yaml"), ""); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error %v, want one naming the embedded pack", err)
	}
}

// utf16Doc and utf32Doc encode text with a byte-order mark, as Windows
// Notepad saves "Unicode" and "Unicode big endian".
func utf16Doc(text string, bigEndian bool) []byte {
	out := []byte{0xFF, 0xFE}
	if bigEndian {
		out = []byte{0xFE, 0xFF}
	}
	for _, c := range utf16.Encode([]rune(text)) {
		if bigEndian {
			out = append(out, byte(c>>8), byte(c))
		} else {
			out = append(out, byte(c), byte(c>>8))
		}
	}
	return out
}

func utf32Doc(text string) []byte {
	out := []byte{0xFF, 0xFE, 0, 0}
	for _, r := range text {
		out = append(out, byte(r), byte(r>>8), byte(r>>16), byte(r>>24))
	}
	return out
}

// TestDeclaredDataLabels_EveryEncodingAndSpellingTheFullLoadReads (#4805
// Codex F1, Opus pass 1 follow-up 1): the raw-text read missed a key yaml.v3
// decodes, so a fail-safe record carried the value. The whole document is
// decoded first now: wherever the full load reads labels, the fast read
// returns the same ones, and a document neither can decode is unreadable,
// never "no labels".
func TestDeclaredDataLabels_EveryEncodingAndSpellingTheFullLoadReads(t *testing.T) {
	plain := "version: x\ndata_labels:\n- id: a\n  patterns:\n  - keywords: [K]\nrules: []\n"
	ls := "\u2028"
	for _, c := range []struct {
		name string
		doc  []byte
	}{
		{"UTF-16 LE with a BOM", utf16Doc(plain, false)},
		{"UTF-16 BE with a BOM", utf16Doc(plain, true)},
		{"UTF-8 with a BOM", append([]byte{0xEF, 0xBB, 0xBF}, plain...)},
		{"key escaped \\x5f", []byte("\"data\\x5flabels\":\n- id: a\n  patterns:\n  - keywords: [K]\n")},
		{"key escaped \\u", []byte("\"\\u0064ata_labels\":\n- id: a\n")},
		{"key escaped \\U", []byte("\"data_\\U0000006cabels\":\n- id: a\n")},
		{"!!binary key", []byte("!!binary ZGF0YV9sYWJlbHM=: [{id: a}]\n")},
		{"verbatim binary tag, %-escaped", []byte("!<tag:yaml.org,2002:bin%61ry> ZGF0YV9sYWJlbHM=: [{id: a}]\n")},
		{"explicit key joined by a backslash line break", []byte("? \"data_\\\n  labels\"\n: [{id: a}]\n")},
		{"U+2028 inside the block", []byte("data_labels:\n- id: a\n" + ls + "- id: b\nrules: []\n")},
		{"fake header inside a quoted scalar, real key quoted",
			[]byte("x: \"line one\ndata_labels:\n- id: fake\n\"\n\"data_labels\": [{id: real}]\n")},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, asPolicy := range []bool{false, true} {
				want, err := fullDecodeLabels(c.doc, asPolicy)
				if err != nil || len(want) == 0 {
					t.Fatalf("control (as policy %v): the full decode gives %v (%v); want labels", asPolicy, ids(want), err)
				}
				got, err := declaredDataLabels(c.doc)
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Errorf("as policy %v: fast %v (%v), full %v", asPolicy, ids(got), err, ids(want))
				}
			}
		})
	}

	// A document the full load cannot decode, whose raw text could hide or
	// misplace the key: unreadable (an error), so the record withholds.
	broken := "rules:\n  - id: broken\n    match: {command_regex: \"x\"\n"
	for _, c := range []struct {
		name string
		doc  []byte
	}{
		{"UTF-16 LE with a BOM, a rule broken", utf16Doc(plain+broken, false)},
		{"UTF-16 BE with a BOM, a rule broken", utf16Doc(plain+broken, true)},
		{"UTF-16 LE without a BOM", utf16Doc(plain, false)[2:]},
		{"UTF-32 with a BOM (yaml.v3 reads no UTF-32)", utf32Doc(plain)},
		{"UTF-8 with a BOM, a rule broken", append([]byte{0xEF, 0xBB, 0xBF}, plain+broken...)},
		{"key escaped \\x5f, a rule broken", []byte("\"data\\x5flabels\":\n- id: a\n" + broken)},
		{"!!binary key, a rule broken", []byte("!!binary ZGF0YV9sYWJlbHM=: [{id: a}]\n" + broken)},
		{"verbatim binary tag, %-escaped, a rule broken", []byte("!<tag:yaml.org,2002:bin%61ry> ZGF0YV9sYWJlbHM=: [{id: a}]\n" + broken)},
		{"explicit key joined by a backslash line break, a rule broken", []byte("? \"data_\\\n  labels\"\n: [{id: a}]\n" + broken)},
		{"U+2028 inside the block, a rule broken", []byte("data_labels:\n- id: a\n" + ls + "- id: b\n" + broken)},
		{"a NUL byte", []byte("data_labels:\n- id: a\x00\n" + broken)},
		{"a Latin-1 byte (not UTF-8, no control character)", []byte("# caf\xe9\ndata_labels:\n- id: a\n" + broken)},
		{"the key named twice", []byte("data_labels:\n- id: a\nx: \"data_labels\"\n" + broken)},
		{"a stray line after the block", []byte("data_labels:\n- id: a\nstray\n- id: b\n" + broken)},
		{"a %TAG directive", []byte("%TAG !e! tag:yaml.org,2002:\n---\ndata_labels:\n- id: a\n" + broken)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := fullDecodeLabels(c.doc, true); err == nil {
				t.Fatalf("control: the full decode accepts this document")
			}
			if got, err := declaredDataLabels(c.doc); err == nil {
				t.Errorf("fast %v with no error; want the labels unreadable", ids(got))
			}
		})
	}
}

// TestLoadDeclaredDataLabels_UTF16PolicyFile_4805: the policy file Notepad
// saves as "Unicode" gives up the labels the full load reads from it.
func TestLoadDeclaredDataLabels_UTF16PolicyFile_4805(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, utf16Doc(dlTestPolicyYAML, false), 0o600); err != nil {
		t.Fatal(err)
	}
	full, err := Load(p)
	if err != nil || len(full.DataLabels) != 2 {
		t.Fatalf("control: the full load reads %d labels (%v)", len(full.DataLabels), err)
	}
	got, err := LoadDeclaredDataLabels(p, filepath.Join(dir, "packs"))
	if err != nil || !reflect.DeepEqual(ids(got), ids(full.DataLabels)) {
		t.Fatalf("fast read %v (%v), full load %v", ids(got), err, ids(full.DataLabels))
	}
}

// TestDeclaredDataLabels_BrokenDocumentSpellings_4814 (#4814 items 6 and 7):
// a broken document whose data_labels key is spelled without its raw text is
// unreadable, never "no labels", so the fail-safe record withholds. Each row
// is a real spelling (the full decode reads a label from it once the broken
// tail is gone) inside a document the full decode refuses.
func TestDeclaredDataLabels_BrokenDocumentSpellings_4814(t *testing.T) {
	var (
		nel = string([]byte{0xC2, 0x85})
		ls  = string([]byte{0xE2, 0x80, 0xA8})
		ps  = string([]byte{0xE2, 0x80, 0xA9})
	)
	b64 := "ZGF0YV9sYWJl" + "bHM=" // base64 of the key
	list := "[{id: a, patterns: [{keywords: [K]}]}]"
	broken := "rules:\n  - id: broken\n    match: {command_regex: \"x\"\n"
	for _, c := range []struct{ name, doc string }{
		// Item 6: the key count ran before the block read refused the
		// directive, so these read as no labels.
		{"%TAG handle naming binary", "%TAG !e! tag:yaml.org,2002:\n---\n!e!binary " + b64 + ": " + list + "\n"},
		{"%TAG after a comment line", "# packs\n%TAG !e! tag:yaml.org,2002:\n---\n!e!binary " + b64 + ": " + list + "\n"},
		{"%TAG after a lone CR", "# packs\r%TAG !e! tag:yaml.org,2002:\r---\r!e!binary " + b64 + ": " + list + "\r"},
		{"%TAG after a mid-line %", "# 100% packs\n%TAG !e! tag:yaml.org,2002:\n---\n!e!binary " + b64 + ": " + list + "\n"},
		// The primary handle with a %-escaped "!": yaml.v3 reads it as !!binary.
		{"!%21binary key", "!%21binary " + b64 + ": " + list + "\n"},
		// Item 7: one row per check a mutant dropped (R4, R7).
		{"\\u-escaped key", `"\u0064ata_labels": ` + list + "\n"},
		{"key joined across U+0085", "? \"data_\\" + nel + "  labels\"\n: " + list + "\n"},
		{"key joined across U+2028", "? \"data_\\" + ls + "  labels\"\n: " + list + "\n"},
		{"key joined across U+2029", "? \"data_\\" + ps + "  labels\"\n: " + list + "\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if strings.Contains(c.doc, "data_labels") {
				t.Fatalf("control: the row writes the key out")
			}
			if got, err := fullDecodeLabels([]byte(c.doc), true); err != nil || len(got) == 0 {
				t.Fatalf("control: unbroken, the full decode reads %d labels (%v); the row must spell the key", len(got), err)
			}
			doc := []byte(c.doc + broken)
			if _, err := fullDecodeLabels(doc, true); err == nil {
				t.Fatalf("control: the full decode accepts the broken document")
			}
			if got, err := declaredDataLabels(doc); err == nil {
				t.Errorf("read %v with no error; want the labels unreadable", ids(got))
			}
		})
	}
}
