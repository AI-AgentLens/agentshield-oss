package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"unicode/utf8"

	"github.com/AI-AgentLens/agentshield/internal/safefile"
	"github.com/AI-AgentLens/agentshield/packs"
	"gopkg.in/yaml.v3"
)

// The data labels a fail-safe record is scrubbed with (#4805).
//
// The hook's fail-safe reading (internal/cli/fail_safe.go) records a call it
// could not evaluate. When it stopped before the shell policy was loaded (the
// config, the audit log or the policy itself failed, or the decision budget
// answered first), it has no label set to scrub the record with, and #4448's
// guarantee (the record never carries the value it stopped) needs one. So it
// reads the data_labels declarations on their own: every file decoded whole,
// as the full load decodes it (so every encoding and spelling yaml.v3 reads
// is read), and only a file the full load refuses read for its block alone.

// DeclaredLabelsError says which source of data_labels could not be read.
// Source is a file path, a pack's label or a directory; never file content.
type DeclaredLabelsError struct {
	Source string
	Err    error
}

func (e *DeclaredLabelsError) Error() string { return e.Source + ": " + e.Err.Error() }
func (e *DeclaredLabelsError) Unwrap() error { return e.Err }

// LoadDeclaredDataLabels returns the data_labels the shell hook's policy
// declares, in the order the full load merges them: DefaultPolicy's, the user
// policy file's (Load), every enabled embedded community shell pack's
// (LoadEmbeddedShellPacks), and every enabled pack LoadPacks reads from
// packsDir (walkShellPackTree, the walker LoadPacks itself uses).
//
// Each source is decoded whole, as the full load decodes it, and only a file
// the full load refuses is read for its data_labels block alone
// (declaredDataLabels), so a file broken elsewhere still gives up its labels.
// err is non-nil when a source that could
// declare labels could not be read: the policy file or an enabled pack
// unreadable, or its data_labels unparsable, or packsDir unlistable. It wraps
// a *DeclaredLabelsError for each. A missing policy file or packs directory
// declares none and is not an error. The labels that could be read are
// returned either way; a caller that must not record a label value treats any
// error as "the label set is unknown".
func LoadDeclaredDataLabels(policyPath, packsDir string) ([]DataLabel, error) {
	labels := append([]DataLabel(nil), DefaultPolicy().DataLabels...)
	var errs []error

	if data, err := safefile.ReadFile(policyPath); err == nil {
		dl, err := declaredDataLabels(data)
		if err != nil {
			errs = append(errs, &DeclaredLabelsError{Source: policyPath, Err: err})
		}
		labels = append(labels, dl...)
	} else if !os.IsNotExist(err) {
		errs = append(errs, &DeclaredLabelsError{Source: policyPath, Err: err})
	}

	hooks := func() PackLoadHooks[declaredLabelsPack] {
		return PackLoadHooks[declaredLabelsPack]{
			Parse: func(data []byte, label string) (*declaredLabelsPack, error) {
				dl, err := declaredDataLabels(data)
				if err != nil {
					return nil, err
				}
				return &declaredLabelsPack{labels: dl}, nil
			},
			Describe: func(*declaredLabelsPack) PackInfo { return PackInfo{} },
			Merge:    func(p *declaredLabelsPack) { labels = append(labels, p.labels...) },
		}
	}
	collect := func(infos []PackInfo) {
		// A disabled pack is never merged, so its labels are not in force
		// and a failure to read it hides none.
		for _, info := range infos {
			if info.LoadError != nil && info.Enabled {
				errs = append(errs, &DeclaredLabelsError{Source: info.Path + " (" + info.Name + ")", Err: info.LoadError})
			}
		}
	}

	collect(LoadPackSources(EmbeddedPackSources(embeddedShellFiles()), hooks()))

	if packsDir != "" {
		infos, err := walkShellPackTree(packsDir, hooks())
		if err != nil && !os.IsNotExist(err) {
			errs = append(errs, &DeclaredLabelsError{Source: packsDir, Err: err})
		}
		collect(infos)
	}
	return labels, errors.Join(errs...)
}

// embeddedShellFiles is the embedded community shell packs the read takes:
// packs.ShellFiles, what LoadEmbeddedShellPacks merges. A variable only so a
// test can hand the read an embedded pack that declares labels, which no
// shipped community pack does today.
var embeddedShellFiles = packs.ShellFiles

// declaredLabelsPack is one pack as LoadDeclaredDataLabels reads it.
type declaredLabelsPack struct{ labels []DataLabel }

// dataLabelsDoc is the one field of a policy file or pack declaredDataLabels
// decodes.
type dataLabelsDoc struct {
	DataLabels []DataLabel `yaml:"data_labels"`
}

// dataLabelsHeader is a top-level `data_labels:` key opening a block
// collection.
var dataLabelsHeader = regexp.MustCompile(`^data_labels[ \t]*:[ \t]*(#.*)?\r?\n?$`)

// declaredDataLabels returns the data_labels of one policy file or pack.
//
// The whole document is decoded first, as the full load (Load, LoadPacks)
// decodes it, so every encoding and spelling yaml.v3 reads is read the same
// way: UTF-16 with a byte-order mark, an escaped key ("data\x5flabels"), a
// !!binary key, a line break yaml.v3 counts that a split on "\n" does not
// (#4805 Codex F1, Opus pass 1 follow-up 1). When the document decodes, its
// labels are the answer, the full load's own.
//
// Only a document the full load refuses falls back to reading the top-level
// `data_labels:` block on its own: the labels are what the record needs, and
// the full load drops the whole file. That read works on raw text, so it
// runs only on text that cannot spell the key where the raw text does not
// show it (blockReadTrusted), names the key exactly once outside whole-line
// comments, and has it as a block-style top-level key whose block ends at
// the next top-level key or the end of the file. A broken document that
// meets those and never names the key declares none. Anything else is an
// error: the labels are unreadable, never "none".
func declaredDataLabels(data []byte) ([]DataLabel, error) {
	var doc dataLabelsDoc
	err := yaml.Unmarshal(data, &doc)
	if err == nil {
		return doc.DataLabels, nil
	}
	if !blockReadTrusted(data) {
		return nil, fmt.Errorf("data_labels: the document does not decode and its text can spell the key out of sight: %w", err)
	}
	switch countKeyOutsideComments(data, "data_labels") {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, fmt.Errorf("data_labels: the document does not decode and names the key more than once: %w", err)
	}
	block, ok := topLevelDataLabelsBlock(data)
	if !ok {
		return nil, fmt.Errorf("data_labels: the document does not decode and has no block the block read can take: %w", err)
	}
	var bd dataLabelsDoc
	if err := yaml.Unmarshal(block, &bd); err != nil {
		return nil, fmt.Errorf("data_labels: %w", err)
	}
	return bd.DataLabels, nil
}

// blockReadTrusted reports whether a document's raw text shows every way it
// could spell the data_labels key, so the key count and the block read can
// rely on it. It must be UTF-8 with no byte-order mark, with no control
// character but tab, line feed and carriage return, and no line break that
// yaml.v3 counts and a split on "\n" does not (U+0085, U+2028, U+2029). It
// must hold no escape that can write a letter (\x, \u, \U) or join two lines
// (a backslash before a line break), and no tag syntax that can decode a
// scalar into other text: "!!" (the secondary handle, binary among it, and
// its %-escaped spellings), a verbatim tag "!<", or "!%" (a %-escaped suffix
// on the primary handle: yaml.v3 reads "!%21binary" as "!!binary"). And it
// must hold no directive line: a %TAG directive can name binary under
// another handle ("%TAG !e! tag:yaml.org,2002:" makes "!e!binary" a base64
// key), and the key count runs before the block read sees the directive, so
// such a text read as declaring no labels (#4814 item 6).
func blockReadTrusted(data []byte) bool {
	if !utf8.Valid(data) || bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) || hasDirectiveLine(data) {
		return false
	}
	for _, r := range string(data) {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	for _, s := range []string{`\x`, `\u`, `\U`, "\\\n", "\\\r", "!!", "!<", "!%"} {
		if bytes.Contains(data, []byte(s)) {
			return false
		}
	}
	return true
}

// hasDirectiveLine reports whether a line of data starts with "%", which
// yaml.v3 reads as a directive: at the start of the text or after a line
// feed or carriage return.
func hasDirectiveLine(data []byte) bool {
	for i := 0; ; {
		j := bytes.IndexByte(data[i:], '%')
		if j < 0 {
			return false
		}
		at := i + j
		if at == 0 || data[at-1] == '\n' || data[at-1] == '\r' {
			return true
		}
		i = at + 1
	}
}

// countKeyOutsideComments counts the times key appears on a line that is not
// a whole-line comment.
func countKeyOutsideComments(data []byte, key string) int {
	n := 0
	k := []byte(key)
	for from := 0; ; {
		i := bytes.Index(data[from:], k)
		if i < 0 {
			return n
		}
		at := from + i
		lineStart := bytes.LastIndexByte(data[:at], '\n') + 1
		if trimmed := bytes.TrimLeft(data[lineStart:at], " \t"); len(trimmed) == 0 || trimmed[0] != '#' {
			n++
		}
		from = at + len(k)
	}
}

// topLevelDataLabelsBlock returns the `data_labels:` line and the lines of
// its value, or false when the block read does not apply.
func topLevelDataLabelsBlock(data []byte) ([]byte, bool) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	start := -1
	for i, line := range lines {
		if bytes.HasPrefix(line, []byte("---")) || bytes.HasPrefix(line, []byte("...")) || bytes.HasPrefix(line, []byte("%")) {
			return nil, false
		}
		if dataLabelsHeader.Match(line) {
			if start >= 0 {
				return nil, false
			}
			start = i
		}
	}
	if start < 0 {
		return nil, false
	}
	var block bytes.Buffer
	block.Write(lines[start])
	for _, line := range lines[start+1:] {
		if len(line) > 0 && !continuesTopLevelValue(line) {
			// The block ends at the next top-level key. Any other line here
			// (a stray scalar, a closing bracket) leaves the document's shape
			// unknown, and a label after it would go unread.
			if !topLevelKeyLine.Match(line) {
				return nil, false
			}
			break
		}
		block.Write(line)
	}
	return block.Bytes(), true
}

// topLevelKeyLine is a line that opens another top-level key: a plain
// identifier-like key, or a quoted one, then a colon and a blank or the end
// of the line.
var topLevelKeyLine = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_.\-]*|"[^"\\]*"|'[^']*')[ \t]*:([ \t]|\r?\n?$)`)

// continuesTopLevelValue reports whether a line can belong to the value of
// the top-level key above it: indented, a comment, empty, or an entry of a
// block sequence written in column 0 ("-" then a blank or the line's end).
func continuesTopLevelValue(line []byte) bool {
	switch line[0] {
	case ' ', '\t', '#', '\n', '\r':
		return true
	case '-':
		return len(line) == 1 || line[1] == ' ' || line[1] == '\t' || line[1] == '\n' || line[1] == '\r'
	}
	return false
}
