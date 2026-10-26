package analyzer

import (
	"strings"
	"testing"
)

func TestInterpInertAuthoringAccept(t *testing.T) {
	cases := []struct{ name, body string }{
		{"assert-edit-script", "p = 'notes.txt'\ns = open(p).read()\nold = 'old'\nnew = 'new'\nassert old in s\ns = s.replace(old, new)\nopen(p, 'w').write(s)"},
		{"assert-predicate", "s = 'old text'\nassert s.startswith('old') and s.count('old') == 1"},
		{"assert-message", "old = 'old'\ns = 'old text'\nassert old in s, 'expected old text'"},
		{"assert-message-variable", "message = 'expected text'\nassert True, message"},
		{"assert-message-expression", "assert True, str(1) + ' expected'"},
		{"assert-message-group", "assert True, ('expected text')"},
		{"assert-literal", "assert 'text'"},
		{"assert-multiline", "s = 'old text'\nassert (\n    'old' in s\n), 'expected text'"},
		{"assert-nested", "for line in ['one', 'two']:\n    assert line, 'empty line'\n    print(line)"},
		{"assert-inline", "if True: assert 'text'; print('done')"},
		{"read-replace-chain", "p = 'notes.txt'\nprint(open(p).read().replace('old', 'new'))"},
		{"read-split-index-chain", "p = 'notes.txt'\nprint(open(p).read().splitlines()[0].replace('old', 'new'))"},
		{"rsplit-index-chain", "s = 'one:two'\nprint(s.rsplit(':', 1)[0].replace('one', 'new'))"},
		{"rsplit-call-chain", "print(open('notes.txt').read().rsplit(':', 1)[0])"},
		{"read-index-chain", "print(open('notes.txt').read()[0].replace('a', 'b'))"},
		{"grouped-read-chain", "print((open('notes.txt').read()).replace('old', 'new'))"},
		{"grouped-file-chain", "print((open('notes.txt')).read().replace('old', 'new'))"},
		{"nested-group-chain", "print(((open('notes.txt').read())).replace('old', 'new'))"},
		{"json-call-index", "import json\nprint(json.loads('[1]')[0])"},
		{"path-call-chain", "from pathlib import Path\nprint(Path('notes.txt').read_text().replace('old', 'new'))"},
		{"if-call-colon", "s = 'old text'\nif s.startswith('old'):\n    print('found')"},
		{"while-call-colon", "s = 'old text'\nwhile s.startswith('old'):\n    break"},
		{"with-call-colon", "p = 'notes.txt'\nwith open(p) as f:\n    print(f.read())"},
		{"for-call-colon", "for n in range(2):\n    print(n)"},
		{"string-after-comma", "print('old'.replace('old', 'new'))"},
		{"multiline-comma", "print('old'.replace(\n    'old',\n    'new',\n))"},
		{"number-after-equals", "n = 1\nprint(n)"},
		{"blank-lines", "\n\ns = 'text'\n\n\nprint(s)\n\n"},
		{"indented-blank-lines", "if True:\n\n    s = 'text'\n    \n\n    print(s)\n\nprint('done')"},
		{"inline-assignment", "if True: s = 'text'; print(s)"},
		{"inline-if-blank-else", "if True: print('yes')\n\nelse: print('no')"},
		{"inline-if-comment-elif", "if False: pass\n# comment\n\nelif True: pass\n\nelse: pass"},
		{"nested-inline-if-blank-else", "for n in range(2):\n    if True: pass\n\n    else: print(n)\n\nprint('done')"},
		{"unicode-literal", "print('café 日本語 🐍')"},
		{"unicode-comment", "# café 日本語 🐍\nprint('text')"},
		{"unicode-escape-data", "print('\\u00e9')"},
		{"slice-bounds", "s = 'old text'\na = 1\nb = 3\nprint(s[a:b].replace('ld', 'new'))"},
		{"slice-start-omitted", "s = 'old text'\nstart = 3\nnew = 'new'\ns = s[:start] + new\nprint(s)"},
		{"slice-end-omitted", "s = 'old text'\nstart = 3\nprint(s[start:])"},
		{"slice-both-omitted", "s = 'old text'\nprint(s[:])"},
		{"slice-call-bounds", "s = 'old text'\nprint(s[s.index('o'):s.index('t')])"},
		{"slice-call-result", "print(open('notes.txt').read()[1:3].replace('old', 'new'))"},
		{"slice-list", "items = ['one', 'two', 'three']\nprint(items[1:3])"},
		{"slice-list-method", "items = ['one', 'two', 'three']\nitems[:2].append('four')"},
		{"slice-fresh-text-list", "print('one\\ntwo'.splitlines()[:1][0].replace('one', 'three'))"},
		{"augmented-plus", "n = 0\nn += 1\nassert n == 1"},
		{"augmented-minus", "n = 2\nn -= 1\nassert n == 1"},
		{"augmented-text", "s = 'old'\ns += ' text'\nprint(s.replace('old', 'new'))"},
		{"augmented-list", "items = ['one']\nitems += ['two']\nprint(items)"},
		{"augmented-set", "items = set(['one', 'two'])\nitems -= set(['one'])\nprint(items)"},
		{"inline-augmented-continue", "n = 0\nfor l in ['one', 'two']:\n    if 'o' in l: n += 1; continue\n    print(l)"},
		{"augmented-safe-destination", "p = 'notes'\np += '.txt'\nopen(p, 'w').write('text')"},
		{"with-bound-file", "p = 'notes.txt'\ns = 'text'\nwith open(p, 'w') as f:\n    f.write(s)"},
		{"blank-lines-before-dedent", "with open('notes.txt', 'a') as f:\n    f.write('text')\n\n\nprint('done')"},
		{"blank-lines-before-eof-dedent", "with open('notes.txt', 'a') as f:\n    f.write('text')\n\n\n"},
		{"tuple-then-string-arg", "print(('one', 'two'), 'three')"},
		{"singleton-tuple-then-string-arg", "print(('one',), 'two')"},
		{"nested-call-then-string-arg", "import os\nt = 'docs'\nk = 'notes'\nprint(open(os.path.join(t, k + '.txt'), 'r').read())"},
		{"write-encoding-chain", "p = 'notes.txt'\ns = 'text'\nopen(p, 'w', encoding='utf-8').write(s)"},
		{"write-concatenated-path-chain", "k = 'notes'\nv = 'text'\nopen(k + '.txt', 'w').write(v)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !closedInertBody("python3", tc.body) || !interpHeredocExecFree("python3", tc.body) {
				t.Fatal("admitted authoring form rejected")
			}
			assertInterpSpanSubset(t, tc.name, "python3", tc.body, tc.body)
		})
	}
}

func TestInterpInertAuthoringReject(t *testing.T) {
	cases := []struct{ name, body string }{
		{"assert-call", "assert eval('payload')"},
		{"assert-message-call", "assert True, eval('payload')"},
		{"assert-message-nonstring", "assert True, [1]"},
		{"assert-message-tuple", "assert True, ('text',)"},
		{"assert-callback", "import re\nassert re.sub('x', eval, 'x')"},
		{"assert-missing-predicate", "assert"},
		{"assert-missing-message", "assert True,"},
		{"assert-extra-message", "assert True, 'one', 'two'"},
		{"chain-unknown-method", "open('notes.txt').read().execute('payload')"},
		{"chain-unknown-root", "danger('notes.txt').read().replace('old', 'new')"},
		{"chain-computed-call", "open('notes.txt').read().splitlines()[0]()"},
		{"chain-index-call", "open('notes.txt').read()[eval('0')]"},
		{"chain-format", "open('notes.txt').read().format('payload')"},
		{"chain-dunder", "open('notes.txt').read().__class__()"},
		{"chain-file-provenance", "open('notes.txt').read().splitlines()[0].write('payload')"},
		{"grouped-path-rename", "from pathlib import Path\n(Path('notes.txt')).replace('.bashrc')"},
		{"tuple-path-rename", "from pathlib import Path\n(Path('notes.txt'),)[0].replace('.bashrc')"},
		{"assert-does-not-prove-destination", "import sys\np = sys.argv[1]\nassert p == 'notes.txt'\nopen(p, 'w').write('payload')"},
		{"def-colon", "def edit():\n    pass"},
		{"with-without-as", "with open('notes.txt'):\n    pass"},
		{"multiple-with", "with open('one.txt') as a, open('two.txt') as b:\n    pass"},
		{"tuple-assignment", "old, new = 'old', 'new'"},
		{"augmented-unknown-call", "n = 0\nn += danger('payload')"},
		{"augmented-minus-unknown-call", "n = 0\nn -= danger('payload')"},
		{"augmented-unbound", "n += 1"},
		{"augmented-root", "open += 1"},
		{"augmented-module", "import sys\nsys += [1]"},
		{"augmented-dunder", "__builtins__ += [1]"},
		{"augmented-attribute", "import sys\nsys.argv += ['one']"},
		{"augmented-file", "f = open('notes.txt')\nf += 'text'"},
		{"augmented-deferred", "p = '.'\np += 'bashrc'\nopen(p, 'w').write('payload')"},
		{"augmented-next-iteration", "p = 'notes'\nfor n in [1, 2]:\n    open(p, 'w').write('payload')\n    p += '.bashrc'"},
		{"augmented-zero-iteration", "p = '.bashrc'\nfor n in []:\n    p += '.bak'\nopen(p, 'w').write('payload')"},
		{"augmented-in-predicate-loop", "p = 'notes'\nwhile open(p, 'w').write('payload'):\n    p += '.bashrc'"},
		{"augmented-separated-operator", "n = 0\nn + = 1"},
		{"slice-start-call", "s = 'text'\nprint(s[eval('0'):2])"},
		{"slice-end-call", "s = 'text'\nprint(s[:eval('2')])"},
		{"slice-upper-unknown", "s = 'text'\nprint(s[1:danger('payload')])"},
		{"slice-step", "s = 'text'\nprint(s[::1])"},
		{"slice-path", "from pathlib import Path\nprint(Path('notes.txt')[:1])"},
		{"slice-file", "print(open('notes.txt')[:1])"},
		{"slice-empty-index", "s = 'text'\nprint(s[])"},
		{"slice-deferred-destination", "p = '.bashrc.bak'\nopen(p[:7], 'w').write('payload')"},
		{"slice-path-container-rename", "from pathlib import Path\nitems = [Path('notes.txt')]\nitems[:1][0].replace('.bashrc')"},
		{"slice-list-callable", "items = ['text']\nitems[:1][0]()"},
		{"rsplit-computed-call", "'one:two'.rsplit(':', 1)[0]()"},
		{"rsplit-unknown-argument", "'one:two'.rsplit(danger('payload'))"},
		{"with-nonadmitted-write", "with open('notes.txt', 'w') as f:\n    f.execute('payload')"},
		{"with-dynamic-write", "import sys\nwith open(sys.argv[1], 'w') as f:\n    f.write('payload')"},
		{"blank-lines-unknown-call", "with open('notes.txt', 'a') as f:\n    f.write('text')\n\n\ndanger('payload')"},
		{"tuple-then-unknown-argument", "print(('one', 'two'), danger('payload'))"},
		{"tuple-with-unknown-call", "print(('one', danger('payload')), 'two')"},
		{"tuple-path-component", "import sys, os\nprint(open(os.path.join('docs', sys.argv[1]), 'w'))"},
		{"inline-unknown-continue", "for n in [1]:\n    if True: danger('payload'); continue"},
		{"write-encoding-dynamic-chain", "import sys\nopen(sys.argv[1], 'w', encoding='utf-8').write('payload')"},
		{"write-concatenated-dynamic-chain", "import sys\nopen(sys.argv[1] + '.txt', 'w').write('payload')"},
		{"signed-number", "n = -1"},
		{"fractional-number", "n = 1.5"},
		{"unexpected-indent", "print('one')\n\n    print('two')"},
		{"missing-suite-indent", "if True:\n\nprint('text')"},
		{"inline-blank-unknown-else", "if True: pass\n\nelse: danger('payload')"},
		{"inline-blank-unknown-elif", "if True: pass\n\nelif danger('payload'): pass"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if closedInertBody("python3", tc.body) || interpHeredocExecFree("python3", tc.body) {
				t.Fatal("unsupported/unsafe authoring form accepted")
			}
		})
	}
}

// Distinguish lexical failures from parser failures. Token stop counts alone
// cannot identify which of these forms occurs in the unavailable audit bodies.
func TestInterpInertAuthoringScanner(t *testing.T) {
	cases := []struct {
		name, body  string
		scan, inert bool
	}{
		{"f-string", `print(f'{value}')`, true, false},
		{"raw-f-string", `print(rf'{value}')`, true, false},
		{"interpolated-call", `print(f'{eval("payload")}')`, true, false},
		{"template-string", `print(t'{value}')`, true, false},
		{"bytes-prefix", `print(b'text')`, true, true},
		{"raw-bytes-prefix", `print(rb'text')`, true, true},
		{"unicode-prefix", `print(u'text')`, true, true},
		{"raw-prefix", `print(r'\btext')`, true, true},
		{"explicit-continuation", "s = 'one' + \\\n    'two'", false, false},
		{"string-continuation", "s = 'one\\\ntwo'", false, false},
		{"implicit-continuation", "print(\n    'text'\n)", true, true},
		{"unicode-text", "print('café 日本語 🐍')", true, true},
		{"unicode-comment", "# café\nprint('text')", true, true},
		{"unicode-identifier", "café = 'text'", false, false},
		{"nonascii-space", "s\u00a0= 'text'", false, false},
		{"smart-quotes", "print(“text”)", false, false},
		{"utf8-bom", "\ufeffprint('text')", false, false},
		{"encoding-cookie", "# coding: utf-8\nprint('text')", false, false},
		{"percent-format", "print('%s' % 'text')", false, false},
		{"multiplication", "n = 2 * 3", false, false},
		{"division", "n = 2 / 3", false, false},
		{"decorator", "@print\ndef edit():\n    pass", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, scan := scanInertBody("python3", tc.body)
			inert := closedInertBody("python3", tc.body)
			if scan != tc.scan || inert != tc.inert {
				t.Fatalf("scan=%v inert=%v; want scan=%v inert=%v", scan, inert, tc.scan, tc.inert)
			}
		})
	}
}

func TestInterpInertAuthoringAssertExclusion(t *testing.T) {
	body := "p = 'notes.txt'\ns = open(p).read()\nold = 'export HOME=/tmp/old'\nnew = 'documented example'\nassert old in s, 'expected example'\ns = s.replace(old, new)\nopen(p, 'w').write(s)\n"
	command := "python3 - <<'PY'\n" + body + "PY"
	if !PositionExcluded(command, []string{LabelPosInterpHeredocLiteral}, nil, func(s string) bool {
		return strings.Contains(s, "export HOME=")
	}) {
		t.Fatal("assert edit script did not excuse its data literal")
	}
}

func TestInterpInertAuthoringPrefixes(t *testing.T) {
	for _, prefix := range []string{"b", "B", "rb", "rB", "Rb", "RB", "br", "bR", "Br", "BR", "u", "U"} {
		t.Run(prefix, func(t *testing.T) {
			for _, literal := range []string{"'text'", `"text"`, "'''first\nsecond'''", `"""text"""`} {
				body := "print(" + prefix + literal + ")"
				if !interpHeredocExecFree("python3", body) {
					t.Fatalf("pure literal prefix %s rejected", prefix)
				}
				_, spans, ok := scanInertBody("python3", body)
				if !ok || len(spans) != 1 || body[spans[0][0]:spans[0][1]] != literal {
					t.Fatal("prefix changed literal span boundaries")
				}
				assertInterpSpanSubset(t, prefix, "python3", body, body)
			}
			if interpHeredocExecFree("python3", "open("+prefix+"'.bashrc', 'w').write('payload')") {
				t.Fatal("literal prefix bypassed deferred destination gate")
			}
		})
	}
	for _, body := range []string{
		`open(b'notes.txt', 'wb').write(b'text')`,
		`print(rb'\btext'.replace(b'text', b'other'))`,
		`print(br'\btext')`,
		`print(u'café 日本語 🐍')`,
		`assert b'text', u'message'`,
	} {
		t.Run("data/"+body, func(t *testing.T) {
			if !interpHeredocExecFree("python3", body) {
				t.Fatal("pure prefixed data rejected")
			}
		})
	}
	for _, prefix := range []string{"f", "F", "rf", "fr", "Rf", "fR", "t", "rt", "tr", "bf", "fb", "ur", "ru", "bb", "rr", "bu", "ub"} {
		t.Run("reject/"+prefix, func(t *testing.T) {
			if interpHeredocExecFree("python3", "print("+prefix+"'{eval(\"payload\")}')") {
				t.Fatal("interpolating/unsupported prefix accepted")
			}
		})
	}
	for _, body := range []string{
		`print(b'café')`,
		`print(rb'日本語')`,
		`print(b'text'.decode())`,
		`print(u'text'.encode())`,
		`open(b'\x2ebashrc', 'w').write(b'payload')`,
		`open(u'\u002ebashrc', 'w').write('payload')`,
		`b'callable'()`,
		`rb'callable'()`,
		`u'callable'()`,
	} {
		t.Run("reject/"+body, func(t *testing.T) {
			if interpHeredocExecFree("python3", body) {
				t.Fatal("unsafe/unsupported prefix use accepted")
			}
		})
	}
}
