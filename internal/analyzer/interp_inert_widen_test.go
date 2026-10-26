package analyzer

import (
	"fmt"
	"strings"
	"testing"
)

func TestInterpInertWidenAccept(t *testing.T) {
	cases := []struct{ name, body string }{
		{"for", "for name in ['one', 'two']:\n    print(name)"},
		{"for-unpack", "for a, b in [('one', 'two')]:\n    print(a, b)"},
		{"for-enumerate", "for i, line in enumerate(['one', 'two']):\n    print(i, line.strip())"},
		{"for-zip", "for a, b in zip(['one'], ['two']):\n    print(a, b)"},
		{"for-sorted", "for line in sorted(['two', 'one'], reverse=True):\n    print(line)"},
		{"for-items", "data = {'one': 'two'}\nfor key, value in data.items():\n    print(key, value)"},
		{"for-splitlines", "for line in 'one\\ntwo'.splitlines():\n    print(line.replace('one', 'three'))"},
		{"for-text-list", "for line in ['one', 'two']:\n    print(line.replace('one', 'three'))"},
		{"for-sorted-text", "for line in sorted('one\\ntwo'.splitlines()):\n    print(line.replace('one', 'three'))"},
		{"for-file-text", "for line in open('notes.txt'):\n    print(line.replace('one', 'three'))"},
		{"fresh-text-index", "print('one\\ntwo'.splitlines()[0].replace('one', 'three'))"},
		{"while", "i = 0\nwhile i < 3:\n    i = i + 1\n    print(i)"},
		{"if-elif-else", "n = 2\nif n == 1:\n    print('one')\nelif n == 2:\n    print('two')\nelse:\n    print('other')"},
		{"break-continue-pass", "for line in ['one', 'two']:\n    if line.startswith('o'):\n        continue\n    elif line.endswith('o'):\n        break\n    else:\n        pass"},
		{"nested-loops", "for a in range(3):\n    for b in range(2):\n        if a != b:\n            print(a, b)\n    print(a)\nprint('done')"},
		{"inline-suites", "for x in range(2): print(x); pass\nif True: pass\nelif False: pass\nelse: print('done')"},
		{"blank-comments", "for x in [1]:\n\n    # comments do not change indentation\n    print(x)\n    # another comment\n\nprint('done')"},
		{"tab-suite", "for x in [1]:\n\tprint(x)"},
		{"crlf-suite", "for x in [1]:\r\n    print(x)\r\nprint('done')"},
		{"cr-suite", "for x in [1]:\r    print(x)\rprint('done')"},
		{"multiline-values", "for x in sorted([\n    'two',\n    'one',\n]):\n    print(\n        x,\n    )"},
		{"triple-string-suite", "for x in [1]:\n    text = '''one\nzero indentation\n  two'''\n    print(text)"},
		{"raw-string-suite", "if True:\n    text = r'one\\ntwo'\n    print(text)"},
		{"with-suite", "with open('notes.txt', 'w') as f:\n    for line in ['one', 'two']:\n        f.write(line)\nprint('done')"},
		{"predicate-call", "if any([True, False]) and len('data') > 0:\n    print('yes')"},
		{"predicate-method", "if 'data'.startswith('d') or 'data'.endswith('a'):\n    print('yes')"},
		{"predicate-parentheses", "n = 2\nif not (n < 1 or n > 3) and n in [1, 2, 3]:\n    pass"},
		{"conditional-call", "label = 'yes' if len('data') > 0 else 'no'\nprint(label)"},
		{"conditional-text-method", "text = 'one' if len('data') > 0 else 'two'\nprint(text.replace('one', 'three'))"},
		{"branch-text-method", "text = 'one'\nif True:\n    text = 'two'\nprint(text.replace('one', 'three'))"},
		{"concatenated-text-method", "text = open('notes.txt').read() + 'one'\nprint(text.replace('one', 'three'))"},
		{"branch-same-path", "if True:\n    dest = 'notes.txt'\nelse:\n    dest = 'notes.txt'\nopen(dest, 'w').write('data')"},
		{"branch-readonly", "dest = 'one.txt'\nif True:\n    dest = 'two.txt'\nprint(open(dest).read())"},
		{"loop-constant-write", "for line in ['one', 'two']:\n    dest = 'notes.txt'\n    open(dest, 'a').write(line)"},
		{"sys-argv-filename", "import sys\ntext = open(sys.argv[1]).read()\nopen('notes.txt', 'w').write(text.replace('one', 'two'))"},
		{"sys-argv-read-mode", "import sys\nwith open(sys.argv[1], mode='r', encoding='utf-8') as f:\n    print(f.readlines())"},
		{"io-argv-read", "import io, sys\nprint(io.open(sys.argv[1], 'rt').read())"},
		{"sys-exit", "import sys\nsys.exit(0)"},
		{"sys-stdout", "import sys\nsys.stdout.write('data')"},
		{"sys-stderr", "import sys\nsys.stderr.write('data')"},
		{"glob-files", "import glob\nfor filename in glob.glob('docs/*.md'):\n    text = open(filename).read()\n    open('combined.md', 'a').write(text.replace('one', 'two'))"},
		{"iglob", "import glob\nfor filename in glob.iglob('docs/*.md'):\n    print(filename)"},
		{"os-listdir", "import os\nfor filename in os.listdir('docs'):\n    print(filename)"},
		{"os-walk", "import os\nfor root, dirs, files in os.walk('docs'):\n    print(root, dirs, files)"},
		{"os-makedirs", "import os\nos.makedirs('docs/generated', exist_ok=True)"},
		{"readlines", "lines = open('notes.txt').readlines()\nprint(lines)"},
		{"writelines", "open('notes.txt', 'w').writelines(['one', 'two'])"},
		{"regex-group", "import re\nmatch = re.search('(one)', 'one')\nif match:\n    print(match.group(1))"},
		{"regex-groups", "import re\nprint(re.match('(one)', 'one').groups())"},
		{"regex-finditer", "import re\nfor match in re.finditer('(one)', 'one one'):\n    print(match.group(1))"},
		{"regex-fullmatch", "import re\nif re.fullmatch('one', 'one'):\n    print('match')"},
	}
	for _, expr := range []string{
		"sorted([2, 1], reverse=True)", "enumerate(['one'])", "range(3)",
		"min([2, 1])", "max(1, 2)", "sum([1, 2])", "set(['one'])",
		"list(('one',))", "dict([('one', 'two')])", "tuple(['one'])", "int('2')",
		"float('2.5')", "bool('one')", "any([True, False])", "all([True, True])",
		"zip(['one'], ['two'])", "isinstance('one', str)", "isinstance(1, (str, int))", "reversed(['one', 'two'])",
	} {
		cases = append(cases, struct{ name, body string }{"builtin/" + expr, "print(" + expr + ")"})
	}
	for _, expr := range []string{
		"data.append('two')", "data.extend(['two'])", "data.insert(0, 'two')",
		"data.pop()", "data.count('one')", "data.index('one')", "data.sort(reverse=True)",
	} {
		cases = append(cases, struct{ name, body string }{"list/" + expr, "data = ['one']\n" + expr})
	}
	for _, expr := range []string{
		"data.update({'two': 'value'})", "data.setdefault('two', 'value')", "data.items()",
		"data.keys()", "data.values()", "data.get('one')", "data.pop('one')",
	} {
		cases = append(cases, struct{ name, body string }{"dict/" + expr, "data = {'one': 'value'}\n" + expr})
	}
	for _, method := range []string{"count", "index", "find", "rfind", "startswith", "endswith", "partition", "rpartition"} {
		cases = append(cases, struct{ name, body string }{"string/" + method, "print('one two'." + method + "('one'))"})
	}
	for _, method := range []string{"exists()", "is_file()", "is_dir()", "glob('*.md')", "rglob('*.md')", "mkdir(parents=True, exist_ok=True)"} {
		cases = append(cases, struct{ name, body string }{"path/" + method, "from pathlib import Path\nPath('docs')." + method})
	}
	for _, method := range []string{"exists", "isfile", "isdir", "relpath", "abspath", "splitext"} {
		cases = append(cases, struct{ name, body string }{"os-path/" + method, "import os\nprint(os.path." + method + "('docs/notes.md'))"})
	}
	for _, predicate := range []string{"n == 2", "n != 1", "n < 3", "n > 1", "n <= 2", "n >= 2", "n in [2]", "n not in [3]", "None is None", "not False", "True and True", "False or True", "1 < n < 3"} {
		cases = append(cases, struct{ name, body string }{"predicate/" + predicate, "n = 2\nif " + predicate + ":\n    pass"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body + "\nprint('export HOME=/tmp/inert-example')\n"
			if !closedInertBody("python3", body) || !interpHeredocExecFree("python3", body) {
				t.Fatalf("benign body rejected:\n%s", body)
			}
			if !reviewLegacyExecFree("python3", body) {
				t.Fatal("acceptance escaped the frozen legacy gate")
			}
			assertInterpSpanSubset(t, tc.name, "python3", body, body)
			// CR/CRLF exercise Python layout directly; shell heredoc extraction
			// has its own unchanged treatment of carriage returns.
			if strings.ContainsRune(body, '\r') {
				return
			}
			command := "python3 - <<'PY'\n" + body + "PY"
			if !PositionExcluded(command, []string{LabelPosInterpHeredocLiteral}, nil, func(s string) bool {
				return strings.Contains(s, "export HOME=")
			}) {
				t.Fatal("accepted body did not excuse its literal in a heredoc")
			}
		})
	}
}

func TestInterpInertWidenReject(t *testing.T) {
	cases := []struct{ name, body string }{
		{"for-call", "for x in [1]:\n    danger('payload')"},
		{"if-call", "if True:\n    danger('payload')"},
		{"elif-call", "if False:\n    pass\nelif True:\n    danger('payload')"},
		{"else-call", "if False:\n    pass\nelse:\n    danger('payload')"},
		{"while-call", "while True:\n    danger('payload')"},
		{"iterable-call", "for x in danger('payload'):\n    print(x)"},
		{"nested-def", "for x in [1]:\n    def f():\n        print('payload')"},
		{"nested-class", "if True:\n    class C:\n        pass"},
		{"nested-decorator", "for x in [1]:\n    @print\n    def f():\n        pass"},
		{"nested-lambda", "for x in [1]:\n    f = lambda: print('payload')"},
		{"nested-import", "for x in [1]:\n    import subprocess"},
		{"conditional-exec", "if eval('payload'):\n    pass"},
		{"while-exec", "while eval('payload'):\n    pass"},
		{"dead-branch-exec", "if False:\n    eval('payload')"},
		{"short-circuit-exec", "if False and eval('payload'):\n    pass"},
		{"nested-predicate-call", "if len(eval('payload')) > 0:\n    pass"},
		{"predicate-callback", "import re\nif re.sub('x', eval, 'payload'):\n    pass"},
		{"predicate-container-callback", "import re\nif re.sub('x', [eval][0], 'payload'):\n    pass"},
		{"predicate-callback-method", "data = ['payload']\nif data.sort(eval):\n    pass"},
		{"predicate-index-exec", "data = ['payload']\nif data[eval('0')]:\n    pass"},
		{"sys-no-import", "print(sys.argv[1])"},
		{"sys-alias", "import sys as s\nprint(s.argv)"},
		{"sys-from", "from sys import argv\nprint(argv)"},
		{"sys-call-alias", "import sys\nf = sys.exit\nf(0)"},
		{"sys-stream-alias", "import sys\nf = sys.stdout\nf.write('payload')"},
		{"sys-stream-other-method", "import sys\nsys.stdout.flush()"},
		{"sys-argv-call", "import sys\nsys.argv('payload')"},
		{"sys-argv-assignment", "import sys\nsys.argv = ['payload']"},
		{"sys-computed", "import sys\nsys.argv[1]('payload')"},
		{"sorted-key", "sorted(['one'], key=str)"},
		{"sorted-key-none", "sorted(['one'], key=None)"},
		{"sort-key", "data = ['one']; data.sort(key=None)"},
		{"builtin-keyword", "list(iterable=['one'])"},
		{"min-key", "min(['one'], key=str)"},
		{"zip-strict", "zip(['one'], strict=True)"},
		{"mkdir-keyword", "from pathlib import Path\nPath('docs').mkdir(mode=1)"},
		{"makedirs-keyword", "import os\nos.makedirs(name='docs', exist_ok=True)"},
		{"glob-keyword", "import glob\nglob.glob('docs/*', root_dir='/etc')"},
		{"isinstance-custom", "isinstance('one', Custom)"},
		{"isinstance-computed", "isinstance('one', eval('str'))"},
		{"type-alias", "kind = str\nprint(kind)"},
		{"type-container", "kinds = [str]\nprint(kinds)"},
		{"for-attribute-target", "import sys\nfor sys.argv in [1]:\n    pass"},
		{"for-subscript-target", "data = [1]\nfor data[0] in [2]:\n    pass"},
		{"for-dunder-target", "for __builtins__ in [1]:\n    pass"},
		{"for-unpack-shadow", "for x, open in [(1, 2)]:\n    pass"},
		{"with-shadow", "with open('notes.txt') as sys:\n    pass"},
		// `with` admits only a file value (Kai's mutation check, 2026-10-19: dropping
		// the kind gate failed nothing). No admitted non-file value has a context
		// manager that executes, so this pins a defence-in-depth gate.
		{"with-non-file-text", "with 'notes.txt' as f:\n    pass"},
		{"with-non-file-list", "with ['notes.txt'] as f:\n    pass"},
		{"dunder-read", "data = []\nif data.__class__:\n    pass"},
		{"getattr", "data = []\ngetattr(data, 'append')('payload')"},
		{"f-string", "for x in [1]:\n    print(f'{x}')"},
		{"format", "for x in [1]:\n    print('{}'.format(x))"},
		{"encode", "for x in ['one']:\n    print(x.encode())"},
		{"decode", "for x in ['one']:\n    print(x.decode())"},
		{"comprehension-call", "data = [eval(x) for x in ['payload']]"},
		{"plain-comprehension", "data = [x for x in ['payload']]"},
		{"unexpected-indent", "print('one')\n    print('two')"},
		{"missing-indent", "for x in [1]:\nprint(x)"},
		{"inconsistent-dedent", "for x in [1]:\n    print(x)\n  print(x)"},
		{"mixed-indent", "for x in [1]:\n\tprint(x)\n        print(x)"},
		{"empty-suite", "if True:\n    # comment\nprint('one')"},
		{"dangling-elif", "elif True:\n    pass"},
		{"dangling-else", "else:\n    pass"},
		{"break-outside", "break"},
		{"continue-outside", "if True:\n    continue"},
		{"inline-compound", "if True: for x in [1]: print(x)"},
		{"loop-else", "for x in [1]:\n    pass\nelse:\n    pass"},
		{"delimiter-mismatch", "for x in [1):\n    pass"},
		{"branch-write", "dest = '.bashrc'\nif False:\n    dest = 'notes.txt'\nopen(dest, 'w').write('payload')"},
		{"else-write", "if True:\n    dest = '.bashrc'\nelse:\n    dest = 'notes.txt'\nopen(dest, 'w').write('payload')"},
		{"elif-write", "dest = '.bashrc'\nif False:\n    dest = 'notes.txt'\nelif False:\n    dest = 'notes.txt'\nopen(dest, 'w').write('payload')"},
		{"zero-iteration-write", "dest = '.bashrc'\nfor x in []:\n    dest = 'notes.txt'\nopen(dest, 'w').write('payload')"},
		{"next-iteration-write", "dest = 'notes.txt'\nfor x in [1, 2]:\n    open(dest, 'w').write('payload')\n    dest = '.bashrc'"},
		{"while-predicate-write", "dest = 'notes.txt'\nwhile open(dest, 'w').write('payload'):\n    dest = '.bashrc'"},
		{"nested-loop-write", "dest = 'notes.txt'\nfor x in [1, 2]:\n    open(dest, 'w').write('payload')\n    for dest in ['.bashrc']:\n        pass"},
		{"break-write", "dest = '.bashrc'\nfor x in [1]:\n    break\n    dest = 'notes.txt'\nopen(dest, 'w').write('payload')"},
		{"continue-write", "dest = '.bashrc'\nfor x in [1]:\n    continue\n    dest = 'notes.txt'\nopen(dest, 'w').write('payload')"},
		{"comparison-path", "open('notes.txt' == 'notes.txt', 'w').write('payload')"},
		{"or-path", "open('' or '.bashrc', 'w').write('payload')"},
		{"and-path", "open('notes.txt' and '.bashrc', 'w').write('payload')"},
		{"conditional-path", "open('notes.txt' if False else '.bashrc', 'w').write('payload')"},
		{"argv-write", "import sys\nopen(sys.argv[1], 'w').write('payload')"},
		{"argv-keyword-write", "import sys\nopen(sys.argv[1], mode='w').write('payload')"},
		{"argv-readplus", "import sys\nopen(sys.argv[1], 'r+').write('payload')"},
		{"argv-read-capability", "import sys\nf = open(sys.argv[1]); f.writelines(['payload'])"},
		{"argv-unknown-mode", "import sys\nopen(sys.argv[1], sys.argv[2])"},
		{"argv-path-write", "import sys\nfrom pathlib import Path\nPath(sys.argv[1]).write_text('payload')"},
		{"glob-write", "import glob\nfor filename in glob.glob('.*'):\n    open(filename, 'w').write('payload')"},
		{"container-file-capability", "data = [open('notes.txt', 'w')]\ndata.pop().write('payload')"},
		{"method-path-provenance", "data = ['.bashrc']\nopen(data.pop(), 'w').write('payload')"},
		{"path-container-rename", "from pathlib import Path\ndata = [Path('notes.txt')]\ndata[0].replace('.bashrc')"},
		{"path-pop-rename", "from pathlib import Path\ndata = [Path('notes.txt')]\ndata.pop().replace('.bashrc')"},
		{"path-loop-rename", "from pathlib import Path\nfor item in [Path('notes.txt')]:\n    item.replace('.bashrc')"},
		{"path-parenthesized-rename", "from pathlib import Path\n(Path('notes.txt')).replace('.bashrc')"},
		{"path-dict-rename", "from pathlib import Path\ndata = {'file': Path('notes.txt')}\ndata.get('file').replace('.bashrc')"},
		{"path-branch-rename", "from pathlib import Path\nitem = Path('notes.txt')\nif True:\n    item = 'text'\nitem.replace('.bashrc')"},
		{"mutated-text-sequence", "from pathlib import Path\nlines = 'one\\ntwo'.splitlines()\nlines.append(Path('notes.txt'))\nfor item in lines:\n    item.replace('.bashrc')"},
		{"aliased-text-sequence", "from pathlib import Path\nlines = ['one']\nalias = lines\nalias.append(Path('notes.txt'))\nlines[0].replace('.bashrc')"},
		{"mutated-glob-sequence", "from pathlib import Path\nimport glob\nfiles = glob.glob('docs/*.md')\nfiles.append(Path('notes.txt'))\nfor item in files:\n    item.replace('.bashrc')"},
		{"mutated-argv-sequence", "from pathlib import Path\nimport sys\nsys.argv.append(Path('notes.txt'))\nfor item in sys.argv:\n    item.replace('.bashrc')"},
		{"os-unknown", "import os\nos.remove('notes.txt')"},
		{"mkdir-deferred", "from pathlib import Path\nPath('.git/hooks/new').mkdir(parents=True)"},
		{"makedirs-deferred", "import os\nos.makedirs('/etc/cron.d/new', exist_ok=True)"},
	}
	for _, attribute := range []string{"path", "modules", "stdin", "version", "executable", "platform", "exit.__call__", "stdout.buffer.write", "stderr.fileno", "settrace", "_getframe"} {
		cases = append(cases, struct{ name, body string }{"sys-attribute/" + attribute, "import sys\nprint(sys." + attribute + ")"})
		cases = append(cases, struct{ name, body string }{"sys-call/" + attribute, "import sys\nsys." + attribute + "('payload')"})
	}
	for call := range inertPythonCalls {
		root := strings.Split(call, ".")[0]
		cases = append(cases, struct{ name, body string }{"for-shadow/" + call, "for " + root + " in [1]:\n    pass"})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if closedInertBody("python3", tc.body) || interpHeredocExecFree("python3", tc.body) {
				t.Fatalf("unsafe/unsupported body accepted:\n%s", tc.body)
			}
		})
	}
}

func TestInterpInertWidenNode(t *testing.T) {
	for _, body := range []string{
		"const data = ['one']; data.push('two');",
		"const data = ['one']; data.pop();",
		"const data = ['two', 'one']; data.sort();",
		"console.log('one'.indexOf('o'));",
		"console.log('one'.lastIndexOf('o'));",
		"console.log('one'.startsWith('o'));",
		"console.log('one'.endsWith('e'));",
	} {
		t.Run(body, func(t *testing.T) {
			if !interpHeredocExecFree("node", body) {
				t.Fatal("benign Node data method rejected")
			}
		})
	}
	for _, body := range []string{
		"const data = ['one']; data.sort(eval);",
		"const data = ['one']; data.sort('eval');",
		"const data = ['one']; data.push(eval);",
		"const data = ['one']; data.pop()('payload');",
		"const data = ['one']; data.map(eval);",
	} {
		t.Run(body, func(t *testing.T) {
			if interpHeredocExecFree("node", body) {
				t.Fatal("Node callable/unsupported method accepted")
			}
		})
	}
}

func TestInterpInertWidenDepth(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 110; i++ {
		fmt.Fprintf(&body, "%sif True:\n", strings.Repeat(" ", i))
	}
	body.WriteString(strings.Repeat(" ", 110) + "pass\n")
	if closedInertBody("python3", body.String()) {
		t.Fatal("unbounded suite nesting accepted")
	}
}
