package analyzer

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestInterpInertOpaqueProbes(t *testing.T) {
	files, err := filepath.Glob("testdata/interp_inert/probes*/*.sh")
	if err != nil || len(files) != 45 {
		t.Fatalf("probe manifest: files=%d err=%v", len(files), err)
	}
	match := regexp.MustCompile(`export HOME=|HOME=/|adb shell am start|ufw disable|pkexec bash`).MatchString
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			b, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Base(file)
			want := strings.HasPrefix(name, "t01-") || strings.HasPrefix(name, "t02-") || strings.HasPrefix(name, "a02-")
			if got := PositionExcluded(string(b), []string{LabelPosInterpHeredocLiteral}, nil, match); got != want {
				t.Fatalf("position excused=%v want=%v", got, want)
			}
		})
	}
}

func TestInterpInertClosedConstructs(t *testing.T) {
	cases := []struct {
		name, lang, body string
		want             bool
	}{
		{"write", "python3", `open("notes.txt", "w").write("payload")`, true},
		{"write-indexed-data", "python3", `probes = ["payload"]; open("notes.txt", "w").write(probes[0])`, true},
		{"index-execution", "python3", `probes = ["payload"]; print(probes[eval("payload")])`, false},
		{"index-computed-call", "python3", `probes = ["payload"]; probes[0]()`, false},
		{"index-callable-reference", "python3", `probes = [eval]; probes[0]("payload")`, false},
		{"index-file-destination", "python3", `paths = [".bashrc"]; open(paths[0], "w").write("payload")`, false},
		{"read", "python3", `print(open("notes.txt").read())`, true},
		{"io", "python3", "import io\nio.open('notes.txt', 'w', encoding='utf-8').write('payload')", true},
		{"json", "python3", "import json\nprint(json.dumps(json.loads('{}'), indent=2))", true},
		{"regex", "python3", "import re\nprint(re.sub('x', 'y', 'text'))", true},
		{"raw-regex", "python3", `pattern = r"\btext\S+"; print(pattern)`, true},
		{"conditional-data", "python3", `tag = "PROSE(+cited)" if f in cited[t] else "PROSE-ONLY"`, true},
		{"conditional-call", "python3", `tag = "text" if eval('payload') else "other"`, false},
		{"conditional-index-call", "python3", `tag = "text" if f in cited[eval('payload')] else "other"`, false},
		{"path", "python3", "from pathlib import Path\nPath('notes.txt').write_text('payload')", true},
		{"path-variable", "python3", "import os\np = os.path.join('docs', 'notes.txt')\nopen(p,'w').write('payload')", true},
		{"node-file", "node", "const fs = require('node:fs');\nfs.writeFileSync('notes.txt', 'payload');", true},
		{"node-json", "node", `console.log(JSON.stringify(JSON.parse('{}')));`, true},
		{"node-path", "node", `const path = require('path'); const fs = require('fs'); fs.writeFileSync(path.join('docs','notes.txt'),'payload');`, true},
		{"unknown-import", "python3", "import subprocess\nx = 'payload'", false},
		{"unknown-call", "python3", "x = 'payload'\nanything(x)", false},
		{"comment-cr", "python3", "x = 'payload'\n# comment\reval(x)", false},
		{"node-comment-cr", "node", "const x = 'payload';\n// comment\reval(x);", false},
		{"node-comment-line-separator", "node", "const x = 'payload';\n// comment\u2028eval(x);", false},
		{"encoding-cookie", "python3", "# coding: unicode_escape\nx = 'payload'", false},
		{"alias", "python3", "import os\nf = os.system\nf('payload')", false},
		{"rebinding", "python3", "open = eval\nopen('payload')", false},
		{"computed-call", "python3", `getattr(__import__('os'), 'system')('payload')`, false},
		{"parenthesized-call", "python3", `(eval)('payload')`, false},
		{"attribute-assignment", "python3", "import io\nio.open = eval\nio.open('payload')", false},
		{"f-string", "python3", `doc = f"{eval('payload')}"`, false},
		{"decorator", "python3", "@print\ndef f():\n  pass", false},
		{"with-file", "python3", "with open('notes.txt', 'w') as f:\n  f.write('payload')", true},
		{"with-non-file", "python3", "with eval('payload') as f:\n  pass", false},
		{"with-data", "python3", "with 'text' as f:\n  pass", false},
		{"callback", "python3", "import re\nre.sub('x', eval, 'payload')", false},
		{"node-dynamic-import", "node", `import('child_process').then(console.log);`, false},
		{"node-template", "node", "const doc = `${eval('payload')}`;", false},
		{"node-computed", "node", `console['log']('payload');`, false},
		{"node-callback", "node", `const fs = require('fs'); fs.writeFileSync('notes.txt','payload',eval);`, false},
		{"ruby-interpolation", "ruby", `File.write('notes.txt', "#{system('payload')}")`, false},
		{"ruby-pipe", "ruby", `File.read('|payload')`, false},
		{"perl-implicit-call", "perl", `system "payload";`, false},
		{"unknown-path", "python3", "import json\np = json.loads('" + `".bashrc"` + "')\nopen(p,'w').write('payload')", false},
		{"keyword-path", "python3", `open(mode='w',file='.bashrc').write('payload')`, false},
		{"absolute-join", "python3", "import os\nopen(os.path.join('docs','/etc/profile'),'w').write('payload')", false},
		{"multipart-Path", "python3", "from pathlib import Path\nPath('/etc','profile').write_text('payload')", false},
		{"absolute-resolve", "node", `const path = require('path'); const fs = require('fs'); fs.writeFileSync(path.resolve('docs','/etc/profile'),'payload');`, false},
		{"escaped-path", "python3", `open('\x2ebashrc','w').write('payload')`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := interpHeredocExecFree(tc.lang, tc.body); got != tc.want {
				t.Fatalf("inert=%v want=%v: %s", got, tc.want, tc.body)
			}
		})
	}
}

func TestInterpInertDeferredWrites(t *testing.T) {
	paths := []string{".bashrc", "~/.zshenv", "$HOME/.profile", "/etc/profile", "/etc/environment", "/etc/crontab", "/etc/cron.d/job", "/etc/profile.d/job.sh", "/var/spool/cron/job", ".config/fish/config.fish", ".git/hooks/pre-commit", ".husky/pre-commit", "docs/../.bashrc"}
	for _, target := range paths {
		t.Run(target, func(t *testing.T) {
			for _, c := range []struct{ lang, body string }{
				{"python3", `open("` + target + `",'w').write('payload')`},
				{"python3", "import os\nopen(os.path.expanduser('" + target + "'),'a').write('payload')"},
				{"python3", "from pathlib import Path\np = Path('" + target + "')\np.write_text('payload')"},
				{"node", `const fs = require('fs'); fs.appendFileSync('` + target + `','payload');`},
				{"ruby", `File.write('` + target + `','payload')`},
			} {
				if interpHeredocExecFree(c.lang, c.body) {
					t.Errorf("accepted %s: %s", c.lang, c.body)
				}
			}
		})
	}
	for _, target := range []string{"notes.txt", ".bashrc.bak", "docs/profile.md"} {
		if !interpHeredocExecFree("python3", `open('`+target+`','w').write('payload')`) {
			t.Errorf("ordinary path rejected: %s", target)
		}
	}
}

func TestInterpInertCommentAwareSpans(t *testing.T) {
	cases := []struct {
		lang, body string
		want       []string
		ok         bool
	}{
		{"python3", "# don't start a literal\nprint(\"text\")\n# that's it", []string{`"text"`}, true},
		{"node", "// don't start a literal\nconsole.log(\"text\"); /* 'comment' */", []string{`"text"`}, true},
		{"python3", `x = "# isn't a comment"`, []string{`"# isn't a comment"`}, true},
		{"node", `const x = "// isn't /* a comment */";`, []string{`"// isn't /* a comment */"`}, true},
		{"python3", "x = \"\"\"first\nsecond\"\"\"", []string{"\"\"\"first\nsecond\"\"\""}, true},
		{"python3", "x = 'first\nsecond'", nil, false},
		{"node", "const x = \"first\nsecond\";", nil, false},
		{"python3", "x = 'first\\\nsecond'", nil, false},
		{"node", "/* unfinished", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.lang+tc.body, func(t *testing.T) {
			_, spans, ok := scanInertBody(tc.lang, tc.body)
			if ok != tc.ok {
				t.Fatalf("scan ok=%v want=%v", ok, tc.ok)
			}
			if len(spans) != len(tc.want) {
				t.Fatalf("spans=%v want=%v", spans, tc.want)
			}
			for i, s := range spans {
				if tc.body[s[0]:s[1]] != tc.want[i] {
					t.Errorf("span=%q want=%q", tc.body[s[0]:s[1]], tc.want[i])
				}
			}
		})
	}
}
