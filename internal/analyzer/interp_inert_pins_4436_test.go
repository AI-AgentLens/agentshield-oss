package analyzer

import "testing"

// Pins four protections of the inert-Python grammar whose mutants survived the
// #4435 allowlist audit (#4436 item 1). The code was correct; nothing tested it.
// Each body must be REJECTED (not inert), and each is the mirror of a mutant:
//
//	M1  a name bound on one route only must become data at the join
//	M2b text before the branch, a Path rebinding inside it (mirror of path-branch-rename)
//	M3  elif/else start from the base vars, not from the previous suite's vars
//	M25 textseq comes only from a textseq argument
func TestInterpInertRejectsMutantSurvivors_4436(t *testing.T) {
	cases := []struct{ name, body string }{
		{"M1-one-route-binding", "if True:\n    dest = 'notes.txt'\nopen(dest, 'w').write('payload')"},
		{"M1-else-only-binding", "if False:\n    pass\nelse:\n    dest = 'notes.txt'\nopen(dest, 'w').write('payload')"},
		{"M2b-text-then-path-in-branch", "from pathlib import Path\nitem = 'text'\nif True:\n    item = Path('notes.txt')\nitem.replace('.bashrc')"},
		{"M3-elif-starts-from-base", "from pathlib import Path\nitem = Path('notes.txt')\nif False:\n    item = 'text'\nelif True:\n    item.replace('.bashrc')"},
		{"M3-else-starts-from-base", "from pathlib import Path\nitem = Path('notes.txt')\nif False:\n    item = 'text'\nelse:\n    item.replace('.bashrc')"},
		{"M25-sorted-of-non-textseq", "from pathlib import Path\nfor item in sorted([Path('notes.txt')]):\n    print(item.replace('a', 'b'))"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if closedInertBody("python3", tc.body) || interpHeredocExecFree("python3", tc.body) {
				t.Fatalf("unsafe/unsupported body accepted:\n%s", tc.body)
			}
		})
	}
}
