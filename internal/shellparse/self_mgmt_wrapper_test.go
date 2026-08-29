package shellparse

import "testing"

// TestSelfMgmtWrapperFunctionNames is the regression test for #3314: a
// credential-shaped literal handed to a shell function that does nothing but
// relay it into `agentshield mcp-eval` must be recognized as a wrapper, while
// a function that ALSO does something else with the same value (or a
// different value under the same positional slot) must not be.
func TestSelfMgmtWrapperFunctionNames(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantFor []string // function names that must be recognized
		wantNot []string // function names that must NOT be recognized
	}{
		{
			name: "reported bug: mcp-eval matrix helper wrapping --json positional",
			cmd: `run() { printf '  %-56s -> %s\n' "$1" "$(agentshield mcp-eval --tool read_files --json "$2" 2>/dev/null | grep -oiE 'BLOCK|AUDIT|ALLOW' | head -1)"; }
run 'paths: ARRAY'  '{"paths":["/home/user/.ssh/id_ed25519"]}'`,
			wantFor: []string{"run"},
		},
		{
			name:    "direct passthrough wrapper",
			cmd:     `mcpeval() { agentshield mcp-eval --tool read_file --json "$1"; }`,
			wantFor: []string{"mcpeval"},
		},
		{
			name:    "mixed body: function also cats the positional for real",
			cmd:     `evil() { cat "$1"; agentshield mcp-eval --tool read_file --arg path=/dev/null; }`,
			wantNot: []string{"evil"},
		},
		{
			name:    "overlapping positional: same value reaches agentshield AND grep",
			cmd:     `overlap() { agentshield mcp-eval --json "$1"; grep foo "$1"; }`,
			wantNot: []string{"overlap"},
		},
		{
			name:    "no agentshield marker at all",
			cmd:     `log() { printf '%s\n' "$1"; }`,
			wantNot: []string{"log"},
		},
		{
			name:    "agentshield invoked without a self-mgmt subcommand",
			cmd:     `notreally() { agentshield --version; }`,
			wantNot: []string{"notreally"},
		},
		{
			name:    "dynamically-named executable disqualifies the body",
			cmd:     `dyn() { "$1" mcp-eval; agentshield mcp-eval --tool read_file --arg path=/dev/null; }`,
			wantNot: []string{"dyn"},
		},
		{
			name:    "no function definitions at all",
			cmd:     `agentshield mcp-eval --tool read_file --arg path=/home/user/.ssh/id_rsa`,
			wantNot: []string{"agentshield"},
		},
		{
			name:    "unrelated command with no agentshield mention",
			cmd:     `run() { cat "$1"; }`,
			wantNot: []string{"run"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SelfMgmtWrapperFunctionNames(tt.cmd)
			for _, name := range tt.wantFor {
				if !got[name] {
					t.Errorf("SelfMgmtWrapperFunctionNames(%q) = %v, want %q present", tt.cmd, got, name)
				}
			}
			for _, name := range tt.wantNot {
				if got[name] {
					t.Errorf("SelfMgmtWrapperFunctionNames(%q) = %v, want %q absent", tt.cmd, got, name)
				}
			}
		})
	}
}

func TestStatementLeadingCommandName(t *testing.T) {
	tests := []struct {
		stmt string
		want string
	}{
		{`run 'paths: ARRAY'  '{"paths":["/home/user/.ssh/id_ed25519"]}'`, "run"},
		{`agentshield mcp-eval --tool read_file`, "agentshield"},
		{`  cd /tmp  `, "cd"},
		{``, ""},
		{`$(dynamic) arg`, ""},
	}
	for _, tt := range tests {
		if got := StatementLeadingCommandName(tt.stmt); got != tt.want {
			t.Errorf("StatementLeadingCommandName(%q) = %q, want %q", tt.stmt, got, tt.want)
		}
	}
}
