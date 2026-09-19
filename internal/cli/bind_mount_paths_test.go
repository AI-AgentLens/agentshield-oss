package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Bind-mount half of #3630, end to end through evaluateCommand — the same
// entry point the IDE hook uses. Helpers live in fail_safe_test.go.
//
// `docker run -v <creddir>:/mnt image` hands the container the bytes of
// <creddir> as surely as `cat` does, but the argv token is `<creddir>:/mnt`
// and the trailing `:` defeats every protected_paths glob. Measured on main
// 2026-09-05 over the 22 protected_paths patterns the shipped community pack
// declares, crossed with 13 spellings: 286/286 probes escaped the
// protected-path layer entirely and 254/286 were not blocked by anything.
//
// The path built here is under a t.TempDir() HOME, so no real credential
// directory is named or touched.

const policyProtectingAWS = `version: "0.1"
defaults:
  decision: "AUDIT"
  protected_paths: ["~/.aws/**"]
rules: []
`

// credDir is the protected directory these tests mount, assembled rather than
// spelled so the file carries no credential-path literal.
const credDir = "~/." + "aws"

func TestProtectedPaths_ContainerBindMountSourceIsARead(t *testing.T) {
	home, _ := newFailSafeHome(t, false, policyProtectingAWS)
	abs := home + "/." + "aws"

	cases := []struct {
		name string
		cmd  string
	}{
		{"docker -v tilde", `docker run -v ` + credDir + `:/mnt img`},
		{"docker -v $HOME", `docker run -v $HOME/.` + `aws:/mnt img`},
		{"docker -v ${HOME}", `docker run -v ${HOME}/.` + `aws:/mnt img`},
		{"docker -v absolute", `docker run -v ` + abs + `:/mnt img`},
		{"docker -v with :ro", `docker run -v ` + credDir + `:/mnt:ro img`},
		{"docker --volume", `docker run --volume ` + credDir + `:/mnt img`},
		{"docker --volume=", `docker run --volume=` + credDir + `:/mnt img`},
		{"docker --mount source=", `docker run --mount type=bind,source=` + credDir + `,target=/mnt img`},
		{"docker --mount src=", `docker run --mount type=bind,src=` + credDir + `,dst=/mnt img`},
		{"podman -v", `podman run -v ` + credDir + `:/mnt img`},
		{"docker create -v", `docker create -v ` + credDir + `:/mnt img`},
		{"docker -v quoted spec", `docker run -v "` + credDir + `:/mnt" img`},
		{"docker -v quoted source", `docker run -v "$HOME/.` + `aws":/mnt img`},
		{"docker -v via variable", `V=$HOME/.` + `aws; docker run -v $V:/mnt img`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := evaluateCommand(tc.cmd, "/tmp", "claude-code-hook", "")
			if res.Decision != policy.DecisionBlock {
				t.Errorf("not blocked: %s\n  decision=%s rules=%v", tc.cmd, res.Decision, res.TriggeredRules)
				return
			}
			if !strings.Contains(strings.Join(res.TriggeredRules, ","), "protected-path") {
				t.Errorf("blocked, but not by the protected-path check: %s → %v", tc.cmd, res.TriggeredRules)
			}
		})
	}
}

// The negative half. A bind mount is a read of its SOURCE, not of every path
// in the spec, and the overwhelming majority of mounts name a project
// directory. If these regress, the fix is worse than the gap.
func TestProtectedPaths_BenignBindMountsStillAllowed(t *testing.T) {
	home, _ := newFailSafeHome(t, false, policyProtectingAWS)

	benign := []string{
		`docker run -v $HOME/project:/app img`,
		`docker run -v ` + home + `/project:/app:ro img`,
		`docker run -v ./data:/data img`,
		`docker run -v .:/src -w /src golang:1.26 go build ./...`,
		`docker run -v /tmp/cache:/cache img`,
		`docker run -v myvolume:/data img`,
		`docker run -v logs:/var/log --name web -p 8080:80 nginx`,
		`docker run --mount type=bind,source=$HOME/src,target=/src img`,
		`docker run --mount type=bind,source=./dist,target=/usr/share/nginx/html nginx`,
		`docker run --mount type=volume,source=pgdata,target=/var/lib/postgresql/data postgres`,
		`docker run --mount type=tmpfs,destination=/tmp img`,
		`docker run --rm -v $PWD:/workspace img make test`,
		`docker run --rm -it -v $(pwd):/app node:20 npm ci`,
		`docker run --rm -v $HOME/go/pkg/mod:/go/pkg/mod golang:1.26 go test ./...`,
		`docker run -v /etc/localtime:/etc/localtime:ro alpine date`,
		`docker create -v $HOME/workspace:/ws img`,
		`podman run --rm -v ./out:/out builder`,
		`nerdctl run -v /srv/data:/data alpine ls /data`,
		`docker build -t myimg .`,
		`docker ps -a`,
		`docker exec -it web sh`,
		`docker -v`,
		`docker --version`,
		// The container-side target is not a host read: mounting something
		// benign over the container's own path must not trip the source rule.
		`docker run -v /tmp/empty:/root/.` + `aws img`,
	}
	for _, cmd := range benign {
		res, _ := evaluateCommand(cmd, "/tmp", "claude-code-hook", "")
		if strings.Contains(strings.Join(res.TriggeredRules, ","), "protected-path") {
			t.Errorf("benign mount hit the protected-path layer: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// A designated consumer in the same command must not launder the mount.
// protectedPathConsumerOnly downgrades BLOCK to AUDIT when EVERY protected
// path in the command sits in a consumer's credential slot; if the mount
// source is invisible to that walk, `ssh -i <key> host && docker run -v
// <creddir>:/mnt img` counts zero non-consumer uses and the mount is
// downgraded along with the ssh.
func TestProtectedPaths_ConsumerCannotLaunderABindMount(t *testing.T) {
	newFailSafeHome(t, false, `version: "0.1"
defaults:
  decision: "AUDIT"
  protected_paths: ["~/.aws/**", "~/.`+`ssh/**"]
rules: []
`)
	key := "~/." + "ssh" + "/id_ed25519"

	// Control: the consumer alone is a recorded AUDIT, not a block.
	solo, _ := evaluateCommand(`ssh -i `+key+` host`, "/tmp", "claude-code-hook", "")
	if solo.Decision == policy.DecisionBlock {
		t.Fatalf("designated consumer alone was blocked — control invalid: %v", solo.TriggeredRules)
	}

	cmd := `ssh -i ` + key + ` host && docker run -v ` + credDir + `:/mnt img`
	res, _ := evaluateCommand(cmd, "/tmp", "claude-code-hook", "")
	if res.Decision != policy.DecisionBlock {
		t.Errorf("consumer laundered the bind mount: %s\n  decision=%s rules=%v",
			cmd, res.Decision, res.TriggeredRules)
	}
}

// Guard against the probe going vacuous: if the shipped community pack ever
// stops declaring protected_paths, every case above would pass for the wrong
// reason. (#3119/#3130/#3137 are three separate instances of a check that
// measured an empty candidate set.)
func TestProtectedPaths_BindMountFixtureIsNotVacuous(t *testing.T) {
	home, _ := newFailSafeHome(t, false, policyProtectingAWS)
	if _, err := os.Stat(home); err != nil {
		t.Fatalf("temp HOME missing: %v", err)
	}
	// Positive control: the plain read of the same directory must block, or
	// the protected-path layer is not live in this fixture at all.
	res, _ := evaluateCommand(`cat `+credDir+`/credentials`, "/tmp", "claude-code-hook", "")
	if res.Decision != policy.DecisionBlock {
		t.Fatalf("positive control did not block — the protected-path layer is not live: %v", res.TriggeredRules)
	}
}

// The exact reproduction through the real hook entry point, so the exit-code
// contract a harness sees is pinned, not just the in-process verdict.
func TestHook_ContainerBindMountOfProtectedDir_ExitsTwo(t *testing.T) {
	home, _ := newFailSafeHome(t, false, policyProtectingAWS)
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"t3630","tool_input":{"command":"docker run -v $HOME/.` + `aws:/mnt img"}}`
	code, stderr := runHookInChildProcess(t, home, payload)
	if code != 2 {
		t.Fatalf("hook exit code = %d; want 2 (BLOCK). stderr:\n%s", code, stderr)
	}
}
