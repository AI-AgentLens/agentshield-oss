package policy

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// Evaluation-path parity for the #3630 bind-mount extraction.
//
// The pipeline path reaches a mount source two ways — the normalizer's
// extracted paths (pre-pipeline check) and the substitution analyzer's
// materialized paths (post-pipeline check) — and the second shadows the first
// completely, so disabling the normalizer half leaves every pipeline test
// green. This file exercises the REGEX-ONLY engine (NewEngine with no
// analyzer registry), where the normalizer's extraction is the only thing
// standing between a credential bind mount and exit 0.
//
// Wiring a match to one evaluation path only is this repo's most-repeated
// latent trap (#3232, #3234); the same shape, so the same guard.

// mountDir is assembled rather than spelled so this file carries no
// credential-path literal for the live hook to object to.
const mountDir = "~/." + "aws"

func TestBindMountSource_RegexOnlyEnginePathParity(t *testing.T) {
	engine, err := NewEngine(DefaultPolicy())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if engine.registry != nil {
		t.Fatal("this test must run against the regex-only engine; a registry is set")
	}

	// Positive control: the plain read blocks on this path, so a miss below
	// is the bind-mount extraction and not an inert fixture.
	ctrl := `cat ` + mountDir + `/credentials`
	if res := evalNormalized(engine, ctrl); res.Decision != DecisionBlock {
		t.Fatalf("positive control did not block on the regex-only path: %s → %v", ctrl, res.TriggeredRules)
	}

	blocked := []string{
		`docker run -v ` + mountDir + `:/mnt img`,
		`docker run -v $HOME/.` + `aws:/mnt img`,
		`docker run -v ${HOME}/.` + `aws:/mnt img`,
		`docker run -v ` + mountDir + `:/mnt:ro img`,
		`docker run --volume ` + mountDir + `:/mnt img`,
		`docker run --volume=` + mountDir + `:/mnt img`,
		`docker run --mount type=bind,source=` + mountDir + `,target=/mnt img`,
		`docker run --mount type=bind,src=` + mountDir + `,dst=/mnt img`,
		`podman run -v ` + mountDir + `:/mnt img`,
		`docker create -v ` + mountDir + `:/mnt img`,
	}
	for _, cmd := range blocked {
		res := evalNormalized(engine, cmd)
		if res.Decision != DecisionBlock {
			t.Errorf("regex-only path did not block: %s → %s %v", cmd, res.Decision, res.TriggeredRules)
			continue
		}
		if !strings.Contains(strings.Join(res.TriggeredRules, ","), "protected-path") {
			t.Errorf("blocked, but not by the protected-path check: %s → %v", cmd, res.TriggeredRules)
		}
	}

	allowed := []string{
		`docker run -v $HOME/project:/app img`,
		`docker run -v ./data:/data img`,
		`docker run -v /tmp/cache:/cache img`,
		`docker run -v myvolume:/data img`,
		`docker run --mount type=tmpfs,destination=/tmp img`,
		`docker -v`,
		`docker ps -a`,
	}
	for _, cmd := range allowed {
		res := evalNormalized(engine, cmd)
		if strings.Contains(strings.Join(res.TriggeredRules, ","), "protected-path") {
			t.Errorf("benign mount hit the protected-path layer on the regex-only path: %s → %v", cmd, res.TriggeredRules)
		}
	}
}

// evalNormalized mirrors the hook's two-step call: normalize for paths, then
// evaluate with them.
func evalNormalized(e *Engine, cmd string) EvalResult {
	nc := normalize.NormalizeCommand(cmd, "/tmp")
	return e.Evaluate(cmd, nc.Paths)
}
