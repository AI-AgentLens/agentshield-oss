// Package execenv detects the execution context AgentShield is running in —
// specifically, whether the current process lives inside a CI/CD runner.
//
// Why this exists (issue #3291 / OWASP State of Agentic AI Security & Governance
// v2.01 p.65): an IDE agent works for a developer it trusts; a CI-resident agent
// ingests input from external contributors it has no reason to trust, making it
// attacker-facing by design. "Controls calibrated for the trusted-developer case
// do not transfer." CI-ness is therefore a first-class match dimension: rules can
// tighten posture (e.g. AUDIT→BLOCK) when provenance is untrusted.
//
// CI-ness is a property of the *host/process*, not of an individual command —
// the runner is either CI or it is not, for the whole process lifetime. So it is
// detected once, from the environment, and handed to the engine. Detection is a
// pure function of a getenv closure so it is deterministic and unit-testable, and
// so callers can inject a fixed environment in tests instead of mutating the
// real, process-global environment (which would race the parallel test suite).
package execenv

import "strings"

// Context describes the detected execution environment. The zero value
// (CI:false, Provider:"") means "not CI / unknown" — the safe default, under
// which no CI-only tightening applies and behaviour matches the historical
// trusted-developer baseline.
type Context struct {
	// CI reports whether the process appears to be running inside a CI/CD
	// runner (GitHub Actions, GitLab CI, CircleCI, …).
	CI bool
	// Provider names the detected CI system when known ("github-actions",
	// "gitlab-ci", "circleci", "buildkite", "jenkins", "azure-pipelines",
	// "generic"). Carried for attestation richness — a receipt that says a
	// block happened in GitHub Actions is more auditor-legible than a bare
	// bool — and never used for gating decisions. Empty when CI is false.
	Provider string
}

// truthy reports whether an environment value means "on". CI systems variously
// set these to "true", "1", or "yes"; a bare-but-set variable (e.g. Jenkins'
// JENKINS_URL) is handled by the caller checking for non-empty instead.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

// Detect inspects the environment (via the supplied getenv, normally os.Getenv)
// and returns the execution Context.
//
// Provider-specific variables are checked before the generic `CI` flag so the
// Provider field is as precise as possible: nearly every runner sets `CI=true`
// in addition to its own marker, so testing the specific marker first yields
// "github-actions" rather than "generic". Ordering is otherwise irrelevant to
// the CI bool — any single match is sufficient.
func Detect(getenv func(string) string) Context {
	switch {
	case truthy(getenv("GITHUB_ACTIONS")):
		return Context{CI: true, Provider: "github-actions"}
	case truthy(getenv("GITLAB_CI")):
		return Context{CI: true, Provider: "gitlab-ci"}
	case truthy(getenv("CIRCLECI")):
		return Context{CI: true, Provider: "circleci"}
	case truthy(getenv("BUILDKITE")):
		return Context{CI: true, Provider: "buildkite"}
	case getenv("JENKINS_URL") != "":
		// Jenkins does not set a truthy flag; the presence of JENKINS_URL is
		// its documented marker.
		return Context{CI: true, Provider: "jenkins"}
	case truthy(getenv("TF_BUILD")):
		// Azure Pipelines sets TF_BUILD=True.
		return Context{CI: true, Provider: "azure-pipelines"}
	case truthy(getenv("CI")):
		// Generic fallback: the de-facto standard flag set by most CI systems.
		return Context{CI: true, Provider: "generic"}
	}
	return Context{}
}
