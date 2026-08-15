# CI-Resident Coding Agents — Deployment Recipe

AgentShield treats **CI-resident coding agents** — agents that review PRs, triage
issues, or gate releases from inside a CI pipeline — as a named, first-class
surface. This guide shows how to wire the Shield hook into a GitHub Actions job
that runs a coding agent, and explains the CI-context rules that tighten posture
automatically when the agent is running there.

## Why CI agents are different

From the OWASP *State of Agentic AI Security and Governance* v2.01 (p.65): an IDE
agent works for a developer it trusts; a CI agent ingests input from external
contributors it has **no reason to trust** — pull-request titles, issue bodies,
review comments — which makes it *attacker-facing by design*. "Controls
calibrated for the trusted-developer case do not transfer." (Confirmed in the
wild by Google's April 2026 `run-gemini-cli` advisory, GHSA-wpqr-6v78-jr5g.)

Same Shield binary, same shell/MCP mediation — but a different **execution
context**, and a set of rules that only apply in it.

## How CI-context detection works

The Shield hook detects CI-ness from the environment the runner sets, via
`internal/execenv`:

| Provider | Signal |
|----------|--------|
| GitHub Actions | `GITHUB_ACTIONS=true` |
| GitLab CI | `GITLAB_CI=true` |
| CircleCI | `CIRCLECI=true` |
| Buildkite | `BUILDKITE=true` |
| Jenkins | `JENKINS_URL` set |
| Azure Pipelines | `TF_BUILD=true` |
| Generic fallback | `CI=true` |

CI-ness is a property of the runner (the whole process), not of any single
command. When detected, rules carrying `match.context.ci: true` become active and
**tighten** their decision (e.g. `AUDIT → BLOCK`). Outside CI, those same rules
never fire and the trusted-developer baseline is unchanged. No configuration is
required — GitHub Actions sets `GITHUB_ACTIONS=true` and `CI=true` for you.

Authoring rules that gate on CI context is documented in
[`policy-guide.md`](policy-guide.md) under `match.context`.

## The CI-context rule pack

`packs/community/ci-context.yaml` ships two tightening rules (embedded in the
binary — no install step):

| Rule | Command shape | Outside CI | Inside CI | Taxonomy |
|------|---------------|-----------|-----------|----------|
| `ci-block-env-dump` | full env dump (`env`, `printenv`, `set`, `export -p`, `env \| …`) | AUDIT | **BLOCK** | `credential-exposure/secret-env-exposure/env-dump` |
| `ci-block-cicd-secrets-enumeration` | `gh secret list`, `gh variable list`, `glab variable list`, `circleci context list-environment-variables` | AUDIT | **BLOCK** | `reconnaissance/credential-discovery/cicd-secrets-enumeration` |

Rationale: in CI the process environment is the union of every pipeline secret
(`GITHUB_TOKEN`, OIDC request tokens, deploy keys, cloud credentials injected by
earlier steps), so a bulk dump or a secrets-name sweep by a prompt-injected,
attacker-facing agent is exfiltration-grade recon — not the routine "check my
config" it is on a laptop. Each rule carries a taxonomy node with an existing
compliance mapping, so a block in CI produces an auditor-defensible receipt.

Targeted, benign forms are deliberately **not** matched: `printenv PATH`,
`set -euo pipefail`, `env FOO=bar make`, `gh secret set`, `gh pr list`.

## Wiring the hook into a GitHub Actions job

The full copy-paste workflow is in
[`examples/github-actions-agent-with-shield.yml`](examples/github-actions-agent-with-shield.yml).
The shape:

```yaml
jobs:
  agent-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # 1. Install AgentShield
      - name: Install AgentShield
        run: |
          brew tap AI-AgentLens/oss
          brew install agentshield
          agentshield version

      # 2. Wire the PreToolUse hook for the coding agent (Claude Code shown)
      - name: Enable AgentShield hook
        run: agentshield setup claude-code

      # 3. Prove the hook is CI-aware BEFORE running the agent (fail fast)
      - name: AgentShield CI-context smoke test
        run: |
          # In CI, a full environment dump must BLOCK (exit 2).
          if agentshield check --shell "env"; then
            echo "::error::AgentShield did not block an env dump in CI"; exit 1
          fi
          echo "OK: env dump blocked in CI context"

      # 4. Run the coding agent — its shell commands now flow through the hook
      - name: Run coding agent
        run: claude -p "Review the PR diff and suggest fixes"
```

Steps 1–2 install and arm Shield; step 3 is the **scripted smoke test** that
asserts the CI-context tightening is live on this runner before the agent gets a
turn; step 4 runs the agent with the hook mediating every shell command it emits.

### Verifying locally

`agentshield check --shell` is a faithful predictor of the hook — it applies the
same CI-context detection:

```bash
# In CI context → BLOCK (exit 2)
GITHUB_ACTIONS=true agentshield check --shell "env"

# Trusted-developer baseline → AUDIT (exit 0)
agentshield check --shell "env"
```

## Notes

- **MCP tool calls** from a CI agent are mediated the same way; see
  [`mcp-mediation.md`](mcp-mediation.md). The CI-context dimension currently gates
  shell rules (`command_regex`/`command_prefix`/`command_exact`); extending it to
  MCP rules is future work.
- **Audit trail:** every decision (including CI blocks) is written to the audit
  log and forwarded to the AI Agent Lens SaaS when configured, feeding the
  runtime-attested-compliance receipt.
