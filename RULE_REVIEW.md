# Formal Rule Review Tracker

Formal security rule reviews conducted by Gary + Kai to reduce FP/FN rates. Reviews focus on real-world developer workflows and attacker bypass techniques that automated tests miss.

**Review cadence**: Full sweep completed 2026-03-23. New rules reviewed periodically (every 2 weeks or every 50 new rules).

## Shield — Runtime Rules (Shell + MCP)

| Pack | Rules | Reviewed | FP Found | FN Found | Issues Filed | Status |
|------|-------|----------|----------|----------|-------------|--------|
| `packs/secrets-pii.yaml` | 105 | 2026-03-23 | 8 | 4 | #280 | Filed |
| `packs/supply-chain.yaml` | 120 | 2026-03-23 | 8 | 6 | #278, #281 | Filed |
| `packs/network-egress.yaml` | 140 | 2026-03-23 | 6 | 6 | Pending | Filed |
| `packs/terminal-safety.yaml` | 635 | 2026-03-23 | 30+ | 10+ | Pending | Filed |
| `packs/mcp/mcp-secrets.yaml` | 144 | 2026-03-23 | 4 | 2 | #279 | Filed |
| `packs/mcp/mcp-safety.yaml` | 42 | 2026-03-23 | 6 | 1 | Pending | Filed |
| `packs/mcp/mcp-supply-chain.yaml` | 12 | 2026-03-23 | 5 | 1 | Pending | Filed |
| `packs/mcp/mcp-persistence.yaml` | 12 | 2026-03-23 | 3 | 1 | Pending | Filed |
| `packs/mcp/mcp-privilege-escalation.yaml` | 10 | 2026-03-23 | 3 | 1 | Pending | Filed |
| `packs/mcp/mcp-financial.yaml` | 13 | 2026-03-23 | 0 | 2 | Pending | Filed |
| `packs/mcp/mcp-governance.yaml` | 6 | 2026-03-23 | 1 | 0 | Pending | Filed |
| `packs/mcp/mcp-reconnaissance.yaml` | 17 | 2026-03-23 | 4 | 1 | Pending | Filed |
| `packs/mcp/mcp-llm-data-flow.yaml` | 23 | 2026-03-23 | 2 | 1 | Pending | Filed |
| `packs/mcp/mcp-content-integrity.yaml` | 16 | 2026-03-23 | 2 | 1 | Pending | Filed |
| `packs/mcp/mcp-response-integrity.yaml` | 8 | 2026-03-23 | 2 | 0 | Pending | Filed |
| `packs/mcp/mcp-generated.yaml` | 0 | N/A | — | — | — | Empty |

## Comply — Static Analysis Rules (Semgrep)

| Category | Files | Rules | Reviewed | FP Found | FN Found | Issues Filed | Status |
|----------|-------|-------|----------|----------|----------|-------------|--------|
| api-keys | 1 | 121 | 2026-03-23 | ~27 | 1 | #307 | Filed |
| uncontrolled-invocations | 1 | 63 | 2026-03-23 | 9 | 0 | #307 | Filed |
| data-exfiltration | 1 | 16 | 2026-03-23 | 1 | 1 | #307 | Filed |
| credential/secrets (9 files) | 9 | ~150 | 2026-03-23 | 6 | 2 | #308 | Filed |
| agent/agentic (11 files) | 11 | ~90 | 2026-03-23 | 7 | 2 | #309 | Filed |
| persistence/escalation (13 files) | 13 | ~170 | 2026-03-23 | 6 | 3 | #310 | Filed |
| supply-chain/cloud/LLM/SDK (13 files) | 13 | ~750 | 2026-03-23 | 7 | 1 | #311 | Filed |
| **Total** | **254** | **~1,360** | **2026-03-23** | **~63** | **~10** | **#307-311** | **Complete** |

### Top Comply FPs (Highest Impact)

1. **Env-var reads flagged as insecure** (#307) — ~25-30 rules flag `os.Getenv("X_API_KEY")` as credential exposure. This is the *recommended secure pattern*.
2. **`config.json`/`settings.json` access** (#308) — Every app reading its own config fires. Most common filenames in JS/TS.
3. **`$ENGINE.query(...)` / `$CLIENT.generate(...)`** (#307) — SQLAlchemy, Django, Faker all trigger uncontrolled-invocation rules.
4. **`$TOOLS.push(...)`** (#309) — Any JS array named `tools` fires as capability escalation.
5. **`systemctl start` / `sudo`** (#310) — Every devops script fires as ERROR severity.
6. **`$STACK.destroy()`** (#311) — Django/SQLAlchemy teardowns fire as Pulumi cloud destruction.
7. **`json.loads()` as sanitizer** (#309) — JSON parsing does NOT sanitize prompt injection. Creates real bypass.
8. **`urlparse()` as SSRF sanitizer** (#311) — URL parsing provides zero SSRF protection. Creates real bypass.

## Top Enterprise-Critical FPs (Must Fix for POC Success)

These FPs will cause enterprises to disable AgentShield in the first hour of evaluation:

1. **Private registry blocking** (#278) — `npm --registry`, `pip --index-url`, `go mod replace` all blocked
2. **Dockerfile/CI write blocking** — `mcp-sc-block-dockerfile-write`, `mcp-sc-block-cicd-config-write` BLOCK routine dev tasks
3. **Localhost endpoint blocking** (#281) — `OLLAMA_HOST=localhost:11434` blocked
4. **API key test prefix** (#280) — Stripe `sk-test-` keys blocked
5. **DNS TXT lookup blocking** — `dig TXT _dmarc.example.com` blocked (DKIM/SPF verification)
6. **AWS CLI tab completion** — `complete -C aws_completer aws` blocked
7. **SSH local forwarding** — `ssh -L` dev tunnels blocked
8. **`batch` prefix** — `aws batch submit-job` blocked (catches all `batch*` commands)
9. **Git pager config** — `git config core.pager delta` blocked
10. **`eval $(ssh-agent -s)`** — Most common eval pattern in developer environments, audit noise

## Review Methodology

- Reviews use the `feature-dev:code-reviewer` agent specialized for FP/FN analysis
- Each rule evaluated against real-world developer workflows and attacker evasion techniques
- Findings require confidence >= 75 to be reported, >= 80 to file issues
- FP threshold: would this fire during a normal enterprise developer's daily workflow?
- FN threshold: could an attacker with basic shell knowledge bypass this rule?
