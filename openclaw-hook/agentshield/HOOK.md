---
name: agentshield
description: "Runtime security gateway — evaluate every exec through AgentShield's 7-layer pipeline"
homepage: https://github.com/security-researcher-ca/AI_Agent_Shield
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "events": ["agent:bootstrap"],
        "requires": { "bins": ["agentshield"] },
      },
  }
---

# AgentShield Hook

Runtime security gateway for OpenClaw agents. Evaluates every shell command through AgentShield's 7-layer analyzer pipeline before the host executes it.

## What It Does

1. **Injects security instructions** into the agent's bootstrap context, telling the agent that a PreToolUse hook will evaluate every command it issues.
2. The host's PreToolUse hook forwards each command to AgentShield for evaluation *before* execution. The agent itself does not wrap commands — AgentShield is evaluation-only and never executes.
3. AgentShield evaluates each command against policy packs (structural, dataflow, semantic, stateful, guardian, datalabel rules).
4. Dangerous commands are **blocked before execution**; safe commands pass through; AUDIT-tier commands execute with a logged flag.

## Protection Layers

- **Regex** — fast pattern matching on known-bad commands
- **Structural** — AST-based analysis (flag reordering, sudo wrapping)
- **Semantic** — intent classification (disk-destroy, file-delete, exfiltration)
- **Dataflow** — source→sink taint tracking (credential → network)
- **Stateful** — multi-step attack chain detection (download → execute)
- **Guardian** — prompt injection signal detection
- **Data Label** — customer-defined PII/codename/SSN/credit-card detection

## Requirements

- `agentshield` must be installed and on PATH (`brew install security-researcher-ca/tap/agentshield`)

## Configuration

AgentShield uses `~/.agentshield/` for policy and audit:

```
~/.agentshield/
├── policy.yaml      # Custom rules (optional)
├── audit.jsonl      # Append-only audit log
└── packs/           # Policy packs
    ├── terminal-safety.yaml
    ├── secrets-pii.yaml
    ├── network-egress.yaml
    └── supply-chain.yaml
```

## Setup

```bash
agentshield setup openclaw
```

Or install manually:

```bash
openclaw hooks install /path/to/Agentic-gateway/openclaw-hook
openclaw hooks enable agentshield
```

## Disabling

```bash
agentshield setup openclaw --disable
# or
openclaw hooks disable agentshield
```

## See Also

- [AgentShield Policy Guide](https://github.com/security-researcher-ca/AI_Agent_Shield/blob/main/docs/policy-guide.md)
- [AgentShield Architecture](https://github.com/security-researcher-ca/AI_Agent_Shield/blob/main/docs/architecture.md)
