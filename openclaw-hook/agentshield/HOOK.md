---
name: agentshield
description: "Bootstrap notice only — AgentShield does not evaluate OpenClaw commands"
homepage: https://github.com/AI-AgentLens/agentshield-oss
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

**This hook does not protect an OpenClaw agent.** It subscribes to `agent:bootstrap` only and injects a notice into the agent's context. Nothing sends an OpenClaw shell command or tool call to AgentShield, so no command is evaluated, logged or blocked (#4582). A real integration needs an OpenClaw pre-tool-call event that can veto the call.

## What It Does

1. On `agent:bootstrap`, adds `AGENTSHIELD.md` to the agent's context. The note tells the agent that AgentShield is not evaluating its commands.
2. Nothing else.

## Requirements

- `agentshield` must be installed and on PATH (`brew install AI-AgentLens/oss/agentshield`)

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

- [AgentShield Policy Guide](https://github.com/AI-AgentLens/agentshield-oss/blob/main/docs/policy-guide.md)
- [AgentShield Architecture](https://github.com/AI-AgentLens/agentshield-oss/blob/main/docs/architecture.md)
