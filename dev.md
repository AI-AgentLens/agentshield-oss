# AgentShield Architecture & Development Guide

AgentShield is a local-first security gateway that sits between AI agents and high-risk tools, enforcing deterministic policies to prevent prompt-injection-driven damage, data exfiltration, and destructive actions.

**Current scope:**
- **Shell command mediation** — 6-layer analyzer pipeline (regex, structural, semantic, dataflow, stateful, guardian)
- **MCP tool call mediation** — stdio proxy with policy evaluation, tool description poisoning detection, and argument content scanning
- **IDE integrations** — Claude Code PreToolUse hook, Windsurf Cascade hooks, Cursor hooks, OpenClaw bootstrap hook, Cursor/Claude Desktop MCP proxy setup

## Documentation

- **[docs/architecture.md](docs/architecture.md)** — System overview, 6-layer pipeline, MCP proxy
- **[docs/policy-guide.md](docs/policy-guide.md)** — Shell + MCP policy authoring
- **[docs/mcp-mediation.md](docs/mcp-mediation.md)** — MCP proxy, description & content scanning
- **[PROGRESS.md](PROGRESS.md)** — Full implementation progress (Phase 1–6)
- **[CLAUDE.md](CLAUDE.md)** — Development commands, architecture reference, test infrastructure
