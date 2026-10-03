# Changelog

All notable changes to AgentShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Codex CLI PreToolUse hook** — OpenAI Codex CLI now ships a native `PreToolUse` hook with the same JSON payload shape as Claude Code (`hook_event_name`, `tool_name`, `tool_input.command`). `agentshield setup codex` writes a `^Bash$`-matched entry to `~/.codex/hooks.json` that calls `agentshield hook`; the existing handler evaluates the payload unchanged. Codex-only `turn_id` is used to label audit events as `codex-hook` / `codex-mcp-hook`. The legacy SessionStart placeholder is swept on upgrade. Disable with `agentshield setup codex --disable`.
- **Codex hook detection in `agentshield scan`** — the Integration Hooks section now walks both `~/.claude/settings.json` and `~/.codex/hooks.json` so `scan` reports Claude Code and Codex side-by-side. Refactored to a shared `detectPreToolUseHook` helper.

### Notes
- Codex enforces per-hook approval: after `agentshield setup codex`, Codex displays `⚠ 1 hook needs review before it can run.` until the user opens `/hooks` inside Codex and trusts the entry. Codex stores the approval as `[hooks.state.<key>].trusted_hash` in config.toml, but the `key` is positional (upstream TODO: "replace this positional suffix with a durable hook id") and the hash serializes a Rust struct via `command_hook_hash`, so AgentShield does not pre-write trust state — the setup command surfaces the manual approval step instead.
- **Claude Code PreToolUse hook** — native integration that intercepts every Bash tool call before execution; blocks map to exit code 2 so Claude Code surfaces the reason. Install with `agentshield setup claude-code`; disable with `agentshield setup claude-code --disable`. The hook auto-detects the Claude Code JSON format (`hook_event_name`) alongside existing Windsurf and Cursor detection.
- **Audit log rotation** — `audit.jsonl` now auto-rotates at 10 MB: the current file is renamed to `audit.jsonl.1` (replacing any prior backup) and a fresh log is started. No configuration needed; the 10 MB limit is compiled in as `defaultMaxLogBytes`.
- **MCP Communication Mediation** — stdio proxy intercepts and evaluates MCP tool calls between IDE agents and MCP servers (`agentshield mcp-proxy`)
- **MCP Policy Engine** — blocked tools list, glob/regex tool name matching, argument pattern matching via `mcp-policy.yaml`
- **Tool Description Poisoning Detection (P1)** — scans `tools/list` responses for hidden instructions, credential harvesting, exfiltration intent, cross-tool shadowing, stealth instructions; poisoned tools silently hidden from IDE
- **Argument Content Scanning (P2)** — scans `tools/call` argument values for SSH keys, AWS credentials, API tokens, .env contents, base64 blobs, and high-entropy strings; blocks exfiltration even through legitimate tools
- **`agentshield setup mcp`** — automatic IDE MCP config rewriting (Cursor, Claude Desktop)
- **`agentshield status`** — at-a-glance view of IDE hooks, MCP proxy status, policy files, packs, and audit log
- **`agentshield scan`** — 14-test self-diagnostic covering shell policy, MCP policy, description scanner, and content scanner
- MCP red-team regression suite (24 test cases, 100% pass rate)
- MCP integration tests with echo server
- Pre-commit hooks for automated quality checks
- GitHub Actions CI/CD pipeline
- Issue and PR templates
- Security policy and vulnerability reporting
- Dependency management with Dependabot
- Code scanning with CodeQL and Gosec
- OSSF Scorecard integration

### Changed
- `agentshield log` now displays MCP events with `[MCP]` prefix, shows `Source` field, hides `Cwd` for MCP entries
- `agentshield log --summary` improved statistics display
- Architecture diagrams updated with MCP proxy flow
- Improved linting and error handling
- Enhanced build automation

### Security
- **HTTP MCP proxy scans compressed upstream responses** (#4154) — the client's `Accept-Encoding` is no longer forwarded upstream; the proxy asks for gzip itself and decodes the answer before scanning. Previously a compressing upstream's `tools/list`, `tools/call` and SSE responses reached the client unscanned whenever the client sent `Accept-Encoding` — which both reference SDKs do by default. A `gzip`, `x-gzip` or `deflate` (zlib or raw, tried in that order) body that decodes to a complete message — including one whose container is cut before its trailer, as the clients' lenient decoders read it, and a multi-member gzip stream read either as every member joined or as its first member alone, the two ways clients read it — is scanned in that form and relayed as identity, with streaming decoders so SSE keeps flowing. The JSON-depth screen runs on each decoded form, so a deep body under a coding gets the depth BLOCK rather than an encoding receipt. Any other body under a coding label (`br`, `zstd`, an unknown token, or bytes that decode to no message) is scanned as identity bytes exactly as before, relayed under its declared coding, and recorded with an AUDIT receipt, `mcp-response-encoding-fail-open`, when no scanner acted; a client that decodes a coding the proxy cannot reads content the proxy could not inspect. A `Content-Encoding` chain of more than two codings the proxy decodes is **BLOCKed** with its own rule id, `mcp-response-encoding-chain-exceeded` (a -32700 parse error for JSON, an empty stream for SSE): the shape is an enumerable count, no legitimate server sends it, and every SDK decodes a three-layer chain to the payload, so forwarding it would deliver unscanned content.
- Tool description poisoning detection stops WhatsApp MCP exfiltration (Apr 2025), GitHub MCP data heist (May 2025), and Invariant Labs attack patterns
- **MCP proxies block JSON nested past the decoder limit and record every unparseable message** (#4158) — a JSON-RPC message nested deeper than the 10000 levels `encoding/json` reads failed every decode in the proxy and was forwarded as-is, in both directions and on both transports, with no decision and no audit record; a `tools/call` for a tool in `BlockedTools` carrying one unread field nested 10001 deep reached the server, and Node's `JSON.parse` on the other end read it. Now a message that opens more than 10000 arrays or objects at once (counted outside string literals) is not forwarded: the client receives a JSON-RPC parse error (`-32700`, `"id": null`) in its place and a BLOCK is recorded under `mcp-json-depth-exceeded`, on the parse-fail-open taxonomy node. Every other parse failure keeps failing open exactly as before — forwarded unscanned — and now leaves the `mcp-extract-fail-open` AUDIT receipt instead of a stderr line. In the server-to-client direction, on both transports, the receipt is withheld from payloads that are not shaped like a message (`{"`, `{}`, `[{` or `[]` after any run of whitespace and UTF-8 BOMs): a stdio server's banner or debug lines on stdout, an empty `202`, an HTML error page, the legacy SSE `endpoint` frame. The depth BLOCK runs on every payload regardless of shape, so a run of BOMs cannot hide a deep message.
- Argument content scanning stops credential exfiltration via MCP tool call parameters
- Added comprehensive security scanning
- Established vulnerability disclosure process

## [0.1.0] - 2026-02-10

### Added
- Initial release of AgentShield
- Runtime security gateway for LLM agents
- 6-layer analyzer pipeline (regex, structural, semantic, dataflow, stateful, guardian)
- OpenClaw integration with automatic hook installation
- Policy pack system with extensible YAML rules
- Comprehensive test suite (123 test cases)
- Homebrew formula for easy installation
- GitHub Actions for automated releases
- Taxonomy-based weakness classification
- Compliance mapping for OWASP LLM Top 10 2025

### Security
- BLOCK/AUDIT/ALLOW decision framework
- Protected paths and allow domains
- Command intent classification
- Data exfiltration detection
- Multi-step attack chain detection
- Prompt injection signal detection

### Documentation
- Complete README with quick start guide
- Policy guide with rule examples
- Threat modeling documentation
- API documentation

### Installation
- Binary releases for multiple platforms
- Homebrew tap integration
- Source installation support

## [Future Releases]

### Planned Features
- [ ] GUI configuration interface
- [ ] Real-time monitoring dashboard
- [ ] Advanced policy editor
- [ ] Integration with more LLM platforms
- [ ] Performance optimizations
- [ ] Extended compliance frameworks
- [ ] Machine learning for anomaly detection

---

**Note:** For security vulnerabilities, please see [SECURITY.md](.github/SECURITY.md) for responsible disclosure process.

