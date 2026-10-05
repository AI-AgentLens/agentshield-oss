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

### Fixed
- **HTTP MCP proxy forwards `Last-Event-ID`** (#4180) — a reconnecting client's `Last-Event-ID` now reaches the upstream, so the server can resume the SSE stream and replay the events sent while the client was disconnected. Previously the header was not in the forwarded set, the stream restarted from scratch, and server-initiated requests and notifications sent in the gap were lost. Replayed events arrive on a stream the SSE relay scans like any other.

### Changed
- `agentshield log` now displays MCP events with `[MCP]` prefix, shows `Source` field, hides `Cwd` for MCP entries
- `agentshield log --summary` improved statistics display
- Architecture diagrams updated with MCP proxy flow
- Improved linting and error handling
- Enhanced build automation

### Security
- **HTTP MCP proxy scans compressed upstream responses** (#4154) — the client's `Accept-Encoding` is no longer forwarded upstream; the proxy asks for gzip itself and decodes the answer before scanning. Previously a compressing upstream's `tools/list`, `tools/call` and SSE responses reached the client unscanned whenever the client sent `Accept-Encoding` — which both reference SDKs do by default. A `gzip`, `x-gzip` or `deflate` (zlib or raw, tried in that order) body that decodes to a complete message — including one whose container is cut before its trailer, as the clients' lenient decoders read it, and a multi-member gzip stream read either as every member joined or as its first member alone, the two ways clients read it — is scanned in that form and relayed as identity, with streaming decoders so SSE keeps flowing. The JSON-depth screen runs on each decoded form, so a deep body under a coding gets the depth BLOCK rather than an encoding receipt. Any other body under a coding label (`br`, `zstd`, an unknown token, or bytes that decode to no message) is scanned as identity bytes exactly as before, relayed under its declared coding, and recorded with an AUDIT receipt, `mcp-response-encoding-fail-open`, when no scanner acted; a client that decodes a coding the proxy cannot reads content the proxy could not inspect. A `Content-Encoding` chain of more than two codings the proxy decodes is **BLOCKed** with its own rule id, `mcp-response-encoding-chain-exceeded` (a -32700 parse error for JSON, an empty stream for SSE): the shape is an enumerable count, no legitimate server sends it, and every SDK decodes a three-layer chain to the payload, so forwarding it would deliver unscanned content.
- **HTTP MCP proxy forwards the canonical `Content-Type` of the relay that scanned the body** (#4174) — a POST response is routed to the SSE relay or the JSON relay on its parsed media type (#4155/#4169); the `Content-Type` the client receives is now exactly `text/event-stream` for a stream and exactly `application/json` for a JSON body whose upstream label was ambiguous (a line mentioning `text/event-stream` anywhere, or more than one `Content-Type` line); an unambiguous `application/json; charset=utf-8` is forwarded as sent. Previously the upstream's own spelling was forwarded, and a client whose header parser disagreed with the proxy's read the branch nothing scanned: `@modelcontextprotocol/sdk` ≤ 1.29 routes on a case-sensitive substring test, so under `Text/Event-Stream; x="application/json"` it parsed as JSON a body the proxy had relayed as a stream with no events — a poisoned `tools/list` reached the client. Same principle as `Content-Encoding` under #4154. The GET stream and the no-flusher fallback are labelled the same way.
- **HTTP MCP proxy scans the GET stream whatever its `Content-Type`** (#4175) — a 2xx answer to the client's GET is relayed through the SSE relay and labelled exactly `text/event-stream`, because `@modelcontextprotocol/sdk` 1.29.0 and 1.30.0 open the server-initiated stream by default and parse any 2xx body as SSE without reading the header; Python `mcp` 2.3.0 reads that stream only under exactly `text/event-stream`, which the canonical label now is. Previously a 2xx GET under `application/json`, `text/plain` or no `Content-Type` was copied to the client verbatim and unscanned, so a server could deliver server→client messages — a replayed response for a pending request id, a sampling or elicitation request, a poisoned `tools/list` — past every scanner. The proxy still sends no `Accept-Encoding` of its own on GET, so a compliant upstream's stream is identity and ends without a receipt (asking for gzip there made a compress-on-request upstream gzip the long-lived stream and every ordinary end of it write a false `mcp-response-encoding-fail-open` receipt); a coding sent unsolicited on a 2xx GET is decoded and scanned when the proxy can, and otherwise relayed under its label with that receipt, where before the same response under a non-SSE label produced no receipt at all. Non-2xx GET answers (the 405 "no stream" reply, a 401) and DELETE responses are relayed as they arrive, as before.
- **HTTP MCP proxy frames SSE streams per the spec and forwards its own framing** (#4178, and the bare-CR row of #4070) — the SSE relay ends a line at CRLF, LF or a bare CR and drops one UTF-8 BOM at the very start of the stream, as the WHATWG EventSource algorithm, `eventsource-parser` (behind `@modelcontextprotocol/sdk`) and `httpx2` (behind Python `mcp`) do; every line is forwarded LF-terminated, so each client parses the forwarded stream exactly as the proxy scanned it. The spec BOM is not re-emitted, and a first line that itself begins with a BOM goes out behind one more, so the forwarded stream never begins with exactly one BOM — otherwise a BOM-stripping client read a line the proxy never scanned as a `data:` line: an upstream opening with two BOMs, or a first event the scanners suppressed followed by a BOM-led line (found by the #4182 adversarial pass; the second shape was also reachable on main). Previously `bufio.ScanLines` framed the stream on `\n` only: a stream terminated with bare CRs read as one line that no `data:` check matched, and a BOM-led stream's first line was not a data line, so both were forwarded unscanned — TS SDK 1.29.0/1.30.0 delivered the poisoned event from both shapes and Python `mcp` 2.3.0 from the bare-CR one, on POST and on the GET stream, with no audit record. A CR that ends one read is held until the next byte decides whether it is half of a CRLF, so a CRLF is never relayed as a line and an empty line. The line limits are unchanged: a line that does not fit in 10 MiB with its terminator ends the relay there, after the lines before it were scanned and forwarded. The SDK reader table in the tests now frames each stream with its SDK's own parser, so this class is visible to it.
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

