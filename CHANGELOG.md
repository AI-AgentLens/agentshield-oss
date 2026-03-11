# Changelog

All notable changes to AgentShield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- Tool description poisoning detection stops WhatsApp MCP exfiltration (Apr 2025), GitHub MCP data heist (May 2025), and Invariant Labs attack patterns
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

