# Accuracy Baseline

Measured across 123 test cases covering 8 threat kingdoms (destructive ops, credential exposure, data exfiltration, unauthorized execution, privilege escalation, persistence/evasion, supply chain, reconnaissance).

| Metric | Regex Only | Pipeline (6-layer) | Improvement |
|--------|-----------|--------------------------------------|-------------|
| **Precision** | 79.3% | **100.0%** | +20.7pp |
| **Recall** | 59.0% | **100.0%** | +41.0pp |
| True Positives | 46 | 106 | +60 |
| True Negatives | 17 | 17 | 0 |
| False Positives | 12 | 0 | −12 |
| False Negatives | 32 | 0 | −32 |

> Run `go test -v -run TestAccuracyMetrics ./internal/analyzer/` for regex-only metrics.
> Run `go test -v -run TestPipelineAccuracyMetrics ./internal/analyzer/` for pipeline metrics.

Regenerate the full failing test list anytime:

```bash
go test -v -run TestGenerateFailingTestsReport ./internal/analyzer/
```

## Red-Team Regression (21 commands)

The guardian + pipeline is tested against prompt injection scenarios. All 21 commands pass minimum decision checks.

Regenerate the full report:

```bash
go test -v -run TestRedTeamPipelineReport ./internal/analyzer/
```

## MCP Security Test Results

### MCP Policy Red-Team (24 cases)

| Category | Cases | Pass Rate |
|---|---|---|
| Blocked tools (execute_command, run_shell, etc.) | 6 | 100% |
| Credential access (SSH, AWS, GnuPG paths) | 6 | 100% |
| System directory writes (/etc, /usr, cron) | 4 | 100% |
| Safe operations (read project files, weather) | 5 | 100% |
| Evasion attempts (path traversal, empty names) | 3 | 100% |
| **Total** | **24** | **100%** |

```bash
go test -v -run TestRedTeamMCP ./internal/mcp/
```

### Tool Description Poisoning Scanner (11 test cases)

Detects 5 signal categories: hidden_instructions, credential_harvest, exfiltration_intent, cross_tool_override, stealth_instruction.

```bash
go test -v -run TestDescriptionScan ./internal/mcp/
```

### Argument Content Scanner (18 test cases)

Detects 11 signal types: private_key, aws_credential, github_token, bearer_token, generic_secret, stripe_key, slack_token, basic_auth, env_file_content, base64_blob, high_entropy.

```bash
go test -v -run TestContentScan ./internal/mcp/
```

### Self-Test

Run all checks at once:

```bash
agentshield scan   # 14 tests: shell + MCP + description + content
```
