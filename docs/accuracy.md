# Accuracy

Accuracy is measured, never maintained by hand. The numbers that used to live on
this page (a 123-case baseline from 2026-03-01, "6-layer pipeline") went stale
within weeks and stayed here for six months. Regenerate rather than read.

| What | Command | Output |
|---|---|---|
| Regex-only vs full-pipeline precision/recall over the whole corpus | `go test -run 'TestAccuracyMetrics\|TestPipelineAccuracyMetrics' ./internal/analyzer/ -timeout 40m` | stdout |
| Known false negatives | `go test -run TestGenerateFailingTestsReport ./internal/analyzer/ -timeout 40m` | `FAILING_TESTS.md` (gitignored) |
| Red-team regression: shell pipeline, guardian, MCP | `go test -run TestRedTeam ./internal/analyzer/ ./internal/guardian/ ./internal/mcp/ -timeout 40m` | `internal/*/testdata/*_REDTEAM_REPORT.md` (gitignored) |
| MCP scenario coverage (TP + TN per rule) | `make mcp-verify` | stdout |
| Rule counts (terminal / MCP / total) | `make coverage` | `COVERAGE.md` |
| Latency budget (typical / adversarial P95) | `make test-perf` | stdout |

Two things to know before running these:

- The analyzer suite takes 20+ minutes. Under the default `go test` timeout
  (10m) it dies in a way that looks like a performance regression (#3236) —
  always pass `-timeout`.
- `TestAccuracyMetrics` is static (regex only); `TestPipelineAccuracyMetrics`
  is the live metric and the one that responds to pipeline changes. The
  2026-07-01 stage ablation was measured against the latter.

The case corpus lives in `internal/analyzer/testdata/*.go`, one file per threat
kingdom. Never quote a corpus size or recall figure from a doc — quote the test
output and the commit it ran on.

Self-test of an installed binary:

```bash
agentshield scan
```
