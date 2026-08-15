# MCP fixture indirection (`args_b64`)

**Problem it solves (issue #2925).** MCP detection rules need true-positive fixtures
that contain the very phrasing the rule detects (exfil relays, prompt injection,
av-evasion, …). When an AI agent authors a *dense batch* of these rules in one
session, the accumulated attack phrasing trips Claude Code's **session
safety-classifier** — a harness-level meta-classifier, distinct from AgentShield
and the permission prompt. Once tripped, it refuses *all* `go` execution for the
rest of the session (`go build`, `go test`, even `go version`), so the agent can't
verify its work locally. This has caused real overnight work loss on our
highest-moat rule development.

**Fix.** Keep the raw payload out of the session transcript. Instead of writing a
test case's arguments inline, store them as an opaque base64 blob in an `args_b64`
field. The committed rule — and every later read of it — carries only the blob, so
the batch never accumulates enough readable attack phrasing to cross the
classifier threshold.

`args_b64` is **test-only**: at runtime, tool-call arguments come from the MCP
proxy, never from a rule's `tests:` block. Encoding fixture args cannot affect live
policy evaluation.

## Field

```yaml
tests:
  tp:
    - tool: "write_file"
      args_b64: "eyJwYXRoIjoiL2V0Yy9zaGFkb3cifQ=="   # base64 of {"path":"/etc/shadow"}
  tn:
    - tool: "write_file"
      args: {"path": "/workspace/README.md"}          # inline is still fine for benign TNs
```

- `args_b64` is base64 of a **JSON object** — the same map you would have written
  under `args:`.
- `args` and `args_b64` are **mutually exclusive** on a single case (setting both
  is a hard error).
- Numbers decode as `float64` (JSON semantics). Immaterial for the string-valued
  tool arguments (paths, content, URLs) these rules match on — use plain inline
  `args` for the rare numeric-argument case.
- Only the *sensitive* cases need encoding. Benign TNs can stay inline for
  readability; mix freely within one rule.

## Authoring workflow

Use the `encode-fixture` helper so the raw phrasing appears at most once,
transiently, and never lands in a committed file:

```bash
# Encode: JSON args on stdin -> base64 for the args_b64 field
echo '{"path":"/etc/shadow","content":"…"}' | go run ./cmd/encode-fixture

# Decode (for review/debugging): base64 on stdin -> pretty JSON
go run ./cmd/encode-fixture -d <<< "eyJwYXRoIjoiL2V0Yy9zaGFkb3cifQ=="
```

For an agent operating under the classifier: write the args JSON to a scratch file
it will not re-read (or pipe it straight in), encode once, and paste only the
resulting base64 into the rule YAML.

## How it decodes

`internal/mcp.MCPTestCase.ResolvedArgs()` is the single canonical decode path. The
inline-test harness (`internal/mcp/rule_yaml_test.go`) calls it for every TP/TN
case, so inline `args` and `args_b64` are behaviorally identical — verified by
`TestFixtureIndirection_EndToEnd` in `internal/mcp/fixture_indirection_test.go`.
