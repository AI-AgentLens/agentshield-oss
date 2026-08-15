# Design: Data-Driven Rule System

> **Status:** Phase 1 (Structural) — In Progress  
> **Inspired by:** Traditional SAST rule engines, Semgrep pattern matching  
> **Innovation:** Shell-command-native analysis (pipes, redirects, operators) — not source code

## Problem

Today, users can only write **regex rules** in YAML. Layers 2–6 are hardcoded in Go:

| Layer | User-writable? | Detection capability |
|-------|---------------|---------------------|
| Regex | ✅ YAML | Pattern matching on raw string |
| Structural | ❌ Go only | AST parsing, flag normalization, pipe detection |
| Semantic | ❌ Go only | Intent classification |
| Dataflow | ❌ Go only | Source→sink taint tracking |
| Stateful | ❌ Go only | Multi-step attack chains |
| Guardian | ❌ Go only | Prompt injection signals |

Regex is brittle: `rm -rf /` vs `rm --recursive --force /` vs `sudo rm -f -r /` require
increasingly complex patterns. In traditional SAST tools, regex is used only for secret/content detection.
Most rules are structural, dataflow, or semantic — more robust and easier to write.

## Target Architecture

```
                            YAML Rule
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
              match.regex  match.struct  match.dataflow
                    │          │          │
                    ▼          ▼          ▼
              RegexAnalyzer  StructAnalyzer  DataflowAnalyzer
              (user rules)  (built-in Go    (built-in Go
                            + user YAML)    + user YAML)
                    │          │          │
                    └──────────┼──────────┘
                               ▼
                           Combiner
                      (most restrictive)
```

**Key principle: Additive, not replacement.**  
Built-in Go rules are the "Secure Coding Rulepacks" — always present.  
User YAML rules extend them. Same combiner resolves conflicts.

## SAST Concept Mapping

| Traditional SAST Concept | AgentShield Equivalent | Notes |
|----------------|----------------------|-------|
| FunctionIdentifier | `executable` + `subcommand` | Command = function |
| Parameters | `flags_all`/`flags_any` + `args` | Flags = method params |
| Structural tree query | `structural:` match block | YAML instead of XML |
| Taint source | `dataflow.source` | File/command as source |
| Taint sink | `dataflow.sink` | Network/device/cron as sink |
| Taint passthrough | `dataflow.via` | Encoding/transform commands |
| Taint cleanse | `dataflow.cleanse` | Validators that neutralize risk |
| Taint flags | `dataflow.source.type` | Classification of data kind |
| Control flow pattern | `stateful.chain` | Operator-aware sequencing |
| Content rules (regex) | `match.command_regex` | Already exists |

## Innovation Beyond Traditional SAST

1. **Pipe-chain-aware analysis** — First-class `has_pipe`, `pipe_to`, `pipe_from` predicates.
   Traditional SAST tools don't analyze shell pipes; we do natively.

2. **Operator-aware sequencing** — `&&`, `||`, `;` as control flow connectors.
   Stateful rules can express "download && execute" as a YAML pattern.

3. **Sudo transparency** — `match_sudo: true` automatically matches sudo-wrapped variants.
   No equivalent in source code analysis tools (no sudo in source code).

4. **Guardian layer** — Prompt injection detection is unique to agentic runtime.
   Build-time SAST tools have no equivalent.

5. **Confidence-based combining** — Higher-layer rules (structural, semantic) override
   lower-layer rules (regex) when they disagree, using confidence scores.
   Traditional tools use severity + category; we add confidence weighting.

## Phase 1: Structural Match (YAML)

### YAML Schema

```yaml
rules:
  - id: "block-rm-recursive-system"
    match:
      structural:
        executable: "rm"                      # exact command name
        flags_all: ["r", "f"]                 # must have ALL these flags
        args_any: ["/", "/etc/**", "/usr/**"] # any arg matches any glob
    decision: "BLOCK"
    reason: "Recursive force-delete on system directory."
    taxonomy: "destructive-ops/fs-destruction/system-directory-delete"
```

### Full `structural:` Schema

```yaml
structural:
  # --- Command identification ---
  executable: "rm"                    # exact match (string or list)
  subcommand: "install"               # for npm/pip/git subcommands

  # --- Flag predicates ---
  flags_all: ["r", "f"]              # must have ALL of these
  flags_any: ["r", "recursive", "R"] # must have at least ONE
  flags_none: ["dry-run", "n"]       # must NOT have any of these

  # --- Argument predicates ---
  args_any: ["/", "/etc/**"]         # any positional arg matches any glob
  args_none: ["--help"]              # no arg matches any of these

  # --- Pipe analysis ---
  has_pipe: true                      # command contains a pipe operator
  pipe_to: ["sh", "bash", "python3"] # RHS of pipe is one of these executables
  pipe_from: ["curl", "wget"]        # LHS of pipe is one of these executables

  # --- Modifiers ---
  negate: false                       # if true, finding fires when NO match (for ALLOW overrides)
```

### Design Decisions

1. **`executable` accepts string or list** — `"rm"` or `["rm", "unlink", "shred"]`.
   Allows one rule to cover equivalent commands.

2. **`flags_all` vs `flags_any`** — Both short (`r`) and long (`recursive`) forms accepted.
   The structural parser already normalizes `--recursive` → `recursive` and `-rf` → `r`, `f`.

3. **`args_any` uses glob matching** — `"/etc/**"` matches `/etc/passwd`, `/etc/shadow`, etc.
   Same glob syntax as `protected_paths` (users already know it).

4. **`pipe_to`/`pipe_from`** — Expresses "download piped to interpreter" without regex.
   The structural parser already identifies pipe operators and segments.

5. **`negate`** — Allows structural ALLOW overrides: "if command IS this safe pattern, ALLOW."
   Similar to suppression rules in traditional SAST tools.

6. **`match_sudo` is implicit** — The structural parser already strips sudo.
   All structural rules automatically handle sudo-wrapped variants. No flag needed.

### Implementation

**Files changed:**

| File | Change |
|------|--------|
| `internal/policy/types.go` | Add `Structural *StructuralMatch` to `Match` |
| `internal/analyzer/structural_rule.go` | New: `StructuralRule` type + `MatchStructuralRule()` |
| `internal/analyzer/structural.go` | Accept user rules, evaluate after built-in checks |
| `internal/policy/pipeline.go` | Convert `policy.StructuralMatch` → `analyzer.StructuralRule` |
| `internal/analyzer/structural_rule_test.go` | New: unit tests for matcher |

**Files NOT changed:**
- `engine.go` — no changes needed (already delegates to registry)
- `combiner.go` — no changes (already handles multi-analyzer findings)
- `regex.go` — no changes
- Built-in structural checks — remain as-is

### How User Rules Combine with Built-in Checks

```
StructuralAnalyzer.Analyze(ctx)
  ├── 1. Parse command → ctx.Parsed (always)
  ├── 2. Run built-in Go checks (rmRecursiveRoot, pipeToShell, etc.)
  ├── 3. Run user YAML structural rules against ctx.Parsed
  └── 4. Return all findings → Combiner
```

Built-in checks and user rules produce findings independently.
The Combiner applies most-restrictive-wins across ALL findings from ALL layers.

## Phase 2: Dataflow Match (YAML) — ✅ Implemented

```yaml
rules:
  - id: "block-credential-to-network"
    match:
      dataflow:
        source:
          type: "credential"              # pre-classified: credential, sensitive, zero
          paths: ["~/.ssh/**", "~/.aws/**"]
        sink:
          type: "network"                 # pre-classified: network, device, cron
          commands: ["curl", "wget", "nc"]
        via: ["base64", "gzip"]           # optional: encoding/transform in between
    decision: "BLOCK"
```

## Phase 3: Semantic Match (YAML) — ✅ Implemented

```yaml
rules:
  - id: "block-disk-destruction"
    match:
      semantic:
        intent: "disk-destroy"            # intent category from semantic analyzer
    decision: "BLOCK"
```

## Phase 4: Stateful Match (YAML) — ✅ Implemented

```yaml
rules:
  - id: "block-download-execute-chain"
    match:
      stateful:
        chain:
          - executable_any: ["curl", "wget"]
            flags_any: ["o", "O", "output"]
          - operator: "&&"
          - executable_any: ["bash", "sh", "chmod"]
    decision: "BLOCK"
```

## Testing Strategy

1. **Unit tests** for each match predicate (`flags_all`, `args_any`, `pipe_to`, etc.) — ✅ 52 structural tests
2. **Dataflow tests** — pipe flows, redirect flows, via transforms, negate — ✅ 16 tests
3. **Semantic tests** — intent matching, risk_min threshold, negate, analyzer integration — ✅ 16 tests
4. **Stateful tests** — chain matching, flags in chain, negate, edge cases, analyzer integration — ✅ 13 tests
5. **Integration tests** with real YAML packs containing all rule types — ✅
6. **Regression** — existing 123 test cases + 21 red-team cases must pass unchanged — ✅
