Generate a new AgentShield runtime policy rule from a GitHub issue.

## Input

$ARGUMENTS is a GitHub issue URL or number from the `security-researcher-ca/AI_Agent_Shield` repo.

## Steps

1. **Parse the issue**:
   ```bash
   gh issue view <N> --repo security-researcher-ca/AI_Agent_Shield --json number,title,body,labels
   ```
   Extract: threat description, kingdom, example commands (BLOCK + ALLOW), decision, match type (if specified).

2. **Read project conventions**: Read `CLAUDE.md` for rule format, test coverage requirements, and kingdom-to-file mapping.

3. **Create a feature branch**:
   ```bash
   git checkout -b rule/<issue-number>-<short-slug>
   ```

4. **Determine target pack** based on kingdom:
   | Kingdom | Pack file |
   |---------|-----------|
   | destructive-ops | `packs/terminal-safety.yaml` |
   | credential-exposure | `packs/secrets-pii.yaml` |
   | data-exfiltration | `packs/network-egress.yaml` |
   | supply-chain | `packs/supply-chain.yaml` |
   | Others | Best-fit existing pack |

5. **Choose match type** if not specified in the issue. Prefer the simplest analyzer that covers the threat:
   - `regex` — for simple command prefixes/patterns
   - `structural` — when flag/argument analysis matters (uses shell AST)
   - `semantic` — when intent classification is needed
   - `dataflow` — when source→sink taint tracking through pipes/redirects is needed
   - `stateful` — when multi-step attack chain detection is needed

6. **Generate the rule** in the target pack YAML. Follow existing rules in that file for format. Required fields:
   ```yaml
   - id: "<pack-prefix>-<verb>-<noun>"
     taxonomy: "<kingdom>/<category>/<specific>"
     match:
       # Use the appropriate match type
     decision: "BLOCK"  # or AUDIT
     reason: "Human-readable explanation"
     confidence: 0.90
   ```

7. **Generate test cases** in `internal/analyzer/testdata/<kingdom>_cases.go`:
   - Minimum **2 TP + 2 TN** cases
   - Use the `TestCase` struct:
     ```go
     {
         ID:               "TP-<RULE-ID>-001",
         Command:          "the dangerous command",
         ExpectedDecision: "BLOCK",
         Classification:   "TP",
         TaxonomyRef:      "kingdom/category/specific",
         Analyzer:         "regex",  // which analyzer should catch this
         Description:      "description of why this is dangerous",
         Tags:             []string{"tp", "kingdom-tag"},
     },
     ```
   - TN cases use `ExpectedDecision: "ALLOW"`, `Classification: "TN"`, `Tags: []string{"tn", "safe"}`
   - Include edge cases: variations of the dangerous command, similar-but-safe commands

8. **Run tests**:
   ```bash
   go test -v -run TestAccuracy ./internal/analyzer/
   ```
   If tests fail, read the error, fix the rule or test, and retry (up to 3 attempts).

9. **Run full suite** to check for regressions:
   ```bash
   go test ./...
   ```

10. **Regenerate failing tests report**:
    ```bash
    go test -v -run TestGenerateFailingTestsReport ./internal/analyzer/
    ```

11. **Commit and push**:
    ```bash
    git add packs/<file>.yaml internal/analyzer/testdata/<kingdom>_cases.go FAILING_TESTS.md
    git commit -m "feat: add rule <rule-id> — <short description>

    Closes #<issue-number>"
    git push -u origin rule/<issue-number>-<short-slug>
    ```

12. **Create PR**:
    ```bash
    gh pr create --title "Rule: <short description>" --body "Closes #<issue-number>

    ## Rule
    - ID: \`<rule-id>\`
    - Decision: BLOCK/AUDIT
    - Match type: regex/structural/etc.
    - Kingdom: <kingdom>

    ## Test cases
    - TP: <count> cases
    - TN: <count> cases

    ## Validation
    - [ ] TestAccuracy passes
    - [ ] Full test suite passes
    - [ ] No regressions in FAILING_TESTS.md"
    ```

13. **Comment on issue and update labels**:
    ```bash
    gh issue comment <N> --repo security-researcher-ca/AI_Agent_Shield --body "PR created: <pr-url>"
    gh issue edit <N> --repo security-researcher-ca/AI_Agent_Shield --add-label "pr-ready" --remove-label "in-progress"
    ```
