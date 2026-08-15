# Taxonomy Health Report

**Generated**: 2026-03-16 (Opus Taxonomy Deep Dive — Audit #44)
**Total entries**: 103 | **Kingdoms**: 8 | **Categories**: 48 | **Pack rules**: 255

---

## 1. Entries by Kingdom

| Kingdom | Entries | % of Total |
|---------|---------|-----------|
| Destructive Operations | 24 | 23.3% |
| Credential & Secret Exposure | 17 | 16.5% |
| Data Exfiltration | 14 | 13.6% |
| Supply Chain Compromise | 11 | 10.7% |
| Privilege Escalation | 11 | 10.7% |
| Persistence & Defense Evasion | 9 | 8.7% |
| Unauthorized Code Execution | 9 | 8.7% |
| Reconnaissance & Discovery | 8 | 7.8% |

**Observation**: Destructive Operations dominates (23.3%), driven by cloud infrastructure entries (13 AWS/Azure/GCP/K8s entries). Unauthorized Execution and Persistence are the lightest kingdoms.

---

## 2. Risk Level Distribution

| Level | Count | % |
|-------|-------|---|
| Critical | 48 | 46.6% |
| High | 47 | 45.6% |
| Medium | 7 | 6.8% |
| Low | 1 | 1.0% |

**Observation**: 92.2% of entries are Critical or High. This is appropriate for a security taxonomy — the entries represent genuine threats. The 7 Medium entries are: generic-config-access, network-http-request, standard-package-install, context-window-probe, technology-fingerprint, uncontrolled-model-invocation, and dependency-confusion/package-install.

---

## 3. Runtime Rule Coverage (AgentShield Packs)

| Metric | Count | % |
|--------|-------|---|
| Entries with runtime rules | 102 | 99.0% |
| Entries without runtime rules | 1 | 1.0% |

**Uncovered entries** (no pack rules):
1. `unauthorized-execution/agentic-attacks/mcp-tool-description-poisoning` — Needs guardian/description scanner enhancement (tracked: Shield #202)

**Previously uncovered, now implemented** (PRs #207, #208):
- `unauthorized-execution/agentic-attacks/agent-memory-poisoning` — Added to terminal-safety.yaml + mcp/mcp-persistence.yaml
- `supply-chain/model-poisoning/rag-knowledge-base-poisoning` — Added to supply-chain.yaml + mcp/mcp-supply-chain.yaml

**Note**: `ai-hallucination-injection` and `ai-misinformation-propagation` are intentionally not covered — they require LLM output validation, not shell/MCP interception.

**Assessment**: 99.0% runtime coverage. Only mcp-tool-description-poisoning (Shield #202) and the 2 LLM-output entries remain without pack rules.

---

## 4. Static Analysis Coverage (AI_risk_compliance / Semgrep)

| Metric | Count | % |
|--------|-------|---|
| Entries with Semgrep rules | 97 | 97.0% |
| Entries without Semgrep rules | 3 | 3.0% |
| Total Semgrep rules | 454 | — |

**Uncovered entries** (no Semgrep rule):
1. `credential-exposure/config-file-access/generic-config-access` — intentionally generic, hard to write precise static rules
2. `destructive-ops/cloud-infra/gcloud-storage-delete` — GCP storage deletion not yet covered
3. `persistence-evasion/shell-startup/shell-profile-backdoor` — **NEW entry** — needs Semgrep rule for `.bashrc`/`.zshrc` writes

**Dual coverage** (both runtime + static): **97 of 103 entries (94.2%)**. The 3 new agentic-attack entries now have runtime pack rules but still need Semgrep coverage (tracked: Comply #212).

---

## 5. Compliance Coverage per Standard

| Standard | Total Controls | Covered | Gap | Coverage % |
|----------|---------------|---------|-----|-----------|
| OWASP LLM Top 10 2025 | 10 | 10 | 0 | **100.0%** |
| ISO/IEC 27001:2022 | 16 | 14 | 2 | 87.5% |
| EU AI Act 2024 | 7 | 7 | 0 | **100.0%** |
| NIST AI RMF 1.0 | 8 | 7 | 1 | 87.5% |
| SOC 2 Type II | 12 | 12 | 0 | **100.0%** |
| **Overall** | **53** | **50** | **3** | **94.3%** |

**Remaining gaps** (organizational controls outside runtime security scope):
- ISO A.5.1 (Policies for Information Security) — governance, not technical
- ISO A.8.33 (Test Information) — test data handling, not agent security
- NIST MAP-1 (Context Establishment) — organizational risk context

**Key improvement this audit**: LLM08 coverage went from 0 → 3 entries with the addition of RAG knowledge base poisoning, MCP tool description poisoning, and agent memory poisoning.

---

## 6. OWASP LLM 2025 Mapping Distribution

| Category | Entries | Assessment |
|----------|---------|-----------|
| LLM01 Prompt Injection | 10 | GOOD |
| LLM02 Sensitive Info Disclosure | 42 | STRONG |
| LLM03 Supply Chain | 8 | GOOD |
| LLM04 Data/Model Poisoning | 3 | ADEQUATE (was 2) |
| LLM05 Improper Output Handling | 35 | STRONG |
| LLM06 Excessive Agency | 93 | OVER-BROAD (90%) |
| LLM07 System Prompt Leakage | 2 | LOW |
| LLM08 Vector/Embedding Weaknesses | 3 | ADEQUATE (was 0) |
| LLM09 Misinformation | 2 | LOW |
| LLM10 Unbounded Consumption | 4 | ADEQUATE |

---

## 7. Quality Metrics

| Metric | Value |
|--------|-------|
| Total YAML lines across entries | 6,043 |
| Average lines per entry | 58.7 |
| Entries with all 5 compliance mappings | 103 (100%) |
| Entries with MITRE ATT&CK references | ~95% |
| Entries with CWE references | ~95% |
| Entries with external reference links | ~30% |
| Categories with _category.yaml | 48/48 (100%) |
| Kingdoms with _kingdom.yaml | 8/8 (100%) |

---

## 8. Changes Made in This Audit

### OWASP Mapping Fixes (11 entries)
| Entry | Change | Reason |
|-------|--------|--------|
| ssh-tunnel | LLM08 → LLM02 | SSH tunnels are data exfil, not vector/embedding |
| cicd-config-injection | Remove LLM08 | CI/CD is supply chain, not vector/embedding |
| history-clearing | LLM08 → LLM06 | Anti-forensics is excessive agency, not vector |
| log-tampering | LLM08 → LLM06 | Anti-forensics is excessive agency, not vector |
| system-prompt-exfiltration | Add LLM02 | Exposes sensitive information, not just prompt leakage |
| database-credential-access | Add LLM06 | Consistency with other credential exposure entries |
| clipboard-data-exposure | Add LLM06 | Consistency with other credential exposure entries |
| dns-lookup | Add LLM06 | Consistency with other reconnaissance entries |
| ebpf-surveillance | Reorder to [LLM02, LLM06] | Alphabetical consistency |
| at-job-scheduling | Remove LLM05 | LLM05 doesn't apply to job scheduling |
| global-package-install | Add LLM03 | Supply chain entry should map to LLM03 |

### Severity Calibration (4 entries)
| Entry | Before | After | Reason |
|-------|--------|-------|--------|
| pipe-to-shell | medium | **critical** | Most dangerous install pattern, zero review window |
| clipboard-data-exposure | medium | **high** | Passive credential harvesting, high confidence |
| git-data-exfil | medium | **high** | Source code value underestimated |
| uncontrolled-model-selection | medium | **high** | Consistency with customer-data-to-llm |

### Compliance Mapping Fixes (4 entries)
| Entry | Change | Reason |
|-------|--------|--------|
| ai-hallucination-injection | Add SOC2 PI1.3 | Processing integrity applies to hallucinated content |
| ai-misinformation-propagation | Add SOC2 PI1.3 | Processing integrity applies to false content |
| cloud-credential-access | Add ISO A.5.23 | Cloud services security control |
| uncontrolled-agent-execution | Add EU Art.14 | Human oversight applies to autonomous agents |

### New Taxonomy Entries (3 entries)
| Entry | Kingdom | Risk | Gap Filled |
|-------|---------|------|-----------|
| rag-knowledge-base-poisoning | Supply Chain (7.4) | Critical | LLM08 + LLM04 |
| mcp-tool-description-poisoning | Unauthorized Execution (4.4) | Critical | LLM01 + LLM08 |
| agent-memory-poisoning | Unauthorized Execution (4.4) | High | LLM01 + LLM08 |

---

## 9. Top 5 Recommendations

1. **Reduce LLM06 over-mapping**: Currently 90% of entries map to LLM06 (Excessive Agency). Review and remove from entries where agency is not the primary threat (e.g., pure credential exposure, pure network egress). Target: <60%.

2. **Create GitHub issues for new entry rules**: The 3 new taxonomy entries (RAG poisoning, MCP tool poisoning, agent memory poisoning) need corresponding pack rules in AgentShield and Semgrep rules in AI_risk_compliance.

3. **Consider merging CI/CD entries**: `cicd-config-injection` (supply-chain) and `pipeline-config-write` (persistence-evasion) describe the same attack from different kingdom perspectives. Recommend merging into a single supply-chain entry.

4. **Expand LLM07 coverage**: System prompt leakage has only 2 entries. Consider adding entries for system prompt extraction via tool responses and prompt reconstruction attacks.

5. **Add external references**: Only ~30% of entries have external reference links. Prioritize adding links to MITRE ATT&CK technique pages and relevant security research papers for the 70% that lack them.

---

## Audit History

| Audit | Date | Entries | Runtime Coverage | Compliance Coverage | Key Changes |
|-------|------|---------|-----------------|--------------------|----|
| #43 | Prior | 99 | 100% | 88.7% | Shield #137 fix, Comply submodule bump |
| **#44** | **2026-03-16** | **103** | **97.1%** | **94.3%** | **11 OWASP fixes, 4 severity fixes, 3 new entries, LLM08 gap filled** |
| **#45** | **2026-03-16** | **103** | **99.0%** | **94.3%** | **Runtime rules for rag-kb-poisoning + agent-memory-poisoning (PRs #207,#208); closed stale issues #201,#203; opened Comply #212 for Semgrep coverage** |
