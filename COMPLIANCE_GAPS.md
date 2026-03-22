# Compliance Gap Analysis

**Generated**: 2026-03-22 (Baby Kai Taxonomy — Audit #199)
**Taxonomy entries**: 299 | **Compliance standards**: 5 | **Total controls**: 53

## Executive Summary

The taxonomy provides strong coverage across most compliance controls, with **50 of 53 controls (94%)** having at least one taxonomy entry mapped. **3 controls have zero coverage** — all are organizational/policy-level controls out of scope for a runtime security product. Previously-noted gaps (LLM08 Vector & Embedding Weaknesses, SOC2 PI1.3 Processing Integrity, EU AI Act Art.14 Human Oversight, ISO A.5.23 Cloud Services) have all been **resolved**.

---

## OWASP LLM Top 10 2025 Coverage

| ID | Category | Entries | Coverage | Notes |
|----|----------|---------|----------|-------|
| LLM01 | Prompt Injection | 8 | GOOD | Covered via pipe-to-shell, reverse-shell, base64 exfil, indirect-code-exec |
| LLM02 | Sensitive Information Disclosure | 42 | STRONG | Broadest coverage — credential exposure + data exfiltration kingdoms |
| LLM03 | Supply Chain | 12 | GOOD | supply-chain kingdom + cicd-tampering, build-pipeline entries |
| LLM04 | Data and Model Poisoning | 10 | GOOD | model-poisoning category expanded: rag-knowledge-base-poisoning, adversarial-embedding-manipulation, training-data-tampering, model-deserialization-exploit |
| LLM05 | Improper Output Handling | 35 | STRONG | Destructive ops + supply chain entries |
| LLM06 | Excessive Agency | 91 | BROAD | ~92% of entries — used as catch-all for agent autonomy |
| LLM07 | System Prompt Leakage | 5 | GOOD | system-prompt-exfiltration, context-window-probe, cross-session-context-leakage, agent-memory-poisoning, context-window-poisoning |
| LLM08 | Vector & Embedding Weaknesses | **4** | **ADEQUATE** | ~~GAP~~ → **RESOLVED**: rag-knowledge-base-poisoning, adversarial-embedding-manipulation, embedding-inversion-attack, cross-tenant-rag-leakage |
| LLM09 | Misinformation | 3 | LOW | ai-hallucination-injection, ai-misinformation-propagation, ai-assisted-social-engineering |
| LLM10 | Unbounded Consumption | 4 | ADEQUATE | fork-bomb, unbounded-transfer, uncontrolled-agent/model |

### Resolved Gaps (cumulative)
- **LLM08** ✅: Now covered by 4 entries: `rag-knowledge-base-poisoning`, `adversarial-embedding-manipulation`, `embedding-inversion-attack`, `cross-tenant-rag-leakage` (Audit #184)
- **LLM04** ✅: Expanded from 2 to 10+ entries via new model-poisoning subcategory entries (Audit #184)

### Resolved Gaps (this audit)
- **LLM07** ✅: Expanded from 3 to 5 entries — added `agent-memory-poisoning` (CLAUDE.md/cursorrules ARE system prompts) and `context-window-poisoning` (displacing system prompts from context) (Audit #199)

### Remaining Gaps
- **LLM07**: Coverage now GOOD at 5 entries; further expansion possible as more agentic memory patterns emerge

### Over-representation
- **LLM06**: Mapped to 92% of entries. While agent autonomy is broadly relevant, this dilutes the signal. Consider reserving LLM06 for entries specifically about agent capability boundaries.

---

## ISO/IEC 27001:2022 Coverage

| Control | Title | Entries | Status |
|---------|-------|---------|--------|
| A.5.1 | Policies for Information Security | **0** | **GAP** |
| A.5.10 | Acceptable Use of Information Assets | 25 | STRONG |
| A.5.23 | Information Security for Cloud Services | 14 | GOOD |
| A.5.34 | Privacy and Protection of PII | 21 | STRONG |
| A.8.3 | Information Access Restriction | 23 | STRONG |
| A.8.4 | Access to Source Code | 8 | GOOD |
| A.8.9 | Configuration Management | 60 | STRONG |
| A.8.11 | Data Masking | 8 | GOOD |
| A.8.12 | Data Leakage Prevention | 21 | STRONG |
| A.8.20 | Networks Security | 18 | STRONG |
| A.8.23 | Web Filtering | 17 | STRONG |
| A.8.25 | Secure Development Life Cycle | 16 | STRONG |
| A.8.26 | Application Security Requirements | 4 | ADEQUATE |
| A.8.28 | Secure Coding | 12 | GOOD |
| A.8.31 | Environment Separation | 23 | STRONG |
| A.8.33 | Test Information | **0** | **GAP** |

### Gap Analysis
- **A.5.1 (Policies)**: Organizational-level control — taxonomy focuses on technical threats, not policy governance. Acceptable gap for a runtime security product.
- **A.5.23 (Cloud Services)** ✅: **RESOLVED** — 14 entries now explicitly mapped, including cloud-credential-access, azure-cli-token-extract, gcp-cli-token-extract, cloud-cli-access, vault-secret-read, and others.
- **A.8.33 (Test Information)**: Test data protection isn't in scope for runtime agent security. Acceptable gap.

---

## EU AI Act 2024 Coverage

| Article | Title | Entries | Status |
|---------|-------|---------|--------|
| Art.9 | Risk Management System | 56 | STRONG |
| Art.10 | Data and Data Governance | 8 | GOOD |
| Art.13 | Transparency | 8 | GOOD |
| Art.14 | Human Oversight | 32 | GOOD |
| Art.15 | Accuracy, Robustness, Cybersecurity | 78 | STRONG |
| Art.26 | Deployer Obligations | 2 | LOW |
| Art.50 | Transparency for Certain AI Systems | 1 | LOW |

### Gap Analysis
- **Art.14 (Human Oversight)** ✅: **RESOLVED** — 32 entries now map to Art.14, including uncontrolled-agent-execution, uncontrolled-model-invocation, unrestricted-tool-invocation, autonomous-tool-chaining, and many agentic attack entries.
- **Art.26/Art.50**: These are deployer/transparency obligations — more organizational than technical. Acceptable low coverage for a runtime security product.

---

## NIST AI Risk Management Framework 1.0 Coverage

| Control | Title | Entries | Status |
|---------|-------|---------|--------|
| GOVERN-1 | Policies and Practices | 20 | GOOD |
| GOVERN-6 | Team-Level Policies | 7 | ADEQUATE |
| MAP-1 | Context Establishment | **0** | **GAP** |
| MAP-5 | Risk Estimation | 23 | STRONG |
| MEASURE-2 | Risk Measurement | 13 | GOOD |
| MANAGE-1 | Risk Prioritization | 49 | STRONG |
| MANAGE-2 | Risk Mitigation Strategy | 45 | STRONG |
| MANAGE-4 | Risk Treatment Monitoring | 15 | GOOD |

### Gap Analysis
- **MAP-1 (Context Establishment)**: Organizational control about establishing AI risk context. Not directly addressable by runtime security rules. Acceptable gap.

---

## SOC 2 Type II Coverage

| Control | Title | Entries | Status |
|---------|-------|---------|--------|
| CC6.1 | Logical/Physical Access Controls | 23 | STRONG |
| CC6.2 | System Credential Management | 10 | GOOD |
| CC6.3 | Authorization and Access Control | 17 | STRONG |
| CC6.6 | System Boundary Protection | 26 | STRONG |
| CC6.7 | Information Transmission Restriction | 14 | GOOD |
| CC6.8 | Unauthorized Software Prevention | 12 | GOOD |
| CC7.1 | Change/Vulnerability Detection | 23 | STRONG |
| CC7.2 | Security Event Monitoring | 7 | ADEQUATE |
| CC8.1 | Change Management Controls | 40 | STRONG |
| CC9.1 | Risk Mitigation Activities | 16 | GOOD |
| PI1.3 | Processing Integrity — Data Accuracy | **4** | **ADEQUATE** |
| C1.1 | Confidentiality of Information | 13 | GOOD |

### Gap Analysis
- **PI1.3 (Processing Integrity)** ✅: **RESOLVED** — Now covered by `ai-hallucination-injection`, `ai-output-accountability-gap`, `rag-knowledge-base-poisoning`, `adversarial-embedding-manipulation`.

---

## Cross-Standard Gap Summary

| Gap | Standards Affected | Severity | Status |
|-----|-------------------|----------|--------|
| ~~No vector/embedding/RAG entries~~ | OWASP LLM08 | ~~CRITICAL~~ | ✅ **RESOLVED** (Audit #184) — 4 entries added |
| ~~Low model poisoning coverage~~ | OWASP LLM04 | ~~HIGH~~ | ✅ **RESOLVED** (Audit #184) — 10+ model-poisoning entries |
| ~~No processing integrity mapping~~ | SOC2 PI1.3 | ~~MEDIUM~~ | ✅ **RESOLVED** (Audit #184) — 4 entries cover PI1.3 |
| ~~Low human oversight mapping~~ | EU AI Act Art.14 | ~~MEDIUM~~ | ✅ **RESOLVED** (Audit #185) — 32 entries now map to Art.14 |
| ~~Missing cloud services mapping~~ | ISO A.5.23 | ~~LOW~~ | ✅ **RESOLVED** (Audit #185) — 14 entries now map to A.5.23 |
| Policy/organizational controls | ISO A.5.1, NIST MAP-1, EU Art.26/50 | LOW | Acceptable — out of scope for runtime security |

---

## Coverage Heat Map

```
Standard         Total  Covered  Gap  Coverage%
OWASP LLM 2025      10      10    0     100.0%  (unchanged)
ISO 27001:2022       16      14    2      87.5%  (+1 since Audit #184: A.5.23 resolved)
EU AI Act 2024        7       7    0     100.0%  (unchanged)
NIST AI RMF 1.0       8       7    1      87.5%  (unchanged — MAP-1 acceptable)
SOC 2 Type II        12      12    0     100.0%  (unchanged)
─────────────────────────────────────────────
TOTAL                53      50    3      94.3%  (+1.8pp since Audit #184)
```

*Note: "Covered" means at least 1 taxonomy entry maps to the control. Quality of coverage varies — see per-standard analysis above.*
