# Compliance Gap Analysis

**Generated**: 2026-03-16 (Opus Taxonomy Deep Dive — Audit #44)
**Taxonomy entries**: 99 | **Compliance standards**: 5 | **Total controls**: 53

## Executive Summary

The taxonomy provides strong coverage across most compliance controls, with **47 of 53 controls (89%)** having at least one taxonomy entry mapped. However, **6 controls have zero coverage**, and several OWASP LLM categories are significantly under-represented. The most critical gap is **LLM08 (Vector & Embedding Weaknesses)** with zero taxonomy entries after incorrect mappings were removed during this audit.

---

## OWASP LLM Top 10 2025 Coverage

| ID | Category | Entries | Coverage | Notes |
|----|----------|---------|----------|-------|
| LLM01 | Prompt Injection | 8 | GOOD | Covered via pipe-to-shell, reverse-shell, base64 exfil, indirect-code-exec |
| LLM02 | Sensitive Information Disclosure | 42 | STRONG | Broadest coverage — credential exposure + data exfiltration kingdoms |
| LLM03 | Supply Chain | 8 | GOOD | Primarily supply-chain kingdom entries |
| LLM04 | Data and Model Poisoning | 2 | LOW | Only checkpoint-substitution + training-data-tampering |
| LLM05 | Improper Output Handling | 35 | STRONG | Destructive ops + supply chain entries |
| LLM06 | Excessive Agency | 91 | BROAD | 92% of entries — used as catch-all for agent autonomy |
| LLM07 | System Prompt Leakage | 2 | LOW | system-prompt-exfiltration + context-window-probe |
| LLM08 | Vector & Embedding Weaknesses | **0** | **GAP** | **No taxonomy entries — critical gap** |
| LLM09 | Misinformation | 2 | LOW | ai-hallucination-injection + ai-misinformation-propagation |
| LLM10 | Unbounded Consumption | 4 | ADEQUATE | fork-bomb, unbounded-transfer, uncontrolled-agent/model |

### Critical Gaps
- **LLM08**: No coverage for RAG poisoning, embedding manipulation, vector DB injection — a rapidly growing attack surface
- **LLM04**: Only 2 entries cover model poisoning; no coverage for indirect data poisoning via RAG knowledge bases
- **LLM07**: Only 2 entries; system prompt protection is increasingly important as prompts contain security policies

### Over-representation
- **LLM06**: Mapped to 92% of entries. While agent autonomy is broadly relevant, this dilutes the signal. Consider reserving LLM06 for entries specifically about agent capability boundaries.

---

## ISO/IEC 27001:2022 Coverage

| Control | Title | Entries | Status |
|---------|-------|---------|--------|
| A.5.1 | Policies for Information Security | **0** | **GAP** |
| A.5.10 | Acceptable Use of Information Assets | 25 | STRONG |
| A.5.23 | Information Security for Cloud Services | **0** | **GAP** |
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
- **A.5.23 (Cloud Services)**: Cloud credential access and cloud CLI entries exist but don't explicitly map to this control. **Recommended fix**: Add A.5.23 to cloud-credential-access and cloud-cli-access entries.
- **A.8.33 (Test Information)**: Test data protection isn't in scope for runtime agent security. Acceptable gap.

---

## EU AI Act 2024 Coverage

| Article | Title | Entries | Status |
|---------|-------|---------|--------|
| Art.9 | Risk Management System | 56 | STRONG |
| Art.10 | Data and Data Governance | 8 | GOOD |
| Art.13 | Transparency | 8 | GOOD |
| Art.14 | Human Oversight | 2 | LOW |
| Art.15 | Accuracy, Robustness, Cybersecurity | 78 | STRONG |
| Art.26 | Deployer Obligations | 2 | LOW |
| Art.50 | Transparency for Certain AI Systems | 1 | LOW |

### Gap Analysis
- **Art.14 (Human Oversight)**: Only pipe-to-shell and one other entry. Most agent autonomy entries (LLM06-mapped) should also reference Art.14 since human oversight is the primary mitigation. **Recommended fix**: Add Art.14 to uncontrolled-agent-execution and uncontrolled-model-invocation entries.
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
| PI1.3 | Processing Integrity — Data Accuracy | **0** | **GAP** |
| C1.1 | Confidentiality of Information | 13 | GOOD |

### Gap Analysis
- **PI1.3 (Processing Integrity)**: No entries address data accuracy/integrity in AI processing. This could be addressed by mapping ai-hallucination-injection and ai-misinformation-propagation to PI1.3. **Recommended fix**: Add PI1.3 to both AI content integrity entries.

---

## Cross-Standard Gap Summary

| Gap | Standards Affected | Severity | Recommended Action |
|-----|-------------------|----------|-------------------|
| No vector/embedding/RAG entries | OWASP LLM08 | **CRITICAL** | Create new taxonomy entry for RAG/vector poisoning |
| Low model poisoning coverage | OWASP LLM04 | HIGH | Expand model-poisoning category (indirect poisoning via RAG) |
| No processing integrity mapping | SOC2 PI1.3 | MEDIUM | Map AI content integrity entries to PI1.3 |
| Low human oversight mapping | EU AI Act Art.14 | MEDIUM | Add Art.14 to agent autonomy entries |
| Missing cloud services mapping | ISO A.5.23 | LOW | Add A.5.23 to cloud credential/CLI entries |
| Policy/organizational controls | ISO A.5.1, NIST MAP-1, EU Art.26/50 | LOW | Out of scope for runtime security — acceptable |

---

## Coverage Heat Map

```
Standard         Total  Covered  Gap  Coverage%
OWASP LLM 2025      10       9    1      90.0%
ISO 27001:2022       16      13    3      81.3%
EU AI Act 2024        7       7    0     100.0%
NIST AI RMF 1.0       8       7    1      87.5%
SOC 2 Type II        12      11    1      91.7%
─────────────────────────────────────────────
TOTAL                53      47    6      88.7%
```

*Note: "Covered" means at least 1 taxonomy entry maps to the control. Quality of coverage varies — see per-standard analysis above.*
