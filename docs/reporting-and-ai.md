# Reporting and AI enrichment

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

## 11. Reporting requirements

### Executive / high-level report

Provide a concise assessment of the target and scan date, policy outcome, completion status, key risk themes, affected components, and recommended remediation priorities. Include unique issue counts by severity and category, affected occurrences, accepted exceptions, changes since a comparable baseline, and a clearly visible coverage section.

Describe business impact conditionally when deployment context is unknown. Show immediate actions, near-term remediation work, and longer-term improvements, with owners where configured. Do not present finding counts as a precise probability of breach or an invented universal security score.

### Engineering / low-level report

Provide searchable findings with stable IDs, scanner provenance, file/line or package/resource coordinates, redacted evidence, available data-flow traces, advisory references, fixed versions where known, remediation guidance, and verification steps. Include native severity alongside normalized severity, suppression rationale, scan failures, tool versions, ruleset identifiers, and database dates.

### Output package

```text
security-report/
  index.html
  executive-summary.md
  technical-report.md
  findings.json
  findings.sarif
  scan-manifest.json
  coverage.json
  sbom.cdx.json          (when requested)
  evidence/             (sanitized, access-restricted artifacts)
```

JSON is the complete canonical interchange format. SARIF exports compatible findings for developer tooling; SBOMs remain separate inventory artifacts. HTML must be self-contained, accessible, and escaped, with no remote assets. PDF export can follow after the MVP.


## 12. AI-assisted reporting

AI receives a bounded evidence package containing canonical findings, approved context, and deterministic aggregate statistics. It may draft summaries, explain technical weaknesses, group remediation themes, and suggest developer verification steps. Every substantive finding-specific claim must reference a finding or evidence ID.

Offer three modes: `off` for deterministic templates, `local` for a configured local model endpoint, and `cloud` for an explicitly approved provider and data policy. Local inference also requires resource limits and secure endpoint configuration.

Apply secret redaction before any model input. Default to metadata-only summaries; allow source snippets only under an explicit policy. Record provider/model identity, prompt-template version, redaction policy, timestamp, and input hashes. Enforce request budgets, timeouts, response schemas, and output-size limits.

Repository text, comments, dependency metadata, and scanner messages are untrusted data. They must not instruct the model to run tools, alter policy, transmit additional files, or suppress findings. The reporting model has no execution tools or direct repository-write access.

AI suggestions must remain visibly separate from scanner facts. AI cannot change severity, create authoritative vulnerability records, close findings, approve exceptions, or decide CI pass/fail. Validate generated identifiers and statistics against the canonical model; reject unsupported claims and fall back to templates. Proposed fixes require human review and subsequent testing/rescanning.
