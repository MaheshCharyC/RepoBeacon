# Normalized finding schema

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

## 10. Normalized vulnerability schema

Use a versioned JSON envelope containing `assessment`, `targets`, `scanner_runs`, `coverage`, `findings`, `policy_result`, and `artifacts`. Validate it with JSON Schema. Preserve unknown vendor fields in a namespaced extension object so adapters can evolve without losing evidence.

### Finding model

| Field | Meaning |
| --- | --- |
| `id`, `fingerprint`, `fingerprint_version` | Assessment-local identifier plus stable, versioned comparison identity |
| `category` | `sast`, `secret`, `sca`, `iac`, `container`, `kubernetes`, or `license` |
| `title`, `description` | Evidence-backed description, independent of AI commentary |
| `observations[]` | Scanner name/version, rule ID, native severity, native confidence, result identifier, and evidence reference |
| `severity`, `severity_basis` | Normalized `critical/high/medium/low/info/unknown` and the mapping policy used |
| `confidence`, `confidence_basis` | Scanner or reviewer confidence; unknown when the source provides none |
| `identifiers` | CVE/GHSA/OSV aliases and CWE identifiers when supplied or reliably mapped |
| `scores[]` | CVSS version, vector, value, source, and timestamp when available |
| `target_id`, `locations[]` | Repository-relative file locations, package manifests, image digest/layer, or resource identities |
| `package`, `dependency_paths[]` | Ecosystem, package URL, installed version, direct/transitive status, and dependency paths if known |
| `resource` | IaC address or Kubernetes kind, namespace, and name where applicable |
| `evidence[]`, `dataflow[]` | Redacted snippets, source/sink traces, and artifact references |
| `remediation` | Scanner-supported fix guidance, fixed versions, references, and verification steps |
| `context` | Reachability, exposure, asset criticality, and evidence sources; unknown by default |
| `priority`, `priority_reasons[]` | Deterministic operational priority and explicit contributing factors |
| `triage` | State, owner, rationale, reviewer, expiry, and audit history |
| `baseline_state` | New, existing, changed, or not comparable |
| `ai_enrichment` | Optional explanation, cited finding/evidence IDs, model metadata, and review status |

Conditional fields must be absent or null when inapplicable. Never invent CVEs, numeric confidence, CVSS scores, fixed versions, or runtime exposure to fill a schema.

Illustrative minimal finding:

```json
{
  "id": "finding-001",
  "fingerprint": "sha256:illustrative-placeholder",
  "fingerprint_version": "1",
  "category": "sast",
  "title": "Potential SQL injection",
  "description": "A scanner reported user input reaching a SQL execution sink.",
  "severity": "high",
  "severity_basis": "rule-map-v1",
  "confidence": "unknown",
  "identifiers": {"cwe": ["CWE-89"], "advisories": []},
  "target_id": "repository-001",
  "locations": [{"path": "src/orders.py", "start_line": 42}],
  "observations": [{
    "scanner": "example-scanner",
    "scanner_version": "example-version",
    "rule_id": "example/sql-injection",
    "native_severity": "high",
    "evidence_ref": "evidence-001"
  }],
  "context": {"reachability": "unknown", "internet_exposure": "unknown"},
  "triage": {"state": "open"},
  "baseline_state": "new",
  "ai_enrichment": null
}
```

**Correlation rules:** SCA identity includes advisory aliases, ecosystem/package identity, installed version, and affected target context. SAST identity uses mapped rule family, normalized path, and a stable code anchor rather than line number alone. IaC identity includes resource instance and control. Secret correlation uses a locally keyed HMAC if needed; never store raw secret values or an unkeyed guessable-secret hash. Maintain all occurrences and source observations.

Related findings are not necessarily duplicates. A shared CWE or similar title is insufficient to merge two issues. Preserve scanner severity disagreements and explain the selected normalized severity. A missing finding becomes “resolved” only after a comparable successful scan covers its prior location and check; otherwise use “not observed” or “not comparable.”
