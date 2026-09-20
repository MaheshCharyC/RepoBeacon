# MVP and acceptance criteria

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

## 15. MVP definition and acceptance criteria

The MVP scans a local repository with Semgrep CE, Gitleaks, and Trivy. Its certified SAST test matrix initially includes JavaScript/TypeScript and Python; other supported inputs may run with clearly identified coverage status. SCA certification begins with npm lockfiles and pinned Python dependency inputs. Terraform, Dockerfile, and Kubernetes YAML fixtures establish configuration coverage. Accept explicitly supplied image archives or registry images for package analysis; do not automatically build images.

Include a bounded optional CodeQL pilot for JavaScript/TypeScript and Python where eligible, avoiding build-dependent extraction in the initial release. A pre-provisioned CodeQL installation is sufficient; automatic redistribution is outside the MVP.

Deliver discovery, coverage accounting, timeouts, normalized JSON, HTML executive/technical views, basic SARIF, baseline comparison, trusted suppressions, CI exit codes, and optional evidence-grounded AI summaries. Scanning and deterministic reports must work with AI disabled. Offline mode uses pre-provisioned assets and reports missing or stale databases explicitly.

Acceptance criteria:

- The same scan interface completes on tested Windows, Linux, and macOS environments.
- Seeded supported findings appear with correct locations, categories, and scanner provenance; clean fixtures test known false-positive cases.
- Each planned check receives a terminal execution status, and required missing coverage cannot yield exit code `0`.
- Executive counts reconcile exactly with canonical JSON under documented counting rules.
- Duplicate observations retain evidence while unique findings are counted once.
- Synthetic secrets are absent from logs, stored reports, and AI requests in redaction tests.
- Timeout, malformed output, unavailable tools, and AI failure still produce valid partial reports.
- Offline tests detect and block attempted network activity.
- Repeating a scan with the same snapshot, tools, rules, database, and policy produces stable finding identities and policy decisions.
- Performance is measured on a published reference corpus and hardware; release budgets are set from those measurements rather than an untested universal scan-time claim.
