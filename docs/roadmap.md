# Phased roadmap

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

## 16. Phased roadmap

Indicative estimates assume two engineers with part-time application security support. Re-estimate after the adapter and platform spike; toolchain complexity and security qualification can change delivery time.

| Phase | Indicative duration | Deliverables and exit gate |
| --- | --- | --- |
| 0 — Feasibility | 1–2 weeks | Verify licensing and maintenance posture; qualify initial OS/tool matrix; benchmark representative repositories; approve schema and threat model |
| 1 — MVP | 4–6 weeks | Default scanner adapters, local scans, optional bounded CodeQL pilot, normalization, deterministic reports, coverage-aware exit codes; acceptance suite passes |
| 2 — Reporting and CI | 2–3 weeks | Harden AI validation, improve baselines/triage, support approved remote checkout and CI examples; assess report accuracy with security reviewers |
| 3 — Expanded analysis | 3–5 weeks | Broader CodeQL languages and isolated builds, comparative Checkov/OSV evaluation, improved image provenance, optional Syft SBOM and license policy |
| 4 — Operational maturity | Ongoing | Offline bundles, organization policy distribution, history storage, integrations, optional live Kubernetes checks, signed release lifecycle |

Prioritize adapter correctness, coverage transparency, and report usefulness before dashboards or automated remediation. Future fix proposals should be isolated changes with human approval, tests, and rescans.
