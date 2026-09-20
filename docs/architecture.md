# Architecture and scan workflow

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

## 8. Architecture

Use a modular application with external scanner processes and a versioned adapter interface:

```text
CLI + trusted policy + target
              |
      Discovery and preflight
              |
       Explicit scan plan
              |
 Resource-bounded scheduler
              |
  Scanner adapters and isolated workers
              |
 Sanitized evidence + run manifest
              |
 Normalization and correlation
              |
 Deterministic policy evaluation
              |
 Report model ---- Optional AI enrichment
              |
 HTML / Markdown / JSON / SARIF / optional SBOM
```

| Component | Responsibility |
| --- | --- |
| Discovery | Inspect files without executing them; identify languages, package inputs, infrastructure, and candidate images |
| Planner | Match inputs to declared adapter capabilities; calculate prerequisites and coverage expectations |
| Tool manager | Resolve approved binaries by version and integrity metadata; manage offline bundles and isolated installations |
| Scheduler | Enforce dependencies, concurrency, CPU/memory budgets, cancellation, and per-tool deadlines |
| Adapters | Construct argument arrays, invoke scanners, interpret native exit codes, and parse documented outputs |
| Evidence store | Keep restricted, sanitized artifacts with integrity hashes and provenance |
| Normalizer | Map severities, identifiers, locations, packages, and resource instances into the canonical schema |
| Correlation engine | Identify exact duplicates; group related issues without losing individual evidence |
| Policy engine | Apply severity thresholds, required coverage, baselines, and approved exceptions |
| AI gateway | Redact and minimize input, call configured providers, validate structured responses, and record attribution |
| Report renderer | Generate leadership and developer views from the same canonical report model |

Each adapter exposes `capabilities`, `preflight`, `plan`, `execute`, and `normalize`. Its contract declares supported inputs, host requirements, network needs, output schema, and whether it may execute repository code. Use subprocess isolation; an adapter is not permission to load arbitrary repository-provided plugins.

### Platform strategy

Ship the orchestrator for Windows, Linux, and macOS, with a tested OS/architecture matrix. Scanner support is a separate compatibility matrix. Semgrep currently advertises native Windows support, but exact scanner versions still require qualification. [Semgrep platform documentation](https://semgrep.dev/products/community-edition/)

Prefer native scanner execution where supported. Offer an explicit container or WSL execution backend when useful, recording its actual platform and prerequisites. Do not promise that every scanner-language combination runs on every host. Generic “Unix” support beyond Linux and macOS is a future portability objective, not an MVP commitment.


## 9. Scan workflow

1. **Identify the target.** Capture repository identity, commit where available, working-tree changes, and content hashes. Prefer a stable snapshot; detect mutations during scanning.
2. **Load trusted policy.** Establish profiles, budgets, network rules, output settings, and required coverage. Repository settings cannot weaken centrally enforced policy.
3. **Discover content.** Inventory language and package inputs, infrastructure files, and exclusions without building or installing project dependencies.
4. **Preflight.** Check scanner integrity, licenses/entitlements, toolchains, storage, database freshness, and offline readiness.
5. **Plan and execute.** Run independent scanners concurrently within resource limits; isolate authorized build-dependent work.
6. **Capture status.** Record success, failure, timeout, unsupported, not applicable, disabled, or blocked for every planned check. Preserve completed results if another tool fails.
7. **Normalize and correlate.** Preserve native evidence, map fields, deduplicate exact matches, and link related observations.
8. **Evaluate policy.** Calculate deterministic counts and priorities; apply approved exceptions and baseline comparisons.
9. **Enrich optionally.** Generate AI explanations from redacted evidence. AI failure leaves the deterministic assessment usable.
10. **Publish locally.** Write reports atomically, display the output location, and return the appropriate status. Uploads require an explicit integration configuration.
