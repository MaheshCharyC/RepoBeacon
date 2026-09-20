# RepoBeacon

## Project description and implementation blueprint

**Working title:** RepoBeacon — One command. Unified application security insight.  
**Document version:** 1.0 · 19 September 2026  
**Status:** Proposed product specification; command examples describe the intended interface, not an existing application.  
**Audience:** Product owners, application security teams, engineering leads, developers, and AI coding assistants.

## 1. Executive overview

RepoBeacon is a cross-platform command-line application that coordinates established security scanners, consolidates their findings, and produces actionable reports for both leadership and engineering teams. A developer points the tool at a source repository and runs one command. RepoBeacon detects applicable technologies, selects compatible scanners, executes an explicit scan plan, normalizes results, and generates a unified security assessment.

The product covers static application security testing (SAST), exposed secrets, software composition analysis (SCA), infrastructure as code (IaC), Dockerfiles, container images, and Kubernetes manifests. Optional extensions generate software bills of materials (SBOMs), assess license policies, and inspect explicitly authorized Kubernetes clusters.

An optional AI layer explains findings, summarizes likely business impact, and proposes remediation steps using scanner evidence. Core findings, counts, policy decisions, and reports remain available without AI or a cloud account.

**Product promise:** One command to coordinate supported security checks and understand their results, with an honest account of what was and was not assessed.

“Arbitrary repositories” means the application accepts repositories from any host or a local directory and discovers their contents. It does not imply complete analysis of every language, framework, dependency ecosystem, or vulnerability class. Unsupported content must be visible in every report.

## 2. Project-name options

| Name | Positioning | Consideration |
| --- | --- | --- |
| **RepoBeacon — recommended** | Clear security guidance across a repository | Memorable and broad enough for code, dependencies, and infrastructure |
| AppSecCompass | Helps teams navigate application security findings | Explicit purpose; longer CLI name |
| SourceSentinel | Continuous attention to source-code security | May suggest a narrower scope than the product delivers |
| ScanConverge | Combines independent scanners into one assessment | Strong emphasis on aggregation |
| RiskAtlas | Maps technical findings to engineering priorities | Broad name requiring explanatory branding |

Use `repobeacon` as the proposed executable. Names are creative proposals; trademark, package-registry, repository, and domain availability have not been checked.

## 3. Problem, users, and value

Security tools use different installation methods, configuration formats, severity scales, identifiers, and reports. Teams spend time running tools and reconciling results before they can decide what to fix. Leadership receives counts without context, while developers receive findings without a clear path to remediation.

RepoBeacon serves developers needing a local pre-release check, application security engineers reviewing mixed-language repositories, platform teams enforcing CI policies, and engineering leaders prioritizing remediation. Its main value is consistent orchestration, traceable evidence, transparent coverage, and two reports built from the same underlying assessment.

## 4. Goals and non-goals

### Goals

- Provide the same core command interface on Windows, Linux, and macOS.
- Detect languages, package manifests, lockfiles, infrastructure definitions, and image references automatically.
- Run appropriate scanners through versioned adapters with bounded time and resource use.
- Support a useful open-source default profile and optional CodeQL analysis where permitted and technically supported.
- Preserve evidence and scanner provenance while reducing duplicate findings.
- Generate executive and technical reports plus machine-readable output.
- Support reproducible CI decisions, approved exceptions, baselines, and explicit coverage requirements.
- Keep source and findings local by default; make external data transfer explicit.

### Non-goals

- Guaranteeing that all vulnerabilities are detected, that a clean result means secure, or that all languages receive equal coverage.
- Replacing penetration testing, threat modeling, manual review, runtime monitoring, or compliance audits.
- Exploiting findings, testing discovered credentials against providers, or changing production infrastructure by default.
- Automatically fixing code, upgrading dependencies, rotating secrets, or opening pull requests in the MVP.
- Building a new general-purpose SAST engine or vulnerability database.
- Certifying legal compliance from license detection or inferring live cluster security from YAML alone.

## 5. Functional scope and coverage boundaries

| Domain | Inputs and intended checks | Coverage boundary |
| --- | --- | --- |
| SAST | Supported source languages; injection, unsafe APIs, data-flow weaknesses, insecure coding patterns | Quality depends on language, framework, rules, extractor, and build mode |
| Secrets | Working tree, explicitly selected Git history, supported image files | A match indicates suspected exposure; validity and revocation require separate handling |
| SCA | Supported manifests, lockfiles, installed packages, image package inventories | Unresolved versions and unsupported ecosystems remain unknown; package presence does not prove reachability |
| IaC | Terraform, supported cloud templates, deployment configuration | Static configuration may differ from deployed state |
| Docker | Dockerfile configuration and separately supplied container images | A Dockerfile scan does not inspect its built image; image scanning does not require running the image |
| Kubernetes | YAML and explicitly supplied rendered Helm/Kustomize output | Unrendered templates can limit coverage; live cluster assessment is a separate opt-in capability |
| SBOM, optional | Repository or image package inventory | Inventory artifact, not proof of security or complete dependency resolution |
| License policy, optional | Package metadata, detected licenses, configured allow/deny policies | A policy finding is distinct from a security vulnerability; uncertain licenses require review |

Every assessment must identify its target snapshot, included paths, exclusions, languages discovered, applicable scanners, actual execution outcomes, rule versions, database freshness, and unresolved coverage gaps.

## 6. Scanner evaluation and recommendation

Tool capabilities below reflect upstream documentation reviewed for this proposal. Release engineering must qualify exact binary, ruleset, database, operating-system, and architecture combinations before shipping them.

| Tool | Role and strengths | Constraints and recommendation |
| --- | --- | --- |
| **GitHub CodeQL** | Semantic and data-flow SAST for supported languages; SARIF output | Optional deep-analysis adapter. CLI usage is governed by GitHub terms; do not treat it as a universally unrestricted open-source engine. License eligibility, supported language, host, and extraction/build requirements must pass preflight. [CodeQL CLI documentation](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli) |
| **Semgrep Community Edition** | Broad-language SAST, custom rules, relatively simple source scanning | Default SAST candidate. CE analysis does not provide all commercial cross-file capabilities. Engine and individual rule licenses must be assessed separately. [Semgrep repository](https://github.com/semgrep/semgrep) |
| **Gitleaks** | Secret detection in directories and Git history; structured reports and redaction | MVP secret adapter candidate. Upstream currently describes the project as feature complete with security-patch-only future releases; assess maintenance suitability before freezing the dependency. [Gitleaks repository](https://github.com/gitleaks/gitleaks) |
| **TruffleHog** | Secret discovery with credential-verification capabilities | Optional alternative or additional adapter. Keep verification disabled unless specifically authorized; review AGPL licensing for the intended distribution and deployment. [TruffleHog repository](https://github.com/trufflesecurity/trufflehog) |
| **Trivy** | Broad coverage across package vulnerabilities, configuration, secrets, images, and SBOM workflows | Default SCA, IaC, and image candidate to minimize the initial integration surface. Enable scanner categories explicitly and qualify trusted releases. [Trivy repository](https://github.com/aquasecurity/trivy) |
| **OSV-Scanner** | Open-source dependency vulnerability analysis using OSV data | Evaluate as a focused SCA alternative or cross-check for selected ecosystems; measure incremental findings and duplicate rates before enabling alongside Trivy. [OSV-Scanner repository](https://github.com/google/osv-scanner) |
| **Checkov** | Infrastructure configuration policies across supported IaC frameworks | Optional deeper IaC profile. Evaluate rule quality and additional coverage against Trivy on representative repositories. [Checkov repository](https://github.com/bridgecrewio/checkov) |
| **Syft** | Package inventory and SBOM generation from images and filesystems | Preferred candidate when dedicated SBOM generation becomes a product requirement. [Syft repository](https://github.com/anchore/syft) |
| **Grype** | Vulnerability analysis of images, filesystems, and supported SBOMs | Alternative to Trivy’s vulnerability component, particularly with a Syft inventory workflow. [Grype repository](https://github.com/anchore/grype) |
| **Dependabot** | GitHub dependency alerts and security-update pull requests | Optional GitHub integration for remediation and alert import. Do not make the hosted workflow a prerequisite for local, host-independent scanning. [Dependabot documentation](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates) |

**Recommended starting combination:** Semgrep CE + Gitleaks + Trivy, with CodeQL available as an optional adapter. This is an architectural recommendation, conditional on release qualification, maintenance review, and representative accuracy testing. Avoid enabling every overlapping scanner by default.

Evaluate candidates using the same seeded vulnerable and clean fixtures. Measure supported inputs, verified detections, false positives, incremental unique findings, cold/warm execution time, peak memory, offline behavior, platform reliability, output stability, licensing, and maintenance activity. Add a scanner when its demonstrated benefit justifies its operational cost.

### CodeQL integration policy

CodeQL is valuable for deeper analysis where its language and framework support applies. Current supported language information must come from the pinned release and [official support matrix](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/), rather than a permanent claim of universal language support.

The adapter checks user-configured usage eligibility, discovers supported languages, selects an appropriate extraction mode, creates one or more databases, executes pinned query packs, and imports SARIF. Public-source availability alone must not be used to infer permission for every possible use. Private-code usage requires the applicable entitlement; the CLI terms differ from the license for the open-source queries and libraries. [CodeQL licensing context](https://github.com/github/codeql/blob/main/README.md)

Some extraction modes require builds and toolchains. Prefer build-free extraction where supported and appropriate; otherwise require an explicitly trusted build profile. Build execution can run repository-controlled code and belongs in an isolated worker. When CodeQL cannot run, record the reason and continue other configured checks; if policy requires CodeQL, the overall assessment is incomplete.

## 7. CLI experience

After installation and scanner provisioning, the primary workflow is:

```text
repobeacon scan .
```

This discovers applicable inputs, runs the standard profile, writes HTML and JSON reports, and prints a concise summary with coverage status. First-run provisioning is separate from scanning so CI does not silently download or execute unreviewed tools.

Proposed commands work in PowerShell and common Unix shells without shell-specific continuation syntax:

```text
repobeacon doctor
repobeacon tools install --profile standard
repobeacon scan . --profile standard --output ./security-report
repobeacon scan "C:\work\payments" --output "C:\reports\payments"
repobeacon scan /home/dev/payments --format html,json,sarif,markdown
repobeacon scan . --profile deep --codeql auto
repobeacon scan . --secrets-history all
repobeacon scan . --image registry.example.com/team/app:release
repobeacon scan . --baseline ./previous/findings.json --fail-on high --new-only
repobeacon scan . --offline --ai off
repobeacon scan . --ai local
repobeacon scan . --ai cloud --ai-policy ./approved-ai-policy.yaml
repobeacon scan . --sbom cyclonedx --license-policy ./license-policy.yaml
repobeacon scan https://github.com/example/project.git --ref release-v1
```

The last command is a later-phase feature. Resolve remote refs to immutable commits; record image digests when tags are supplied. Authentication uses credential helpers or an approved secret store, never credentials embedded in command-line URLs.

**Profile semantics:** `standard` uses the default open-source stack. `deep` additionally attempts eligible CodeQL analysis and configured advanced checks. `auto` never overrides licensing, build trust, or network policy. `--offline` requires pre-provisioned rules and databases, blocks network activity, and disallows cloud AI.

**Proposed exit codes:** `0` = required coverage completed and policy passed; `1` = completed assessment failed finding policy; `2` = assessment incomplete or execution/configuration failure. Exit `2` takes precedence when both findings and coverage failures exist. Reports retain separate `execution_status` and `policy_status` fields so automation can distinguish causes. Optional skipped checks remain visible even when exit code is `0`.

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

## 13. Suggested technology stack

| Area | Proposed choice | Rationale |
| --- | --- | --- |
| Orchestrator | Go | Native executables, process control, concurrency, straightforward cross-platform packaging |
| CLI | Cobra | Structured commands, flags, help, and completion |
| Configuration | Strictly validated YAML plus JSON Schema for exchanged data | Human-readable policy with explicit versioning and rejected unknown settings |
| Scanner integration | External binaries using JSON/SARIF | Preserves tool independence and avoids binding the application to scanner internals |
| Storage | JSON and filesystem artifacts for MVP; SQLite later | Simple inspectable outputs first, efficient history when needed |
| Rendering | Go HTML/text templates with embedded assets | Deterministic offline reports with automatic HTML escaping |
| AI | Provider-neutral HTTP interface with typed responses | Local and cloud options without coupling detection to a model vendor |
| Packaging | Signed release archives/installers and pinned tool manifest | Reproducible provisioning and explicit integrity checks |
| CI and tests | Go tests, adapter fixtures, Windows/Linux/macOS matrix | Verify platform behavior and native-output compatibility |

A Python implementation is viable for a prototype, especially for a Python-heavy team. Go is the recommended production orchestrator; individual scanners retain their own runtime prerequisites. A single orchestrator executable does not imply that every scanner and toolchain fits inside it.

## 14. Proposed repository structure

```text
repobeacon/
  cmd/repobeacon/         CLI entry point
  internal/
    cli/                 Commands and user-facing output
    config/              Policy loading and precedence
    discovery/           Repository and input inventory
    planner/             Capability matching and preflight
    runner/              Scheduling, isolation, cancellation
    tools/               Approved versions and provisioning
    adapters/
      semgrep/
      gitleaks/
      trivy/
      codeql/
    model/               Canonical assessment and findings
    normalize/           Native-to-canonical mappings
    correlate/           Fingerprints and duplicate handling
    policy/              Thresholds, baselines, exceptions
    ai/                  Redaction, providers, validation
    report/              Renderers and templates
    storage/             Artifacts and later scan history
  schemas/               Versioned JSON schemas
  policies/              Example profiles and policy files
  rules/                 Approved rule manifests and licenses
  testdata/              Synthetic repositories and scanner fixtures
  tests/integration/     Cross-platform end-to-end cases
  docs/                  Architecture, adapters, threat model
  packaging/             Release and offline-bundle definitions
  .github/workflows/     Build and release checks
  go.mod
  README.md
  SECURITY.md
```

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

## 17. Security and operational considerations

**Untrusted repository execution.** Discovery and default scanning must not run installation hooks, tests, build scripts, Docker builds, or template plugins. Approved builds run in ephemeral workers with read-only inputs where possible, bounded writable storage, minimal environment variables, and restricted network access. Protect against symlink escapes, path traversal, oversized archives, and resource exhaustion.

**Trusted configuration.** A target repository cannot supply a new scanner executable, enable cloud AI, choose an exfiltration endpoint, or disable enforced checks. Ignore or explicitly reconcile scanner-native configuration and inline suppressions according to trusted policy; report effective exclusions. Exceptions require an owner, rationale, scope, expiry, and audit trail.

**Scanner supply chain.** Pin and verify scanner binaries, images, query packs, and rules against approved manifests. Prefer upstream signatures or attestations when available and an independently trusted checksum source otherwise. Qualify updates before promotion; support revocation of a compromised release. Separate dependency-update permissions from scan execution permissions.

**Credential and evidence handling.** Use minimal repository and registry credentials, pass them through approved mechanisms, and redact process output. Never inherit all developer or CI secrets into workers. Enable scanner redaction at the source and apply a second redaction boundary before persistence. Store sensitive artifacts under restrictive permissions with retention and deletion policies. A suspected exposed secret requires rotation/revocation guidance, not just deletion from source.

**Container and Kubernetes access.** Prefer image archives or registry retrieval without mounting a host Docker socket. Scanning an image must not run its entrypoint. Future live-cluster scanning uses explicit context selection, scoped read-only RBAC, and a separate authorization path; never silently use the current kubeconfig context.

**Network and privacy.** Inventory tool telemetry, rule downloads, database updates, registry pulls, advisory lookups, and AI requests. Disable telemetry by default. Record allowed destinations and database freshness; an offline run cannot silently fall back to cloud services. Treat exported reports as sensitive engineering information.

**Output safety.** Escape all repository and scanner text in HTML, sanitize terminal control sequences, restrict link protocols, and avoid external report assets. Parse scanner outputs with limits and schema checks. Raw results are untrusted input even when produced by an approved scanner.

**Policy reliability.** Preserve unknown severity and reachability. Do not automatically lower priority merely because no exploitability evidence is available. Keep technical severity separate from operational priority. Report both security-policy failure and incomplete execution, and prevent an optional AI response from affecting release decisions.

## 18. Guidance for AI-assisted implementation

Build the product in small, verifiable slices. First define the canonical schema, adapter contract, execution-status model, and golden report fixtures. Next implement discovery and one scanner adapter end to end, including malformed output and timeout handling. Add subsequent scanners only after the first pipeline produces reproducible reports.

Use AI coding assistance to scaffold adapters, generate synthetic fixtures, draft documentation, and propose report copy. Require review for process execution, network access, redaction, fingerprints, policy precedence, and licensing assumptions. Never include real credentials or private customer repositories in test fixtures.

The first reviewable milestone is a local command that produces a traceable finding, a visible coverage result, and matching executive/technical output. The MVP is complete when the acceptance criteria in this document pass across the certified platform matrix, including failure and privacy tests.
