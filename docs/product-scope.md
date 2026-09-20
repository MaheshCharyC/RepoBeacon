# Product scope and naming

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

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
