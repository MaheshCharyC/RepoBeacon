# Implementation design

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

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
