# Scanner evaluation and CodeQL policy

Extracted from the [RepoBeacon project description](project-description.md), version 1.0. This document specifies proposed behavior; implementation is pending.

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
