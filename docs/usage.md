# RepoBeacon 0.1.0 — usage and implementation status

This guide describes executable behavior. The project description and its extracted documents describe the larger product roadmap.

## Requirements and installation

Use Python 3.10 or newer, with current patch updates, on Windows, Linux, or macOS. The orchestrator uses the Python standard library. Scans include CodeQL by default: before scanning, RepoBeacon verifies the CLI, language extractors, and query packs and checks GitHub's latest stable release. It installs or repairs the complete official bundle when needed. See [CodeQL installation and language detection](codeql.md) for cache location, build requirements, platform prerequisites, and applicable terms.

On macOS, each scan also uses Homebrew to install missing selected Semgrep, Gitleaks, and Trivy packages. Install those scanners separately on other platforms. `--no-install-tools` disables installation and CodeQL update checks; installed CodeQL is still verified locally. `doctor` only verifies local installations and never installs or updates them.

```text
python -m venv .venv
```

Activate the environment with `.venv\Scripts\Activate.ps1` on Windows PowerShell or `source .venv/bin/activate` on macOS/Linux, then:

```text
python -m pip install -e .
repobeacon scan .
repobeacon doctor
```

On macOS, make sure Homebrew is available on `PATH`; RepoBeacon runs `brew install` only for selected standard scanners that are missing. Obtain Gitleaks and Trivy from the [official Gitleaks releases](https://github.com/gitleaks/gitleaks/releases) and [official Trivy releases](https://github.com/aquasecurity/trivy/releases) when installing manually. Verify the selected release according to your organization's supply-chain policy. Place their executables on PATH or alongside the Python environment's interpreter. Windows binaries use `.exe`. Scanner discovery prefers executables next to the current Python interpreter, then PATH, and also checks the standard Homebrew binary directories on macOS.

For this development checkout, tools were provisioned in `.tools/venv` without changing global installations. Run `.tools/venv/bin/repobeacon` on this Mac after local package installation. This environment and downloaded binaries are ignored by Git and are not part of the source distribution.

## Run scans

```text
repobeacon scan .
repobeacon scan ./my-project --output ./reports/first-scan
repobeacon scan ./my-project --scanners semgrep,gitleaks
repobeacon scan ./my-project --rules ./trusted-custom-rules.yaml
repobeacon scan ./my-project --image registry.example.com/app:release
repobeacon scan ./my-project --image ./image.tar
repobeacon scan ./my-project --profile deep --codeql-authorized
repobeacon scan ./my-project --scanners codeql
repobeacon scan ./trusted-project --codeql-allow-builds
repobeacon scan ./my-project --no-install-tools
repobeacon scan ./my-project --baseline ./reports/first-scan/findings.json --new-only
repobeacon scan ./my-project --cache ./.cache/trivy --no-update
```

From the repository root, `python -m repobeacon` supports the same arguments without package installation. Run `repobeacon scan --help` for the authoritative flag list.

Each scan creates a new directory. The default is `security-report/<UTC timestamp>`. Explicit output directories must not already exist. Seven files are written: `index.html`, `executive-summary.md`, `technical-report.md`, `findings.json`, `findings.sarif`, `coverage.json`, and `scan-manifest.json`.

Exit codes are `0` for completed checks passing policy, `1` for completed checks failing policy, `2` for incomplete scans or invalid configuration, and `130` for user cancellation. Unknown severity fails the finding gate conservatively. A missing scanner never counts as a successful scan. `--fail-on` defaults to `high`.

## Implemented coverage

| Scanner | Implemented integration | Boundary |
| --- | --- | --- |
| Semgrep | Local JSON scan, bundled rules or an explicit local rules file | Six starter rules: Python eval/exec, shell execution, disabled TLS verification; JavaScript/TypeScript eval and innerHTML. These are potential-risk patterns, not proof of exploitability. |
| Gitleaks | Directory scan with upstream default rules, full scanner redaction, raw secret fields discarded | Working tree only; no credential verification or Git history |
| Trivy | Filesystem vulnerabilities and misconfiguration; explicit image/archive scan | Database access may require network and time; ecosystem support follows installed Trivy |
| CodeQL | Automatically detected Python, JS/TS, Ruby, Java/Kotlin, C/C++, C#, Go, Rust, Swift, and GitHub Actions; security-extended queries per family | Requires installed platform extractors and toolchains; Go/Kotlin/Swift autobuild and Rust extraction require `--codeql-allow-builds` |

Custom Semgrep rules are trusted executable-analysis configuration: review their content and license before supplying them. The CLI does not download registry rules automatically. Source languages without bundled checks are listed in the coverage report. Dockerfile checks and Kubernetes YAML checks use Trivy; no images are built and no manifests are deployed.

Trivy receives an isolated home directory and does not inherit registry credentials from the caller. Public registry images and local image archives are supported; private registry authentication needs a future explicit credential integration. No Docker socket is used for remote image retrieval.

## Snapshot, configuration, and privacy

Scans operate on a temporary copy of regular files. Symlinks, version-control data, common dependency/environment directories, prior default reports, scanner ignore/config files, and files over 10 MiB are excluded and recorded. Snapshots are limited to 100,000 files and 512 MiB. The manifest includes content hashes and a snapshot digest. File edits after copying do not affect analysis of the copy.

Scanner subprocesses receive a filtered environment and temporary home. CodeQL builds require `--codeql-allow-builds`; those builds may execute repository scripts and install dependencies, so use the flag only for trusted targets. Tool provisioning downloads and executes official scanner distributions before analysis. The CLI does not execute images or expose AI tools. Timeouts terminate scanner process groups on Unix and process trees on Windows. Native stdout/stderr is size-limited and withheld on failures. Scanner-generated report files are checked against a 32 MiB parsing limit.

Raw source snippets, matched secrets, and native reports are discarded. Normalized titles and remediation text are sanitized, but automatic redaction is not a guarantee against every possible secret format. Reports contain repository paths, dependency information, and findings and must be handled as sensitive. HTML escapes scanner text and uses a restrictive content security policy.

The snapshot is not a security sandbox. Scanners have the permissions of the CLI process and may access the network. `--no-update` requests cached Trivy analysis; it is deliberately not named `--offline`, because this application does not enforce network isolation. Use an OS/container sandbox for that requirement.

## Baselines and identity

A baseline must have the same target path identity, application version, scanner versions, selected scanner/language/image configuration, and Semgrep rules digest, and its required checks must have completed. An incomparable baseline is labeled; `--new-only` then returns exit code 2. Existing findings remain in reports even when excluded from the new-only gate.

Version 0.1 fingerprints retain scanner identity and line coordinates. They deduplicate repeated identical observations but do not merge different scanners' findings, resolve advisory aliases, or survive all line shifts. Findings absent from a new scan are not automatically declared resolved. Vulnerability databases can change between comparable scans; that is not evidence of a source-code change.

## Optional AI reporting

AI is off by default. Supply an explicitly configured endpoint using the following small provider-neutral protocol; this is not a direct drop-in endpoint for arbitrary model vendor APIs.

```text
repobeacon scan . --ai local --ai-endpoint http://127.0.0.1:8000/report --ai-model my-local-model
repobeacon scan . --ai cloud --ai-endpoint https://approved.example.com/report --ai-model approved-model
```

The CLI sends a JSON POST containing `model`, an instruction, and up to 50 findings with `finding_id`, `category`, `severity`, and sanitized `title`. It does not send source snippets, paths, raw secrets, or complete reports. Cloud mode optionally reads a bearer token from `REPOBEACON_AI_TOKEN`; the token is not passed to scanners. Cloud URLs require HTTPS; local endpoints require a literal loopback address. Redirects and implicit proxy use are disabled.

Expected response:

```json
{
  "summaries": [
    {
      "finding_id": "RB-existing-finding-id",
      "explanation": "Explanation grounded in the supplied finding.",
      "remediation": "Suggested verification and remediation steps."
    }
  ]
}
```

Unknown/duplicate finding IDs, unexpected fields, oversized text, invalid JSON, and oversized responses are rejected. Suggestions are marked unverified, attributed to the model, and cannot alter findings, severity, counts, or exit codes. This validates structure and attribution, not the factual truth of generated prose. AI errors fall back to deterministic reports.

## Development and validation

```text
python -m unittest discover -s tests -v
repobeacon scan testdata/vulnerable --scanners semgrep
```

The synthetic target contains deliberately vulnerable source, an old dependency declaration, and insecure deployment configuration. Never execute or deploy it. Five findings are expected from the bundled Semgrep rules. Findings from database-backed scanners vary by release and database.

The source includes Windows/Linux/macOS CI configuration. A workflow file is not evidence that those hosted jobs have run; platform qualification remains pending until actual results are recorded.

See the [local validation record](validation.md) for actual scanner versions, test outcomes, and unverified integrations.

## Remaining roadmap

Full network/process isolation, signature attestation for tool provisioning, policy files and reviewed suppressions, Git-history scanning, remote repository checkout, richer SAST rules, SBOM/license export, live Kubernetes access, custom CodeQL build commands, database provenance, cross-scanner correlation, and packaged standalone releases remain future work. CodeQL bundle downloads are SHA-256 checked against GitHub release metadata. These limitations do not prevent the implemented local scanner pipeline from running.

Python was selected to deliver a runnable implementation using the available toolchain with no runtime package dependencies. The Go stack in the original proposal is not implemented. Refer to this document when determining current behavior.
