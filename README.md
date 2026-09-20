# RepoBeacon

One command. Unified application security insight.

RepoBeacon is an application security CLI that coordinates established scanners and produces unified executive and engineering reports. It integrates Semgrep, Gitleaks, Trivy, and CodeQL for SAST, secrets, dependencies, infrastructure configuration, and container images.

## Project status

Version 0.1.0 is a working Python implementation with no runtime Python dependencies. It creates an isolated source snapshot, runs external scanner binaries, normalizes findings, applies thresholds and baselines, and writes HTML, Markdown, JSON, and SARIF. AI enrichment is optional through a documented HTTP protocol.

Start with the [runnable usage guide](docs/usage.md). The original design documents describe the broader roadmap and include features not yet implemented. The bundled SAST rules are a small starter pack, not comprehensive language coverage.

The default stack is Semgrep Community Edition, Gitleaks, Trivy, and GitHub CodeQL. CodeQL usage remains subject to GitHub's terms. Final versions and rulesets must pass the qualification process described in the documentation.

## Documentation

Start with the [complete project description](docs/project-description.md) or the [documentation index](docs/README.md).

- [Product scope and naming](docs/product-scope.md)
- [Scanner evaluation and CodeQL policy](docs/scanner-evaluation.md)
- [CLI specification](docs/cli-specification.md)
- [Architecture and scan workflow](docs/architecture.md)
- [Finding schema and correlation](docs/finding-schema.md)
- [Reports and AI enrichment](docs/reporting-and-ai.md)
- [Technology stack and repository layout](docs/implementation-design.md)
- [MVP and acceptance criteria](docs/mvp.md)
- [Phased roadmap](docs/roadmap.md)
- [Threat model and security controls](docs/security-design.md)
- [AI-assisted implementation guidance](docs/ai-development.md)

## Quick start

```text
python -m pip install -e .
repobeacon scan .
repobeacon doctor
```

`repobeacon scan` includes CodeQL by default, verifies its CLI, extractors, and query packs, and checks GitHub for the latest stable bundle on every run. Missing, broken, or older installations are replaced by a verified bundle in RepoBeacon's user cache. Languages are detected automatically. See [CodeQL setup and language support](docs/codeql.md).

On macOS, missing Semgrep, Gitleaks, and Trivy packages are installed through Homebrew. Use `--no-install-tools` to disable installation and CodeQL update checks, or `--scanners semgrep,gitleaks,trivy` to exclude CodeQL. Languages whose CodeQL extraction executes build code require `--codeql-allow-builds` for trusted targets. From a checkout, `python -m repobeacon scan .` also works without installing this package. Missing or failed selected scanners produce exit code 2, never a clean result.

Run the automated tests with `python -m unittest discover -s tests -v`.

## Development

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for the proposed implementation sequence and validation expectations. See [SECURITY.md](SECURITY.md) for security reporting guidance.

No open-source license has been selected for this repository. Scanner engines, rule packs, databases, and their distribution terms require separate review.
