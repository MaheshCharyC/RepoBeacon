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

## Prerequisites

| Requirement | Setup |
| --- | --- |
| Python 3.10 or newer | Use a current patch release. CodeQL archive extraction requires Python's `tarfile.data_filter`. The local setup was validated with Python 3.12.14. |
| Python virtual environment | Install RepoBeacon inside a project `.venv` to keep its packages separate from macOS/Homebrew Python. |
| Homebrew on macOS | Install [Homebrew](https://brew.sh/) and ensure `brew --version` works. RepoBeacon uses it to install missing Semgrep, Gitleaks, and Trivy. |
| CodeQL platform prerequisites | Supported bundle targets are macOS Intel/Apple Silicon, Linux x64/ARM64 with glibc, and Windows x64. Apple Silicon requires Xcode command-line tools and Rosetta 2. See [CodeQL setup](docs/codeql.md). |
| Network access and disk space | Initial setup downloads scanners, CodeQL query packs, and Trivy databases. Allow several GiB for downloads, extracted bundles, caches, and temporary analysis databases. CodeQL checks for updates on each enabled scan. |
| CodeQL usage eligibility | Your use must comply with [GitHub's CodeQL terms](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli). Automatic installation does not grant a license. |

RepoBeacon installs or updates the complete CodeQL bundle automatically and stores it in `~/.cache/repobeacon/codeql/`. It does not install Python, Homebrew, Xcode, Rosetta, or project toolchains. On Linux and Windows, install Semgrep, Gitleaks, and Trivy separately and make them available on `PATH`; see the [installation guide](docs/usage.md#requirements-and-installation).

For trusted projects that need CodeQL build execution, install the appropriate toolchains and dependencies: Go for Go projects, a JDK and project build tools for Kotlin, Xcode/Swift tools for Swift, or cargo/rustup for Rust. These analyses require `--codeql-allow-builds` because they may execute project build code. See the [language support table](docs/codeql.md#language-detection).

## Quick start on macOS

Check Homebrew and Xcode command-line tools:

```sh
brew --version
xcode-select -p
```

If the command-line tools are missing, run `xcode-select --install`. On Apple Silicon, ensure Rosetta 2 is installed as described in the [CodeQL setup guide](docs/codeql.md).

Install Python if needed, then create the environment from the RepoBeacon checkout. Using the Homebrew interpreter explicitly avoids accidentally selecting macOS's older `/usr/bin/python3`:

```sh
brew install python@3.12
cd /path/to/RepoBeacon
"$(brew --prefix python@3.12)/bin/python3.12" -m venv .venv
source .venv/bin/activate
python --version
python -m pip install --upgrade pip
python -m pip install -e .
repobeacon scan .
repobeacon doctor
```

The first scan installs missing scanners before analysis. `repobeacon doctor` only verifies local installations; it does not install them. CodeQL is stored outside `.venv` and is discovered by RepoBeacon even if the standalone `codeql` command is not on your shell's `PATH`.

The environment and installed tools persist across terminal and machine restarts. For each new terminal session, activate the existing environment:

```sh
cd /path/to/RepoBeacon
source .venv/bin/activate
repobeacon scan /path/to/your-project
```

You can also run `.venv/bin/repobeacon scan /path/to/your-project` without activating it. You do not need to recreate `.venv` or reinstall RepoBeacon for each scan.

## Scanner setup and options

`repobeacon scan` includes CodeQL by default, verifies its CLI, extractors, and query packs, and checks GitHub for the latest stable bundle on every run. Missing, broken, or older installations are replaced by a verified bundle in RepoBeacon's user cache. Languages are detected automatically. See [CodeQL setup and language support](docs/codeql.md).

On macOS, missing Semgrep, Gitleaks, and Trivy packages are installed through Homebrew. Use `--no-install-tools` to disable installation and CodeQL update checks, or `--scanners semgrep,gitleaks,trivy` to exclude CodeQL. Languages whose CodeQL extraction executes build code require `--codeql-allow-builds` for trusted targets. From a checkout, `python -m repobeacon scan .` also works without installing this package. Missing or failed selected scanners produce exit code 2, never a clean result.

Run the automated tests with `python -m unittest discover -s tests -v`.

## Development

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for the proposed implementation sequence and validation expectations. See [SECURITY.md](SECURITY.md) for security reporting guidance.

No open-source license has been selected for this repository. Scanner engines, rule packs, databases, and their distribution terms require separate review.
