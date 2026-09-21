# CodeQL setup and automatic scanning

Run `repobeacon scan .` to include CodeQL alongside Semgrep, Gitleaks, and Trivy. Use `repobeacon scan . --scanners codeql` for CodeQL alone. The previous `--profile deep` and `--codeql-authorized` flags remain accepted for compatibility; neither is required to enable CodeQL now. Installing and using CodeQL remains subject to [GitHub's applicable terms](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli).

## Installation and verification

For the one-command macOS setup, run `bash setup.sh` from the RepoBeacon checkout. It installs the OS prerequisites below, prepares Python, then runs `repobeacon setup` to install missing scanners, update CodeQL, and verify all four tools before your first scan. Existing Python installations can run `repobeacon setup` directly after installing the package.

Before reading the source snapshot, each CodeQL-enabled scan verifies the existing CLI version, installed language extractors, and corresponding query packs. It checks the latest stable CLI release from `github/codeql-cli-binaries`, then selects its matching platform bundle from `github/codeql-action`. Prereleases and arbitrary download URLs are rejected. The full bundle contains compatible precompiled queries as well as the CLI.

A working installation at the latest version is reused. Missing, broken, incomplete, or older installations trigger a bundle download. The download's size and SHA-256 must match official GitHub release metadata before extraction. A staged installation must pass verification before it becomes active. Failed updates preserve the previous active installation. Old managed bundles are retained so an in-progress scan is not disrupted; no external installation is overwritten.

Managed bundles live under `~/.cache/repobeacon/codeql/`; an atomic `active.json` pointer selects the verified bundle. RepoBeacon discovers it automatically, without editing shell configuration. `repobeacon doctor` checks it locally, including extractors and packs.

`--no-install-tools` disables downloads and latest-release checks, but still verifies the installed CLI and query packs. Without that flag, network failures or unavailable releases are recorded as CodeQL errors rather than silently claiming an older installation is current. Other scanners continue and reports indicate incomplete coverage with exit code 2. Tool setup errors for the Homebrew-managed scanners can still stop startup before reports are generated. `--no-update` controls Trivy data only; it does not disable CodeQL updates.

Official bundles are selected for macOS (Intel and Apple Silicon), Linux x64/ARM64, and Windows x64. macOS Apple Silicon requires Xcode command-line tools and Rosetta 2; `setup.sh` checks these and starts the installers when needed. The Python `setup` and `scan` commands do not install OS prerequisites themselves. Linux requires glibc. Safe archive extraction requires a patched Python with `tarfile.data_filter` (included in current Python 3.10+ patch releases). See [GitHub's installation documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli).

## Language detection

Detection uses source-file extensions and `.github/workflows/*.yml` / `*.yaml` paths in the filtered local snapshot. No GitHub repository connection is needed. Related languages share one database, and each database runs its family's `security-extended` suite.

| Detected source | CodeQL family | Extraction |
| --- | --- | --- |
| Python | `python` | `none` |
| JavaScript, TypeScript | `javascript` | `none` |
| Ruby | `ruby` | `none` |
| C, C++ | `cpp` | `none` |
| C# | `csharp` | `none` |
| Java without Kotlin | `java` | `none` |
| Kotlin, including mixed Java/Kotlin | `java` | `autobuild`, explicit build permission |
| Go | `go` | `autobuild`, explicit build permission |
| Swift | `swift` | `autobuild`, explicit build permission; macOS toolchain |
| Rust | `rust` | `none`, but build scripts/macros may execute; explicit build permission |
| GitHub Actions workflows | `actions` | `none` |

For a trusted repository requiring build execution:

```sh
repobeacon scan ./trusted-project --codeql-allow-builds --timeout 1800
```

Toolchains and project dependencies must be available to the scanner's filtered environment. The snapshot is not an OS sandbox. Build scripts can access the host and network. Rust requires cargo/rustup even with build mode `none`. See [GitHub's language-specific build requirements](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages).

Unavailable extractors, missing build permission, failed builds, and query failures remain visible as incomplete analysis. Detected languages not mapped to CodeQL are listed in `coverage.languages_without_codeql_support`; a source-only project with no supported language records an unsupported CodeQL run. A directory with no detected code or workflows records CodeQL as not applicable.

Databases and native SARIF are temporary. Normalized findings, scanner versions, language families, and build modes are retained in the reports. Upgrading CodeQL changes baseline comparability. There is no continuous background updater: latest-version checks happen during setup and when a scan selects CodeQL.
