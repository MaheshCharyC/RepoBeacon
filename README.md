# RepoBeacon

**Check a project for security issues and get one easy-to-read report.**

RepoBeacon runs four security tools on a project folder on your computer. It brings their results together so you can see what needs attention, where the issue is, and suggested ways to fix it.

| What it looks for | Tool |
| --- | --- |
| Risky code patterns | Semgrep |
| Accidentally saved passwords, API keys, and other secrets | Gitleaks |
| Known vulnerabilities in dependencies and insecure configuration | Trivy |
| Code vulnerabilities using deeper analysis | CodeQL |

You don't need to start a server or upload your project to use the default scan. Internet access is needed to download tools, updates, and vulnerability data. AI features are off by default.

## Get started on a Mac

You need a Mac [supported by Homebrew](https://docs.brew.sh/Installation#macos-requirements), an internet connection, several GB of free disk space, and permission to install software. Setup installs missing prerequisites for you. Apple and Homebrew installers may ask for your Mac password or show prompts; follow those prompts to continue.

First, [download RepoBeacon](https://github.com/MaheshCharyC/RepoBeacon/archive/refs/heads/main.zip) and unzip it. Open **Terminal** (press **Command + Space**, type **Terminal**, then press Return). Type `cd ` with a space after it, drag the unzipped RepoBeacon folder into Terminal, and press Return. This tells Terminal which folder to work in.

### 1. Set up

Copy this command into Terminal and press Return:

```sh
bash setup.sh
```

This single command:

- Checks Apple command-line tools and starts their installer if needed.
- Installs Homebrew and Python if missing, plus Rosetta 2 on Apple Silicon when needed by CodeQL.
- Creates a private Python environment (`.venv`) and installs RepoBeacon inside it.
- Installs missing Semgrep, Gitleaks, and Trivy, gets the latest stable CodeQL bundle, and verifies all four tools.

Wait for **“Setup complete. All four scanners are ready.”** First-time setup can take a while, especially the CodeQL download. You can rerun the same command after a failed setup; installed tools and a working environment are reused. An old or broken environment is backed up before replacement.

### 2. Scan your project

```sh
.venv/bin/repobeacon scan "/path/to/your-project"
```

Replace `/path/to/your-project` with the folder you want to check. Keep the quotes if the path contains spaces. For example:

```sh
.venv/bin/repobeacon scan "$HOME/Projects/MyApp"
```

Tip: you can type `.venv/bin/repobeacon scan ` and drag your project folder into Terminal, then press Return.

RepoBeacon detects the code languages automatically. It checks for missing scanners and CodeQL updates before scanning, so the tools stay ready. The first scan may also need to download vulnerability data.

**Your report opens automatically in your default browser when the scan finishes.**

## Where to find your results

Terminal prints the full report path. Reports are saved in the folder where you ran the scan:

```text
security-report/
  <date-and-time>/
    index.html
```

If you ran the command from the RepoBeacon folder, look inside that folder's **security-report** directory. Open the newest dated folder and double-click **index.html** to view it again. Each scan gets its own folder, so previous reports are kept.

The report includes a visual summary, severity colors, scanner status, and expandable issue details with file locations and suggested fixes. Start with **Critical** and **High** findings. Check the scanner status too: **incomplete** means some checks could not run, even if no issues were found.

You also get a short written summary (`executive-summary.md`), a detailed report (`technical-report.md`), and files for other tools (`findings.json`, `findings.sarif`, `coverage.json`, and `scan-manifest.json`). Keep the whole report folder when sharing it; review it first because it contains project paths and security findings.

## Next time you use it

Open Terminal in the RepoBeacon folder again and run the scan command from step 2. Setup persists after restarting your Mac. You do **not** need to activate the Python environment or run setup before every scan.

To check installations without running a scan:

```sh
.venv/bin/repobeacon doctor
```

CodeQL is stored in `~/.cache/repobeacon/codeql/`, outside the Python environment. Use `doctor` to check it; a standalone `codeql` command may not be on your Terminal's search path.

## A few useful options

| What you want to do | Command (run from the RepoBeacon folder) |
| --- | --- |
| Scan RepoBeacon itself | `.venv/bin/repobeacon scan .` |
| Save results to a chosen new folder | `.venv/bin/repobeacon scan "/path/to/project" --output "reports/my-scan"` |
| Skip opening the browser | `.venv/bin/repobeacon scan "/path/to/project" --no-open` |
| Skip scanner installation and CodeQL update checks | `.venv/bin/repobeacon scan "/path/to/project" --no-install-tools` |
| See all options | `.venv/bin/repobeacon scan --help` |

**Swift, Go, Kotlin, and Rust:** CodeQL analysis for these languages can execute project build code. For a project you trust, add `--codeql-allow-builds` to the scan command. Its language tools and dependencies must also be installed (for example, full Xcode for an iOS project). Setup installs the scanners; it does not install every project's build tools. See [language requirements](docs/codeql.md#language-detection).

**Linux or Windows:** the one-command setup script currently supports macOS. Use the [manual installation guide](docs/usage.md#requirements-and-installation) on other systems.

## If something goes wrong

- **Setup stopped:** read the error above it, finish any Apple installer prompts, then run `bash setup.sh` again.
- **“No such file or directory” for `.venv/bin/repobeacon`:** make sure Terminal is in the RepoBeacon folder and setup has completed.
- **The browser didn't open:** double-click `index.html` at the report path printed in Terminal.
- **The scan reports an error:** open the report and check the scanner status. Run `.venv/bin/repobeacon doctor` to check the tools. Rerun setup for missing tools or CodeQL repairs; if another installed scanner fails verification, reinstall that tool with Homebrew.
- **A command finishes with a nonzero exit code:** `1` means the scan completed and found issues that fail the severity threshold; `2` means the scan was incomplete or couldn't start. Both need attention.

## Coverage and more information

RepoBeacon is an early version (0.1.0). Findings need human review, and a clean report does not guarantee a secure project. The bundled Semgrep checks are a small starter set for Python, JavaScript, and TypeScript. CodeQL supports additional languages; available checks depend on your project's languages and tools. Scans examine current files, not Git history.

CodeQL use is subject to [GitHub's CodeQL terms](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli). RepoBeacon has not yet selected an open-source license; each scanner also has its own terms.

- [Detailed usage and advanced options](docs/usage.md)
- [CodeQL setup and supported languages](docs/codeql.md)
- [Full documentation and roadmap](docs/README.md)
- [Contributing](CONTRIBUTING.md) and [reporting a security issue](SECURITY.md)
