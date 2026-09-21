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

## Get started

You need an internet connection, several GB of free disk space, and permission to install software. Setup checks your operating system, prepares a private Python environment, installs missing tools, updates CodeQL, and verifies all four scanners. Installers may ask for your password or show prompts; follow them to continue.

First, [download RepoBeacon](https://github.com/MaheshCharyC/RepoBeacon/archive/refs/heads/main.zip) and unzip it. Open a terminal in the unzipped RepoBeacon folder:

- **Windows:** open the folder in File Explorer, click the address bar, type `powershell` or `cmd`, and press Enter.
- **macOS:** open Terminal, type `cd ` with a space after it, drag the RepoBeacon folder into Terminal, and press Return.
- **Linux:** right-click the folder and choose **Open in Terminal**, or use `cd /path/to/RepoBeacon`.

### 1. Set up with one command

Run the command for your terminal from the RepoBeacon folder.

**Windows — PowerShell or Command Prompt (CMD):**

```powershell
.\setup.cmd
```

**macOS (zsh or Bash), Linux, or WSL 2:**

```sh
bash setup.sh
```

**Git Bash on Windows:** use `bash setup.sh`; it automatically launches the Windows installer.

On Windows, `setup.cmd` chooses PowerShell 7 when installed, otherwise Windows PowerShell 5.1, then runs `setup.ps1`. You can also invoke it directly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1
```

The execution-policy option applies only to this process; setup does not change your machine's policy. Organization policies can still require IT assistance.

**What setup handles:**

| System | Installation method |
| --- | --- |
| Windows x64 (Windows 10 1809+ / Windows 11) | Installs WinGet if missing, finds or installs 64-bit Python, installs Semgrep inside `.venv`, and installs Gitleaks and Trivy with WinGet. |
| macOS | Checks Apple command-line tools and Rosetta where needed; uses Homebrew for Python and missing scanners. |
| Linux / WSL 2 | Checks for glibc; detects `apt-get` or `dnf` for Homebrew prerequisites when needed, then uses Homebrew for Python and missing scanners. |

All paths install RepoBeacon into `.venv`, install or update the official CodeQL bundle, and verify the tools. Windows PATH changes are picked up during setup without reopening the terminal.

Wait for **“Setup complete. All four scanners are ready.”** First-time downloads can take a while. You can rerun the same command after a failed setup; working tools and environments are reused. An old or broken environment is backed up before replacement.

Supported Unix systems must meet [Homebrew's macOS requirements](https://docs.brew.sh/Installation#macos-requirements) or [Linux requirements](https://docs.brew.sh/Homebrew-on-Linux#requirements). Run setup as your normal user, without `sudo`; installers request it as needed. Other Linux package managers require Homebrew to be installed first. Alpine/musl Linux, Windows ARM64, and 32-bit systems are not supported by the complete setup.

### 2. Scan your project

**Windows — PowerShell or CMD:**

```powershell
.\.venv\Scripts\repobeacon.exe scan "C:\path\to\your-project"
```

**macOS, Linux, or WSL 2:**

```sh
.venv/bin/repobeacon scan "/path/to/your-project"
```

**Git Bash on Windows:**

```sh
./.venv/Scripts/repobeacon.exe scan "C:/path/to/your-project"
```

Replace the quoted path with the folder you want to check. Keep the quotes if the path contains spaces. For example, a Mac project might be `"$HOME/Projects/MyApp"`, and a Windows project might be `"C:\Users\YourName\Projects\MyApp"`.

RepoBeacon detects the code languages automatically. It checks for missing scanners and CodeQL updates before scanning. The first scan may also download vulnerability data.

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

Open Terminal in the RepoBeacon folder again and run the scan command from step 2. Setup persists after restarting your computer. You do **not** need to activate the Python environment or run setup before every scan.

To check installations without running a scan:

| System | Command |
| --- | --- |
| Windows | `.\.venv\Scripts\repobeacon.exe doctor` |
| macOS / Linux | `.venv/bin/repobeacon doctor` |

CodeQL is stored in `~/.cache/repobeacon/codeql/` (`%USERPROFILE%\.cache\repobeacon\codeql\` on Windows), outside the Python environment. Use `doctor` to check it; a standalone `codeql` command may not be on your Terminal's search path.

## A few useful options

The examples below use macOS/Linux paths. On Windows, replace `.venv/bin/repobeacon` with `.\.venv\Scripts\repobeacon.exe` and use your Windows project path.

| What you want to do | Command (run from the RepoBeacon folder) |
| --- | --- |
| Scan RepoBeacon itself | `.venv/bin/repobeacon scan .` |
| Save results to a chosen new folder | `.venv/bin/repobeacon scan "/path/to/project" --output "reports/my-scan"` |
| Skip opening the browser | `.venv/bin/repobeacon scan "/path/to/project" --no-open` |
| Skip scanner installation and CodeQL update checks | `.venv/bin/repobeacon scan "/path/to/project" --no-install-tools` |
| See all options | `.venv/bin/repobeacon scan --help` |

**Swift, Go, Kotlin, and Rust:** CodeQL analysis for these languages can execute project build code. For a project you trust, add `--codeql-allow-builds` to the scan command. Its language tools and dependencies must also be installed (for example, full Xcode for an iOS project). Setup installs the scanners; it does not install every project's build tools. See [language requirements](docs/codeql.md#language-detection).

For manual installation and additional options, see the [detailed installation guide](docs/usage.md#requirements-and-installation).

## If something goes wrong

- **Setup stopped:** read the error above it, finish any installer prompts, then rerun your setup command from step 1.
- **The scan command is not found:** make sure your terminal is in the RepoBeacon folder, setup has completed, and you are using the command for your terminal from step 2.
- **The browser didn't open:** double-click `index.html` at the report path printed in Terminal.
- **The scan reports an error:** open the report and check the scanner status. Run the `doctor` command for your system from "Next time you use it" above. Rerun setup for missing tools or CodeQL repairs; if another installed scanner fails verification, reinstall it using its package manager. In Windows PowerShell or CMD, reinstall Semgrep with `.\.venv\Scripts\python.exe -m pip install --force-reinstall semgrep`.
- **A command finishes with a nonzero exit code:** `1` means the scan completed and found issues that fail the severity threshold; `2` means the scan was incomplete or couldn't start. Both need attention.

## Coverage and more information

RepoBeacon is an early version (0.1.0). Findings need human review, and a clean report does not guarantee a secure project. The bundled Semgrep checks are a small starter set for Python, JavaScript, and TypeScript. CodeQL supports additional languages; available checks depend on your project's languages and tools. Scans examine current files, not Git history.

CodeQL use is subject to [GitHub's CodeQL terms](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli). RepoBeacon has not yet selected an open-source license; each scanner also has its own terms.

- [Detailed usage and advanced options](docs/usage.md)
- [CodeQL setup and supported languages](docs/codeql.md)
- [Full documentation and roadmap](docs/README.md)
- [Contributing](CONTRIBUTING.md) and [reporting a security issue](SECURITY.md)
