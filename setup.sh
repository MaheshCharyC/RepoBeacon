#!/bin/bash
# Run with: bash setup.sh
set -euo pipefail

trap 'printf "\nSetup stopped. Fix the error above, then run bash setup.sh again.\n" >&2' ERR

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This setup script supports macOS. For Linux/Windows, see docs/usage.md."
    exit 1
fi
if [[ "$EUID" -eq 0 ]]; then
    echo "Run bash setup.sh as your normal user, without sudo. Installers request permission when needed."
    exit 1
fi

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_dir"

echo "RepoBeacon setup: checking your Mac and installing missing tools."
echo "Keep this terminal open. First-time downloads may take a while and need several GB of disk space."

echo "[1/5] Checking Apple command-line tools..."
if ! xcode-select -p >/dev/null 2>&1; then
    xcode-select --install
    while ! xcode-select -p >/dev/null 2>&1; do
        if [[ ! -t 0 ]]; then
            echo "Finish Apple's Command Line Tools installation, then rerun bash setup.sh."
            exit 1
        fi
        read -r -p "Finish the Apple installer, then press Return to continue (Ctrl+C to cancel). "
    done
fi

echo "[2/5] Checking Homebrew..."
find_brew() {
    command -v brew || {
        if [[ -x /opt/homebrew/bin/brew ]]; then
            echo /opt/homebrew/bin/brew
        elif [[ -x /usr/local/bin/brew ]]; then
            echo /usr/local/bin/brew
        else
            return 1
        fi
    }
}
if ! brew_bin="$(find_brew)"; then
    echo "Installing Homebrew from its official installer. Follow its prompts."
    brew_installer="$(mktemp -t repobeacon-homebrew)"
    trap 'rm -f "$brew_installer"' EXIT
    curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh -o "$brew_installer"
    /bin/bash "$brew_installer"
    brew_bin="$(find_brew)"
fi
brew_prefix="$("$brew_bin" --prefix)"
export PATH="$brew_prefix/bin:$brew_prefix/sbin:$PATH"
"$brew_bin" --version

echo "[3/5] Checking CodeQL platform requirements..."
if [[ "$(uname -m)" == "arm64" || "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" == "1" ]]; then
    if ! arch -x86_64 /usr/bin/true >/dev/null 2>&1; then
        echo "Installing Apple's Rosetta 2 for CodeQL. Follow Apple's license prompt."
        sudo softwareupdate --install-rosetta
        arch -x86_64 /usr/bin/true
    fi
fi

echo "[4/5] Preparing RepoBeacon's private Python environment..."
# A supported interpreter avoids macOS's older system Python and global pip installs.
python_prefix="$("$brew_bin" --prefix python@3.12)"
if [[ ! -x "$python_prefix/bin/python3.12" ]]; then
    "$brew_bin" install python@3.12
fi
python_bin="$python_prefix/bin/python3.12"
if [[ -L .venv ]]; then
    echo "The .venv folder is a symbolic link. Move it aside before running setup."
    exit 1
fi
if [[ -e .venv ]] && ! .venv/bin/python -c 'import sys, tarfile; assert sys.version_info >= (3, 10); assert hasattr(tarfile, "data_filter"); assert sys.prefix != sys.base_prefix' >/dev/null 2>&1; then
    backup_dir="$(mktemp -d "$repo_dir/.venv-backup.XXXXXX")"
    mv .venv "$backup_dir/venv"
    printf 'Saved the old or broken environment to %s/venv\n' "$backup_dir"
fi
if [[ ! -x .venv/bin/python ]]; then
    "$python_bin" -m venv .venv
fi
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .

echo "[5/5] Installing and verifying Semgrep, Gitleaks, Trivy, and CodeQL..."
.venv/bin/python -m repobeacon setup
printf '\nNext, scan a project (replace the quoted path with your project folder):\n'
printf '%q scan "/path/to/your-project"\n' "$repo_dir/.venv/bin/repobeacon"
echo "The report opens in your default browser when the scan finishes."
