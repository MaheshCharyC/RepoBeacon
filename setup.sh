#!/bin/bash
# Run with: bash setup.sh
set -euo pipefail

trap 'printf "\nSetup stopped. Fix the error above, then run bash setup.sh again.\n" >&2' ERR

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
setup_os="$(uname -s)"
case "$setup_os" in
    MINGW*|MSYS*|CYGWIN*)
        echo "Windows shell detected; continuing with the PowerShell installer."
        powershell_bin="$(command -v pwsh.exe || command -v powershell.exe)"
        exec "$powershell_bin" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$(cygpath -w "$repo_dir/setup.ps1")"
        ;;
    Darwin|Linux) ;;
    *) echo "Unsupported OS: $setup_os. Setup supports macOS, Linux, and Windows."; exit 1 ;;
esac
if [[ "$EUID" -eq 0 ]]; then
    echo "Run bash setup.sh as your normal user, without sudo. Installers request permission when needed."
    exit 1
fi

cd "$repo_dir"

echo "RepoBeacon setup: detected $setup_os, running in Bash $BASH_VERSION."
echo "Keep this terminal open. First-time downloads may take a while and need several GB of disk space."

echo "[1/5] Checking OS prerequisites..."
case "$(uname -m)" in
    x86_64|amd64|arm64|aarch64) ;;
    *) echo "The complete scanner stack requires a supported 64-bit Intel or ARM system."; exit 1 ;;
esac
if [[ "$setup_os" == "Linux" ]]; then
    if ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
        echo "CodeQL requires glibc Linux. Alpine/musl systems are not supported by this setup."
        exit 1
    fi
elif ! xcode-select -p >/dev/null 2>&1; then
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
        elif [[ -x /home/linuxbrew/.linuxbrew/bin/brew ]]; then
            echo /home/linuxbrew/.linuxbrew/bin/brew
        elif [[ -x "$HOME/.linuxbrew/bin/brew" ]]; then
            echo "$HOME/.linuxbrew/bin/brew"
        else
            return 1
        fi
    }
}
if ! brew_bin="$(find_brew)"; then
    if [[ "$setup_os" == "Linux" ]]; then
        echo "Installing Homebrew's Linux prerequisites using the detected package manager..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y build-essential procps curl file git ca-certificates
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y gcc gcc-c++ make procps-ng curl file git ca-certificates
        else
            echo "No supported system package manager found (apt-get or dnf). Install Homebrew manually, then rerun bash setup.sh."
            exit 1
        fi
    fi
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
if [[ "$setup_os" == "Darwin" ]] && [[ "$(uname -m)" == "arm64" || "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" == "1" ]]; then
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
