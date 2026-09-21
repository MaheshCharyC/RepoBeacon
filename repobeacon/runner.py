import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


class ScannerError(Exception):
    pass


AUTO_INSTALLABLE_SCANNERS = ("semgrep", "gitleaks", "trivy")


def environment(home):
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP"}
    values = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    values.update({"HOME": str(home), "USERPROFILE": str(home), "XDG_CONFIG_HOME": str(home), "NO_COLOR": "1", "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
    return values


def executable(name):
    if name == "codeql":
        from .codeql import managed_executable
        managed = managed_executable()
        if managed:
            return managed
    sibling = Path(sys.executable).parent / (name + ".exe" if os.name == "nt" else name)
    found = shutil.which(str(sibling)) or shutil.which(name)
    if found:
        return found
    directories = [Path("/opt/homebrew/bin"), Path("/usr/local/bin"), Path("/home/linuxbrew/.linuxbrew/bin"), Path.home() / ".linuxbrew/bin"] if sys.platform in {"darwin", "linux"} else []
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        directories.append(Path(os.environ["LOCALAPPDATA"]) / "Microsoft/WinGet/Links")
    for directory in directories:
        candidate = directory / (name + ".exe" if sys.platform == "win32" else name)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def homebrew_executable():
    found = shutil.which("brew")
    if found:
        return found
    for candidate in (Path("/opt/homebrew/bin/brew"), Path("/usr/local/bin/brew"), Path("/home/linuxbrew/.linuxbrew/bin/brew"), Path.home() / ".linuxbrew/bin/brew"):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def install_missing_scanners(names):
    requested = [name for name in AUTO_INSTALLABLE_SCANNERS if name in names]
    missing = [name for name in requested if executable(name) is None]
    if not missing:
        return []
    if sys.platform == "win32":
        install_windows_scanners(missing)
        return missing
    if sys.platform not in {"darwin", "linux"}:
        raise ScannerError(
            "Missing scanners: " + ", ".join(missing) + ". Automatic installation supports macOS/Linux with Homebrew and Windows with WinGet."
        )
    brew = homebrew_executable()
    if brew is None:
        raise ScannerError(
            "Missing scanners: " + ", ".join(missing) + ". Run bash setup.sh to prepare Homebrew, or use --no-install-tools to run without automatic installation."
        )
    print("Installing missing scanners with Homebrew: " + ", ".join(missing))
    try:
        result = subprocess.run([brew, "install", *missing], check=False)
    except OSError as error:
        raise ScannerError("Homebrew could not be started to install missing scanners.") from error
    if result.returncode != 0:
        raise ScannerError(f"Homebrew could not install the missing scanners (exit status {result.returncode}).")
    unresolved = [name for name in missing if executable(name) is None]
    if unresolved:
        raise ScannerError("Homebrew completed, but these scanners are still unavailable: " + ", ".join(unresolved) + ". Check your PATH and Homebrew installation.")
    return missing


def refresh_windows_path():
    # Newly installed WinGet applications must work in this process, without a restart.
    import winreg
    paths = [os.environ.get("PATH", "")]
    for hive, key in ((winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"), (winreg.HKEY_CURRENT_USER, "Environment")):
        try:
            with winreg.OpenKey(hive, key) as entry:
                paths.append(os.path.expandvars(winreg.QueryValueEx(entry, "Path")[0]))
        except OSError:
            pass
    os.environ["PATH"] = os.pathsep.join(paths)


def install_windows_scanners(missing):
    if "semgrep" in missing and sys.prefix == sys.base_prefix:
        raise ScannerError("Run setup.cmd first: Semgrep must be installed inside RepoBeacon's private Python environment.")
    winget = shutil.which("winget")
    if any(name in missing for name in ("gitleaks", "trivy")) and not winget:
        raise ScannerError("WinGet is missing. Run setup.cmd to install Windows prerequisites.")
    commands = []
    if "semgrep" in missing:
        commands.append(("Semgrep", [sys.executable, "-m", "pip", "install", "semgrep"]))
    for name, package in (("gitleaks", "Gitleaks.Gitleaks"), ("trivy", "AquaSecurity.Trivy")):
        if name in missing:
            commands.append((name, [winget, "install", "--id", package, "--exact", "--source", "winget", "--scope", "user", "--accept-source-agreements", "--accept-package-agreements"]))
    for name, command in commands:
        print(f"Installing {name} on Windows...", flush=True)
        try:
            result = subprocess.run(command, check=False)
        except OSError as error:
            raise ScannerError(f"Could not start the {name} installer.") from error
        if result.returncode != 0:
            raise ScannerError(f"Could not install {name} (exit status {result.returncode}). Review the installer output above and rerun setup.cmd.")
    refresh_windows_path()
    unresolved = [name for name in missing if executable(name) is None]
    if unresolved:
        raise ScannerError("Installation finished but these scanners are unavailable: " + ", ".join(unresolved) + ". Check the installer output and rerun setup.cmd.")


def terminate(process):
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10, check=False)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=10)


def execute(arguments, cwd, home, timeout, accepted=(0,), output_limit=32 * 1024 * 1024):
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        options = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        process = subprocess.Popen(arguments, cwd=cwd, env=environment(home), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, **options)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if time.monotonic() > deadline:
                    raise ScannerError("Scanner exceeded its time limit.")
                if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > output_limit:
                    raise ScannerError("Scanner exceeded its output limit.")
                time.sleep(0.05)
        except BaseException:
            terminate(process)
            raise
        if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > output_limit:
            raise ScannerError("Scanner exceeded its output limit.")
        if process.returncode not in accepted:
            raise ScannerError(f"Scanner exited with status {process.returncode}; raw output withheld to protect secrets. Check installation, cache, and supported CLI version.")
        stdout.seek(0)
        return stdout.read(output_limit).decode("utf-8", errors="replace")


def read_json(path):
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ScannerError("Scanner report exceeds 32 MiB.")
    return json.loads(path.read_text(encoding="utf-8"))


def tool_version(name, binary, home):
    arguments = [binary, "version"] if name in {"gitleaks", "codeql"} else [binary, "--version"]
    return execute(arguments, home, home, 15).strip().splitlines()[0][:150]
