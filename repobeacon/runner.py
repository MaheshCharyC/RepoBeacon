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
    if found or sys.platform != "darwin":
        return found
    for directory in (Path("/opt/homebrew/bin"), Path("/usr/local/bin")):
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def homebrew_executable():
    found = shutil.which("brew")
    if found:
        return found
    for candidate in (Path("/opt/homebrew/bin/brew"), Path("/usr/local/bin/brew")):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def install_missing_scanners(names):
    requested = [name for name in AUTO_INSTALLABLE_SCANNERS if name in names]
    missing = [name for name in requested if executable(name) is None]
    if not missing:
        return []
    if sys.platform != "darwin":
        raise ScannerError(
            "Missing scanners: " + ", ".join(missing) + ". Automatic installation is currently supported on macOS with Homebrew; install them from their official distribution channels or use --no-install-tools to record them as missing."
        )
    brew = homebrew_executable()
    if brew is None:
        raise ScannerError(
            "Missing scanners: " + ", ".join(missing) + ". Install Homebrew first, or use --no-install-tools to run without automatic installation."
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
