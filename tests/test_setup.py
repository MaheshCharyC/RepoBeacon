from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from repobeacon.cli import main
from repobeacon.runner import ScannerError


class SetupCommandTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        context = redirect_stdout(self.output)
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)

    def test_setup_provisions_then_verifies_without_scanning(self):
        calls = []
        with patch("repobeacon.cli.install_missing_scanners", side_effect=lambda names: calls.append(("install", names))), patch("repobeacon.cli.executable", return_value="/tools/codeql"), patch("repobeacon.cli.ensure_codeql", side_effect=lambda binary, update: calls.append(("codeql", binary, update))), patch("repobeacon.cli.doctor", side_effect=lambda: calls.append(("verify",)) or 0), patch("repobeacon.cli.scan") as scan:
            self.assertEqual(main(["setup"]), 0)
        self.assertEqual(calls, [("install", ["semgrep", "gitleaks", "trivy"]), ("codeql", "/tools/codeql", True), ("verify",)])
        scan.assert_not_called()
        self.assertIn("Setup complete", self.output.getvalue())

    def test_setup_failure_never_claims_ready(self):
        for failure in ("install", "codeql", "verification"):
            with self.subTest(failure=failure):
                self.output.truncate(0)
                self.output.seek(0)
                with patch("repobeacon.cli.install_missing_scanners", side_effect=ScannerError("install failed") if failure == "install" else None), patch("repobeacon.cli.executable", return_value=None), patch("repobeacon.cli.ensure_codeql", side_effect=ScannerError("download failed") if failure == "codeql" else None), patch("repobeacon.cli.doctor", return_value=2):
                    self.assertEqual(main(["setup"]), 2)
                self.assertNotIn("Setup complete", self.output.getvalue())


# Exercise the bootstrap without network access, package installs, or system changes.
FAKE_TOOL = r'''
import json, os, pathlib, shutil, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ["SETUP_TEST_ROOT"])
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps([name, args, os.getcwd()]) + "\n")
if name == "uname":
    print(os.environ.get("SETUP_TEST_OS", "Darwin") if args == ["-s"] else "arm64")
elif name == "xcode-select":
    if os.environ.get("SETUP_TEST_NO_CLT"):
        sys.exit(1 if args == ["-p"] else 0)
elif name == "brew":
    if args == ["--prefix"]:
        print(root / "brew")
    elif args == ["--prefix", "python@3.12"]:
        print(root / "python")
    elif args == ["install", "python@3.12"]:
        target = root / "python/bin/python3.12"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / "bin/python-template", target)
elif name == "arch":
    sys.exit(0 if (root / "rosetta-ready").exists() else 1)
elif name == "getconf":
    sys.exit(1 if os.environ.get("SETUP_TEST_NO_GLIBC") else 0)
elif name == "cygpath":
    print(args[-1])
elif name == "pwsh.exe":
    sys.exit(int(os.environ.get("SETUP_TEST_STATUS", "0")))
elif name == "sudo":
    assert args == ["softwareupdate", "--install-rosetta"]
    (root / "rosetta-ready").touch()
elif name in ("python", "python3.12"):
    if args[:2] == ["-m", "venv"]:
        target = pathlib.Path(args[2]) / "bin/python"
        target.parent.mkdir(parents=True)
        shutil.copy2(root / "bin/python-template", target)
    elif args[:1] == ["-c"]:
        sys.exit(1 if pathlib.Path(".venv/broken").exists() else 0)
    elif args == ["-m", "repobeacon", "setup"]:
        sys.exit(int(os.environ.get("SETUP_TEST_STATUS", "0")))
'''


@unittest.skipUnless(os.name == "posix" and os.geteuid() != 0 and shutil.which("bash"), "Bash bootstrap checks require a non-root Unix user")
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="repobeacon setup ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repo = self.root / "repo with spaces"
        self.repo.mkdir()
        shutil.copy2(Path(__file__).resolve().parents[1] / "setup.sh", self.repo / "setup.sh")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        script = f'#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(self.root / "fake.py"))} "$0" "$@"\n'
        (self.root / "fake.py").write_text("import sys\nsys.argv = sys.argv[1:]\n" + FAKE_TOOL)
        for name in ("uname", "xcode-select", "brew", "sysctl", "arch", "sudo", "getconf", "cygpath", "pwsh.exe", "python-template"):
            (self.bin / name).write_text(script)
            (self.bin / name).chmod(0o755)
        self.env = {**os.environ, "SETUP_TEST_ROOT": str(self.root), "PATH": str(self.bin) + ":/usr/bin:/bin"}

    def run_setup(self, **environment):
        result = subprocess.run(["/bin/bash", str(self.repo / "setup.sh")], cwd=self.root, env={**self.env, **environment}, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        log = self.root / "calls.jsonl"
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        return result, calls

    def test_fresh_setup_and_repeat_from_another_directory(self):
        result, calls = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(["brew", ["install", "python@3.12"], str(self.repo)], calls)
        self.assertIn(["sudo", ["softwareupdate", "--install-rosetta"], str(self.repo)], calls)
        self.assertIn(["python", ["-m", "repobeacon", "setup"], str(self.repo)], calls)
        self.assertTrue((self.repo / ".venv/bin/python").exists())
        (self.repo / ".venv/preserve-me").touch()
        (self.root / "calls.jsonl").unlink()
        result, calls = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.repo / ".venv/preserve-me").exists())
        self.assertFalse(any(call[1][:2] in (["install", "python@3.12"], ["-m", "venv"], ["softwareupdate", "--install-rosetta"]) for call in calls))

    def test_broken_environment_is_preserved(self):
        (self.repo / ".venv").mkdir()
        (self.repo / ".venv/broken").write_text("old environment")
        result, _ = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        backups = list(self.repo.glob(".venv-backup.*/venv/broken"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "old environment")
        self.assertTrue((self.repo / ".venv/bin/python").exists())

    def test_failed_verification_does_not_offer_scan(self):
        result, _ = self.run_setup(SETUP_TEST_STATUS="2")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Setup stopped", result.stderr)
        self.assertNotIn("Next, scan", result.stdout)

    def test_unsupported_platform_stops_before_installing(self):
        result, calls = self.run_setup(SETUP_TEST_OS="FreeBSD")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([call[0] for call in calls], ["uname"])

    def test_linux_setup_uses_brew_without_apple_installers(self):
        result, calls = self.run_setup(SETUP_TEST_OS="Linux")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(["python", ["-m", "repobeacon", "setup"], str(self.repo)], calls)
        self.assertFalse(any(call[0] in {"arch", "xcode-select", "sudo"} for call in calls))

    def test_windows_bash_dispatches_and_preserves_exit_status(self):
        result, calls = self.run_setup(SETUP_TEST_OS="MINGW64_NT-10.0", SETUP_TEST_STATUS="23")
        self.assertEqual(result.returncode, 23)
        launches = [call for call in calls if call[0] == "pwsh.exe"]
        self.assertEqual(len(launches), 1)
        self.assertEqual(launches[0][1][-2:], ["-File", str(self.repo / "setup.ps1")])
        self.assertFalse(any(call[0] in {"brew", "xcode-select"} for call in calls))

    def test_musl_linux_stops_before_installing(self):
        result, calls = self.run_setup(SETUP_TEST_OS="Linux", SETUP_TEST_NO_GLIBC="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("glibc Linux", result.stdout)
        self.assertFalse(any(call[0] == "brew" for call in calls))

    def test_pending_apple_install_in_noninteractive_session_is_actionable(self):
        result, calls = self.run_setup(SETUP_TEST_NO_CLT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Finish Apple's Command Line Tools installation", result.stdout)
        self.assertFalse(any(call[0] == "brew" for call in calls))
