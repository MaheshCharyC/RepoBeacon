from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from repobeacon.runner import ScannerError, executable, install_missing_scanners


class WindowsInstallerTests(unittest.TestCase):
    def setUp(self):
        for name, value in (("sys.platform", "win32"), ("sys.prefix", "/private-venv")):
            context = patch("repobeacon.runner." + name, value)
            context.start()
            self.addCleanup(context.stop)
        context = redirect_stdout(io.StringIO())
        context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)

    def test_installs_only_missing_tools_and_refreshes_path_before_verification(self):
        installed = {"gitleaks"}
        calls = []
        refreshed = []

        def run(command, check):
            calls.append(command)
            if "pip" in command:
                installed.add("semgrep")
            elif "AquaSecurity.Trivy" in command:
                installed.add("trivy")
            return SimpleNamespace(returncode=0)

        def locate(name):
            # New tools are visible only after the process PATH is refreshed.
            return "/tools/" + name if name in installed and (name == "gitleaks" or refreshed) else None

        with patch("repobeacon.runner.executable", side_effect=locate), patch("repobeacon.runner.shutil.which", return_value="winget.exe"), patch("repobeacon.runner.subprocess.run", side_effect=run), patch("repobeacon.runner.refresh_windows_path", side_effect=lambda: refreshed.append(True)):
            self.assertEqual(install_missing_scanners(["semgrep", "gitleaks", "trivy", "codeql"]), ["semgrep", "trivy"])
        self.assertEqual(calls[0], [sys.executable, "-m", "pip", "install", "semgrep"])
        self.assertIn("AquaSecurity.Trivy", calls[1])
        self.assertIn("--exact", calls[1])
        self.assertEqual(len(calls), 2)

    def test_missing_winget_and_global_python_fail_before_installing(self):
        with patch("repobeacon.runner.executable", return_value=None), patch("repobeacon.runner.subprocess.run") as run:
            with patch("repobeacon.runner.shutil.which", return_value=None), self.assertRaisesRegex(ScannerError, "setup.cmd"):
                install_missing_scanners(["gitleaks"])
            with patch("repobeacon.runner.sys.prefix", sys.base_prefix), self.assertRaisesRegex(ScannerError, "private Python"):
                install_missing_scanners(["semgrep"])
            run.assert_not_called()

    def test_failed_package_install_stops_and_preserves_error(self):
        with patch("repobeacon.runner.executable", return_value=None), patch("repobeacon.runner.shutil.which", return_value="winget.exe"), patch("repobeacon.runner.subprocess.run", return_value=SimpleNamespace(returncode=5)) as run, patch("repobeacon.runner.refresh_windows_path") as refresh:
            with self.assertRaisesRegex(ScannerError, "exit status 5"):
                install_missing_scanners(["gitleaks", "trivy"])
            run.assert_called_once()
            self.assertIn("Gitleaks.Gitleaks", run.call_args.args[0])
            refresh.assert_not_called()

    def test_install_success_without_binary_is_failure(self):
        with patch("repobeacon.runner.executable", return_value=None), patch("repobeacon.runner.shutil.which", return_value="winget.exe"), patch("repobeacon.runner.subprocess.run", return_value=SimpleNamespace(returncode=0)), patch("repobeacon.runner.refresh_windows_path"):
            with self.assertRaisesRegex(ScannerError, "unavailable: trivy"):
                install_missing_scanners(["trivy"])

    def test_finds_winget_links_when_callers_path_is_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "Microsoft/WinGet/Links/trivy.exe"
            binary.parent.mkdir(parents=True)
            binary.write_text("synthetic executable")
            binary.chmod(0o755)
            with patch.dict(os.environ, {"LOCALAPPDATA": directory}), patch("repobeacon.runner.shutil.which", return_value=None):
                self.assertEqual(executable("trivy"), str(binary))


@unittest.skipUnless(sys.platform == "win32", "Requires native Windows PowerShell")
class WindowsBootstrapTests(unittest.TestCase):
    def test_cmd_launcher_preserves_status_with_spaces_in_path(self):
        with tempfile.TemporaryDirectory(prefix="repobeacon setup ") as directory:
            root = Path(directory)
            shutil.copy2(Path(__file__).resolve().parents[1] / "setup.cmd", root / "setup.cmd")
            (root / "setup.ps1").write_text("exit 23\n")
            result = subprocess.run(["cmd.exe", "/d", "/c", "call", str(root / "setup.cmd")], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 23, result.stdout + result.stderr)

    def test_bootstrap_with_simulated_installers(self):
        script = Path(__file__).with_name("windows_setup_checks.ps1")
        for shell in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(shell):
                continue
            with self.subTest(shell=shell):
                result = subprocess.run([shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script)], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
