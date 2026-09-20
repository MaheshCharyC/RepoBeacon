from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from repobeacon.adapters import gitleaks_results, sarif_results, semgrep_results, trivy_results
from repobeacon.ai import enrich
from repobeacon.cli import main
from repobeacon.core import clean, evaluate, finding, safe_location, snapshot, unique_findings
from repobeacon.report import write_reports
from repobeacon.runner import ScannerError, environment, execute, install_missing_scanners


class NormalizationTests(unittest.TestCase):
    def test_semgrep_normalization_and_partial_errors(self):
        payload = {"results": [{"check_id": "python.eval", "path": "/source/app.py", "start": {"line": 4}, "extra": {"message": "Unsafe eval", "severity": "ERROR", "lines": "private source"}}], "errors": [{"type": "ParseError"}]}
        findings, partial, details = semgrep_results(payload, Path("/source"))
        self.assertTrue(partial)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["locations"][0]["path"], "app.py")
        self.assertNotIn("private source", json.dumps(findings))

    def test_gitleaks_discards_all_secret_evidence(self):
        secret = "synthetic-credential-value-123"
        payload = [{"RuleID": "generic-api-key", "File": "app.env", "StartLine": 2, "Secret": secret, "Match": secret, "Description": secret}]
        findings, _, _ = gitleaks_results(payload, Path("/source"))
        self.assertNotIn(secret, json.dumps(findings))
        self.assertEqual(findings[0]["category"], "secret")

    def test_trivy_vulnerability_and_resource_instances(self):
        payload = {"SchemaVersion": 2, "Results": [{"Target": "requirements.txt", "Type": "pip", "Vulnerabilities": [{"VulnerabilityID": "TEST-001", "PkgName": "example", "InstalledVersion": "1.0", "Severity": "CRITICAL", "FixedVersion": "2.0"}]}, {"Target": "pods.yaml", "Type": "kubernetes", "Misconfigurations": [{"ID": "KSV-TEST", "Title": "Privileged pod", "Severity": "HIGH", "CauseMetadata": {"Resource": "pod-a", "StartLine": 1}}, {"ID": "KSV-TEST", "Title": "Privileged pod", "Severity": "HIGH", "CauseMetadata": {"Resource": "pod-b", "StartLine": 1}}]}]}
        findings, partial, _ = trivy_results(payload, Path("/source"))
        self.assertFalse(partial)
        self.assertEqual(len(unique_findings(findings)), 3)
        self.assertEqual(findings[0]["package"]["version"], "1.0")
        self.assertEqual(findings[1]["category"], "kubernetes")

    def test_sarif_security_severity(self):
        payload = {"runs": [{"tool": {"driver": {"rules": [{"id": "py/test", "properties": {"security-severity": "9.1"}}]}}, "results": [{"ruleId": "py/test", "message": {"text": "Potential flaw"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 9}}}]}]}]}
        findings, _, _ = sarif_results(payload, Path("/source"))
        self.assertEqual(findings[0]["severity"], "critical")

    def test_unknown_severity_is_not_silently_passed(self):
        item = finding("test", "rule", "Title", "unexpected", "sast", "app.py")
        result = evaluate([item], [], "high")
        self.assertEqual(result["exit_code"], 1)

    def test_missing_tool_takes_precedence_over_findings(self):
        item = finding("test", "rule", "Title", "critical", "sast", "app.py")
        result = evaluate([item], [{"required": True, "status": "missing"}], "high")
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["policy_status"], "fail")

    def test_invalid_reports_rejected(self):
        for function, payload in [(semgrep_results, {}), (gitleaks_results, {}), (trivy_results, {}), (sarif_results, {})]:
            with self.subTest(function=function.__name__), self.assertRaises(ScannerError):
                function(payload, Path("/source"))

    def test_paths_and_redaction(self):
        self.assertEqual(safe_location("../../private", Path("/source")), "[external-location]")
        self.assertNotIn("hunter2", clean("password=hunter2"))
        self.assertNotIn("passwd", clean("https://user:passwd@example.com"))


class ExecutionTests(unittest.TestCase):
    @patch("repobeacon.runner.homebrew_executable", return_value="/opt/homebrew/bin/brew")
    @patch("repobeacon.runner.subprocess.run")
    @patch("repobeacon.runner.executable")
    def test_missing_scanners_are_installed_once_with_homebrew(self, find_executable, run, _find_brew):
        find_executable.side_effect = [None, "/tools/gitleaks", None, "/tools/semgrep", "/tools/trivy"]
        run.return_value.returncode = 0
        with patch("repobeacon.runner.sys.platform", "darwin"):
            installed = install_missing_scanners(["trivy", "gitleaks", "semgrep"])
        self.assertEqual(installed, ["semgrep", "trivy"])
        run.assert_called_once_with(["/opt/homebrew/bin/brew", "install", "semgrep", "trivy"], check=False)

    @patch("repobeacon.runner.subprocess.run")
    @patch("repobeacon.runner.executable", return_value="/tools/scanner")
    def test_installer_skips_homebrew_when_tools_exist(self, _find_executable, run):
        self.assertEqual(install_missing_scanners(["semgrep", "gitleaks", "trivy"]), [])
        run.assert_not_called()

    def test_environment_does_not_inherit_credentials(self):
        with patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "private", "SEMGREP_APP_TOKEN": "private", "PYTHONPATH": "untrusted"}):
            values = environment(Path("/temporary"))
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", values)
            self.assertNotIn("SEMGREP_APP_TOKEN", values)
            self.assertNotIn("PYTHONPATH", values)

    def test_timeout_kills_process(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with self.assertRaisesRegex(ScannerError, "time limit"):
                execute([sys.executable, "-c", "import time; time.sleep(30)"], path, path, 0.1)

    def test_native_failure_does_not_expose_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with self.assertRaises(ScannerError) as raised:
                execute([sys.executable, "-c", "import sys; sys.stderr.write('synthetic-private-token'); sys.exit(5)"], path, path, 5)
            self.assertNotIn("synthetic-private-token", str(raised.exception))

    def test_output_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with self.assertRaisesRegex(ScannerError, "output limit"):
                execute([sys.executable, "-c", "print('x' * 10000)"], path, path, 5, output_limit=100)

    def test_snapshot_excludes_configs_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "copy"
            source.mkdir()
            destination.mkdir()
            (source / "app.py").write_text("print('hello')")
            (source / ".semgrepignore").write_text("*")
            if os.name != "nt":
                (source / "outside").symlink_to(root)
            inventory = snapshot(source, destination, root / "report")
            self.assertEqual(inventory["languages"], ["python"])
            self.assertFalse((destination / ".semgrepignore").exists())
            self.assertFalse((destination / "outside").exists())

    def test_ai_rejects_non_loopback_local_endpoint(self):
        with self.assertRaises(ValueError):
            enrich([], "local", "http://example.com/report", "test")

    def test_ai_rejects_cloud_http(self):
        with self.assertRaises(ValueError):
            enrich([], "cloud", "http://example.com/report", "test")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "app.py").write_text("eval(input())\n")
        installer = patch("repobeacon.cli.install_missing_scanners", return_value=[])
        self.install_missing_scanners = installer.start()
        self.addCleanup(installer.stop)
        codeql = patch("repobeacon.cli.ensure_codeql", return_value=("/tools/codeql", {"version": "2.27.0", "languages": ["python", "javascript"]}))
        self.ensure_codeql = codeql.start()
        self.addCleanup(codeql.stop)

    def call(self, *arguments):
        with redirect_stdout(io.StringIO()):
            return main(list(arguments))

    def fake_adapter(self, name, source, work, options, **kwargs):
        item = finding(name, "test-rule", "Potential eval", "high", "sast", "app.py", 1)
        return {"scanner": name, "version": "test-1", "status": "success", "required": True, "findings": 1}, [item]

    def test_missing_scanner_still_writes_reports(self):
        output = self.root / "report"
        with patch("repobeacon.adapters.executable", return_value=None):
            code = self.call("scan", str(self.source), "--output", str(output))
        self.assertEqual(code, 2)
        result = json.loads((output / "findings.json").read_text())
        self.assertEqual(result["policy_result"]["execution_status"], "incomplete")
        self.assertEqual(len(list(output.iterdir())), 7)

    def test_scan_checks_selected_scanners_before_scanning(self):
        output = self.root / "report"
        with patch("repobeacon.cli.run_adapter", side_effect=self.fake_adapter):
            self.call("scan", str(self.source), "--scanners", "semgrep,gitleaks", "--output", str(output))
        self.install_missing_scanners.assert_called_once_with(["semgrep", "gitleaks"])

    def test_no_install_tools_skips_prerequisite_installation(self):
        output = self.root / "report"
        with patch("repobeacon.cli.run_adapter", side_effect=self.fake_adapter):
            self.call("scan", str(self.source), "--scanners", "semgrep", "--no-install-tools", "--output", str(output))
        self.install_missing_scanners.assert_not_called()

    def test_baseline_and_new_only(self):
        first, second = self.root / "first", self.root / "second"
        with patch("repobeacon.cli.run_adapter", side_effect=self.fake_adapter):
            self.assertEqual(self.call("scan", str(self.source), "--scanners", "semgrep", "--output", str(first)), 1)
            self.assertEqual(self.call("scan", str(self.source), "--scanners", "semgrep", "--output", str(second), "--baseline", str(first / "findings.json"), "--new-only"), 0)
        result = json.loads((second / "findings.json").read_text())
        self.assertEqual(result["findings"][0]["baseline_state"], "existing")

    def test_incomparable_baseline_cannot_pass_new_only(self):
        baseline = self.root / "baseline.json"
        baseline.write_text('{}')
        with patch("repobeacon.cli.run_adapter", side_effect=self.fake_adapter):
            code = self.call("scan", str(self.source), "--scanners", "semgrep", "--output", str(self.root / "report"), "--baseline", str(baseline), "--new-only")
        self.assertEqual(code, 2)

    def test_existing_output_is_not_overwritten(self):
        output = self.root / "report"
        output.mkdir()
        (output / "keep.txt").write_text("original")
        self.assertEqual(self.call("scan", str(self.source), "--output", str(output)), 2)
        self.assertEqual((output / "keep.txt").read_text(), "original")
        self.install_missing_scanners.assert_not_called()
        self.ensure_codeql.assert_not_called()

    def test_html_escapes_untrusted_findings(self):
        output = self.root / "report"
        assessment = {"target": {"path": "test"}, "created_at": "test", "policy_result": {"execution_status": "complete", "policy_status": "fail"}, "scanner_runs": [], "coverage": {}, "findings": [finding("test", "rule", "<script>alert(1)</script>", "high", "sast", "app.py")]}
        write_reports(assessment, output)
        rendered = (output / "index.html").read_text()
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_ai_failure_does_not_change_gate(self):
        with patch("repobeacon.cli.run_adapter", side_effect=self.fake_adapter), patch("repobeacon.cli.enrich", side_effect=ValueError("bad response")):
            code = self.call("scan", str(self.source), "--scanners", "semgrep", "--output", str(self.root / "report"), "--ai", "local", "--ai-endpoint", "http://127.0.0.1:9999/report")
        self.assertEqual(code, 1)
        report = json.loads((self.root / "report/findings.json").read_text())
        self.assertEqual(report["ai"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
