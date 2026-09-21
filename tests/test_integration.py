from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from repobeacon.cli import main


@unittest.skipUnless(os.environ.get("REPOBEACON_CODEQL_INTEGRATION") == "1", "Set REPOBEACON_CODEQL_INTEGRATION=1 with a real CodeQL bundle installed")
class RealCodeQLTests(unittest.TestCase):
    def test_detects_and_scans_python_and_typescript(self):
        from repobeacon.codeql import installation_root
        root = Path(os.environ.get("REPOBEACON_CODEQL_TEST_ROOT", str(installation_root()))).resolve()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            source = work / "source"
            source.mkdir()
            (source / "app.py").write_text("def greet(name):\n    return 'Hello ' + name\n")
            (source / "app.ts").write_text("export function greet(name: string): string { return 'Hello ' + name; }\n")
            output = work / "report"
            with patch("repobeacon.codeql.installation_root", return_value=root):
                status = main(["scan", str(source), "--scanners", "codeql", "--no-open", "--no-install-tools", "--timeout", "600", "--output", str(output)])
            result = json.loads((output / "findings.json").read_text())
            self.assertEqual(status, 0, result["scanner_runs"])
            self.assertEqual({run["language"] for run in result["scanner_runs"]}, {"python", "javascript"})
            self.assertTrue(all(run["status"] == "success" for run in result["scanner_runs"]), result["scanner_runs"])


@unittest.skipUnless(os.environ.get("REPOBEACON_INTEGRATION") == "1", "Set REPOBEACON_INTEGRATION=1 with real scanners installed")
class RealScannerTests(unittest.TestCase):
    def test_semgrep_bundled_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            with redirect_stdout(io.StringIO()):
                code = main(["scan", str(Path(__file__).resolve().parents[1] / "testdata/vulnerable"), "--scanners", "semgrep", "--no-open", "--output", str(output)])
            self.assertEqual(code, 1)
            report = json.loads((output / "findings.json").read_text())
            self.assertEqual(len(report["findings"]), 5)
            self.assertEqual(report["policy_result"]["execution_status"], "complete")

    def test_gitleaks_real_secret_redaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            synthetic = "a83f962ec075d419b2e80f47a139dc65"
            (source / ".env").write_text('api_key = "' + synthetic + '"\n')
            output = root / "report"
            with redirect_stdout(io.StringIO()) as console:
                code = main(["scan", str(source), "--scanners", "gitleaks", "--no-open", "--output", str(output)])
            self.assertEqual(code, 1)
            report = json.loads((output / "findings.json").read_text())
            self.assertGreaterEqual(len(report["findings"]), 1)
            for artifact in output.iterdir():
                self.assertNotIn(synthetic, artifact.read_text())
            self.assertNotIn(synthetic, console.getvalue())
