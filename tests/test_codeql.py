from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from repobeacon import codeql
from repobeacon.adapters import run_adapter
from repobeacon.cli import main, parser
from repobeacon.core import snapshot
from repobeacon.runner import ScannerError


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        console = redirect_stdout(io.StringIO())
        console.__enter__()
        self.addCleanup(console.__exit__, None, None, None)

    def make_archive(self, path, content=b"synthetic CLI"):
        with tarfile.open(path, "w:gz") as bundle:
            item = tarfile.TarInfo("codeql/codeql.exe" if os.name == "nt" else "codeql/codeql")
            item.size = len(content)
            item.mode = 0o755
            bundle.addfile(item, io.BytesIO(content))

    def test_latest_release_selects_platform_bundle_and_digest(self):
        url = "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-osx64.tar.gz"
        release = {"tag_name": "v2.27.0", "prerelease": False}
        bundle = {"tag_name": "codeql-bundle-v2.27.0", "assets": [{"name": "codeql-bundle-osx64.tar.gz", "browser_download_url": url, "size": 123, "digest": "sha256:" + "a" * 64}]}
        with patch.object(codeql, "release_json", side_effect=[release, bundle]), patch.object(codeql, "bundle_platform", return_value="osx64"):
            version, asset = codeql.latest_bundle()
        self.assertEqual(version, "2.27.0")
        self.assertEqual(asset, {"url": url, "size": 123, "sha256": "a" * 64})

    def test_verification_checks_extractors_and_query_packs(self):
        results = ['{"version":"2.27.0"}', '{"python":["/extractor"]}', 'codeql/python-queries@1.2.3: /queries']
        with patch.object(codeql, "execute", side_effect=results):
            self.assertEqual(codeql.verify_codeql("/codeql"), {"version": "2.27.0", "languages": ["python"]})
        results[-1] = "No packs found"
        with patch.object(codeql, "execute", side_effect=results), self.assertRaisesRegex(ScannerError, "packs are missing"):
            codeql.verify_codeql("/codeql")

    def test_reuses_current_verified_installation_without_download(self):
        info = {"version": "2.27.0", "languages": ["python"]}
        with patch.object(codeql, "verify_codeql", return_value=info), patch.object(codeql, "latest_bundle", return_value=("2.27.0", {})), patch.object(codeql, "download_bundle") as download:
            binary, _ = codeql.ensure_codeql("/existing/codeql", self.root)
        self.assertEqual(binary, "/existing/codeql")
        download.assert_not_called()

    def test_installs_missing_or_repairs_broken_or_upgrades_old_bundle(self):
        info = {"version": "2.27.0", "languages": ["python"]}
        for existing in (None, {"version": "2.26.0"}, ScannerError("broken")):
            with self.subTest(existing=existing):
                root = self.root / str(len(list(self.root.iterdir())))
                results = [info] if existing is None else [existing, info]
                with patch.object(codeql, "latest_bundle", return_value=("2.27.0", {"size": 123, "sha256": "abc"})), patch.object(codeql, "download_bundle", side_effect=lambda asset, path: self.make_archive(path)), patch.object(codeql, "verify_codeql", side_effect=results):
                    binary, details = codeql.ensure_codeql(None if existing is None else "/old/codeql", root)
                self.assertEqual(binary, codeql.managed_executable(root))
                self.assertTrue(Path(binary).is_file())
                self.assertEqual(details["version"], "2.27.0")

    def test_failed_update_preserves_active_installation(self):
        directory = "bundle-" + "a" * 32
        active = self.root / "active.json"
        active.write_text(json.dumps({"directory": directory}))
        before = active.read_text()
        with patch.object(codeql, "verify_codeql", return_value={"version": "2.26.0"}), patch.object(codeql, "latest_bundle", return_value=("2.27.0", {"size": 1})), patch.object(codeql, "download_bundle", side_effect=ScannerError("checksum mismatch")):
            with self.assertRaisesRegex(ScannerError, "checksum mismatch"):
                codeql.ensure_codeql("/old/codeql", self.root)
        self.assertEqual(active.read_text(), before)
        self.assertEqual(list(self.root.iterdir()), [active])

    def test_no_install_verifies_locally_and_never_checks_releases(self):
        with patch.object(codeql, "verify_codeql", return_value={"version": "2.26.0"}), patch.object(codeql, "latest_bundle") as latest:
            binary, _ = codeql.ensure_codeql("/existing/codeql", self.root, update=False)
        self.assertEqual(binary, "/existing/codeql")
        latest.assert_not_called()
        with self.assertRaisesRegex(ScannerError, "missing"):
            codeql.ensure_codeql(root=self.root, update=False)

    def test_download_rejects_corrupt_payload(self):
        payload = b"archive bytes"
        asset = {"url": "https://github.com/bundle", "size": len(payload), "sha256": hashlib.sha256(b"different").hexdigest()}
        with patch.object(codeql, "urlopen", return_value=io.BytesIO(payload)), self.assertRaisesRegex(ScannerError, "checksum"):
            codeql.download_bundle(asset, self.root / "bundle.tar.gz")

    def test_archive_cannot_escape_staging_directory(self):
        archive = self.root / "bundle.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            item = tarfile.TarInfo("../escaped")
            item.size = 1
            bundle.addfile(item, io.BytesIO(b"x"))
        with self.assertRaises(tarfile.TarError):
            codeql.extract_bundle(archive, self.root / "staging")
        self.assertFalse((self.root / "escaped").exists())

    def test_platform_selection(self):
        for system, machine, expected in [("Darwin", "arm64", "osx64"), ("Darwin", "x86_64", "osx64"), ("Linux", "aarch64", "linux-arm64"), ("Linux", "x86_64", "linux64"), ("Windows", "AMD64", "win64")]:
            with self.subTest(system=system, machine=machine), patch.object(codeql.platform, "system", return_value=system), patch.object(codeql.platform, "machine", return_value=machine):
                self.assertEqual(codeql.bundle_platform(), expected)


class LanguageTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX executable mode")
    def test_snapshot_preserves_build_script_executability(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "snapshot"
            source.mkdir()
            destination.mkdir()
            script = source / "gradlew"
            script.write_text("#!/bin/sh\nexit 0\n")
            script.chmod(0o755)
            snapshot(source, destination, root / "report")
            self.assertEqual((destination / "gradlew").stat().st_mode & 0o7777, 0o700)

    def test_groups_languages_and_selects_build_modes(self):
        plan = codeql.language_plan(["python", "javascript", "typescript", "java", "kotlin", "c", "cpp", "go", "swift", "ruby", "rust", "actions", "php"])
        by_language = {entry["language"]: entry for entry in plan}
        self.assertEqual(set(by_language), {"python", "javascript", "java", "cpp", "go", "swift", "ruby", "rust", "actions"})
        self.assertEqual(by_language["java"]["build_mode"], "autobuild")
        self.assertEqual(codeql.language_plan(["java"])[0]["build_mode"], "none")
        self.assertTrue(by_language["rust"]["requires_build_permission"])
        self.assertFalse(by_language["cpp"]["requires_build_permission"])

    def test_detects_extensions_and_workflows_from_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "snapshot"
            source.mkdir()
            destination.mkdir()
            for name in ["app.mjs", "app.cts", "app.cc", "app.kts", ".github/workflows/ci.yaml"]:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic fixture")
            inventory = snapshot(source, destination, root / "report")
        self.assertEqual(set(inventory["languages"]), {"javascript", "typescript", "cpp", "kotlin", "actions"})

    def test_build_execution_requires_explicit_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            options = SimpleNamespace(codeql_binary="/codeql", codeql_allow_builds=False, codeql_info={"languages": ["go"]}, timeout=300)
            with patch("repobeacon.adapters.tool_version", return_value="2.27.0"), patch("repobeacon.adapters.execute") as execute:
                run, _ = run_adapter("codeql", root, root, options, language="go", build_mode="autobuild", requires_build_permission=True)
            self.assertEqual(run["status"], "error")
            self.assertIn("--codeql-allow-builds", run["message"])
            execute.assert_not_called()

    def test_adapter_creates_correct_database_and_query_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            options = SimpleNamespace(codeql_binary="/codeql", codeql_allow_builds=True, codeql_info={"languages": ["java"]}, timeout=300)
            with patch("repobeacon.adapters.tool_version", return_value="2.27.0"), patch("repobeacon.adapters.execute") as execute, patch("repobeacon.adapters.read_json", return_value={"runs": []}):
                run, _ = run_adapter("codeql", root, root, options, language="java", build_mode="autobuild", requires_build_permission=True)
            self.assertEqual(run["status"], "success")
            self.assertEqual(execute.call_args_list[0].args[0][-2:], ["--build-mode", "autobuild"])
            self.assertIn("codeql/java-queries:codeql-suites/java-security-extended.qls", execute.call_args_list[1].args[0])


class ScanTests(unittest.TestCase):
    def test_codeql_is_enabled_by_default_and_no_eligibility_flag_required(self):
        self.assertIn("codeql", parser().parse_args(["scan"]).scanners.split(","))

    def test_scan_routes_each_detected_family_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            for name in ["app.py", "app.js", "app.ts", "App.java", "App.kt", "app.rb"]:
                (source / name).write_text("synthetic fixture")
            def adapter(name, source, work, options, **kwargs):
                return {"scanner": name, "required": True, "status": "success", "language": kwargs["language"]}, []
            with patch("repobeacon.cli.install_missing_scanners"), patch("repobeacon.cli.executable", return_value=None), patch("repobeacon.cli.ensure_codeql", return_value=("/codeql", {})) as ensure, patch("repobeacon.cli.run_adapter", side_effect=adapter) as run, redirect_stdout(io.StringIO()):
                status = main(["scan", str(source), "--scanners", "codeql", "--output", str(root / "report")])
            self.assertEqual(status, 0)
            self.assertEqual([call.kwargs["language"] for call in run.call_args_list], ["java", "javascript", "python", "ruby"])
            ensure.assert_called_once_with(None, update=True)

    def test_failed_setup_still_writes_incomplete_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("pass")
            with patch("repobeacon.cli.install_missing_scanners"), patch("repobeacon.cli.executable", return_value=None), patch("repobeacon.cli.ensure_codeql", side_effect=ScannerError("Network unavailable")), redirect_stdout(io.StringIO()):
                status = main(["scan", str(source), "--scanners", "codeql", "--output", str(root / "report")])
            report = json.loads((root / "report/findings.json").read_text())
            self.assertEqual(status, 2)
            self.assertEqual(report["scanner_runs"][0]["message"], "Network unavailable")


if __name__ == "__main__":
    unittest.main()
