import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from . import __version__
from .adapters import RULES, run_adapter
from .ai import enrich
from .codeql import FAMILIES, ensure_codeql, language_plan, verify_codeql
from .core import SEVERITIES, clean, digest, evaluate, snapshot, unique_findings
from .report import write_reports
from .runner import ScannerError, executable, install_missing_scanners, read_json, tool_version


def parser():
    root = argparse.ArgumentParser(prog="repobeacon", description="Coordinate local security scanners and generate unified reports.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check availability of scanner binaries.")
    scan = commands.add_parser("scan", help="Scan a local directory; CodeQL builds require --codeql-allow-builds.")
    scan.add_argument("target", nargs="?", default=".")
    scan.add_argument("--output", type=Path, help="New output directory; defaults to security-report/<timestamp>.")
    scan.add_argument("--scanners", default="semgrep,gitleaks,trivy,codeql", help="Comma-separated semgrep,gitleaks,trivy,codeql (all by default).")
    scan.add_argument("--no-install-tools", action="store_true", help="Disable tool installation and CodeQL update checks; verify installed CodeQL locally.")
    scan.add_argument("--profile", choices=["standard", "deep"], default="standard")
    scan.add_argument("--codeql-authorized", action="store_true", help="Compatibility flag; CodeQL now runs automatically when selected. Applicable CodeQL terms still apply.")
    scan.add_argument("--codeql-allow-builds", action="store_true", help="Allow CodeQL to execute project build code for Go, Kotlin, Swift, and Rust analysis; use only for trusted targets.")
    scan.add_argument("--rules", type=Path, help="Explicitly trusted local Semgrep rule file.")
    scan.add_argument("--timeout", type=int, default=300, help="Per-command scanner deadline in seconds.")
    scan.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "repobeacon" / "trivy")
    scan.add_argument("--no-update", action="store_true", help="Use cached Trivy data. This is not a network sandbox.")
    scan.add_argument("--image", help="Explicit container image reference or image archive path.")
    scan.add_argument("--fail-on", choices=list(SEVERITIES)[1:], default="high")
    scan.add_argument("--baseline", type=Path)
    scan.add_argument("--new-only", action="store_true")
    scan.add_argument("--ai", choices=["off", "local", "cloud"], default="off")
    scan.add_argument("--ai-endpoint", help="Endpoint implementing the protocol documented in docs/usage.md.")
    scan.add_argument("--ai-model", default="configured-model")
    return root


def doctor():
    missing = False
    with tempfile.TemporaryDirectory(prefix="repobeacon-doctor-") as directory:
        home = Path(directory)
        for name in ["semgrep", "gitleaks", "trivy", "codeql"]:
            binary = executable(name)
            version = "not installed"
            if binary:
                try:
                    if name == "codeql":
                        info = verify_codeql(binary)
                        version = info["version"] + " (extractors and query packs verified)"
                    else:
                        version = clean(tool_version(name, binary, home))
                except Exception:
                    version = "installed but verification failed"
                    missing = True
            else:
                missing = True
            print(f"{name}: {version}")
    return 2 if missing else 0


def apply_baseline(assessment, baseline, new_only):
    comparable = baseline.get("schema_version") == "1.0" and baseline.get("target", {}).get("identity") == assessment["target"]["identity"] and baseline.get("comparison_signature") == assessment["comparison_signature"] and baseline.get("policy_result", {}).get("execution_status") == "complete"
    if not comparable:
        for item in assessment["findings"]:
            item["baseline_state"] = "not comparable"
        assessment["coverage"]["notes"].append("Baseline is not comparable: target, tool/rules configuration, or prior completeness differs.")
        if new_only:
            assessment["scanner_runs"].append({"scanner": "baseline", "required": True, "status": "error", "message": "Cannot apply --new-only to an incomparable baseline."})
        return
    fingerprints = {item["fingerprint"] for item in baseline.get("findings", [])}
    for item in assessment["findings"]:
        item["baseline_state"] = "existing" if item["fingerprint"] in fingerprints else "new"


def scan(options):
    target = Path(options.target).resolve()
    if not target.is_dir():
        raise ValueError("Target must be an existing local directory.")
    if not 1 <= options.timeout <= 86400:
        raise ValueError("Timeout must be between 1 and 86400 seconds.")
    names = list(dict.fromkeys(options.scanners.split(",")))
    if not names or set(names) - {"semgrep", "gitleaks", "trivy", "codeql"}:
        raise ValueError("Unknown or empty scanner selection.")
    if options.profile == "deep" and "codeql" not in names:
        names.append("codeql")
    if options.image and "trivy" not in names:
        raise ValueError("--image requires the trivy scanner.")
    if options.rules:
        options.rules = options.rules.resolve()
        if not options.rules.is_file():
            raise ValueError("--rules must identify a local file.")
    if options.new_only and not options.baseline:
        raise ValueError("--new-only requires --baseline.")
    if options.ai != "off" and not options.ai_endpoint:
        raise ValueError("AI mode requires --ai-endpoint; see docs/usage.md for its protocol.")
    baseline = read_json(options.baseline) if options.baseline else None
    if baseline is not None and not isinstance(baseline, dict):
        raise ValueError("Baseline must be a RepoBeacon assessment object.")
    if baseline is not None:
        entries = baseline.get("findings", [])
        if not isinstance(entries, list) or any(not isinstance(entry, dict) or not isinstance(entry.get("fingerprint"), str) for entry in entries):
            raise ValueError("Baseline findings must contain string fingerprints.")
    now = datetime.now(timezone.utc)
    output = (options.output or Path("security-report") / now.strftime("%Y%m%dT%H%M%S%fZ")).absolute()
    if output.is_symlink() or output.exists():
        raise ValueError("Output must be a new directory to avoid overwriting or mixing reports.")
    output = output.resolve()
    options.cache = options.cache.resolve()
    if not options.no_install_tools:
        install_missing_scanners(names)
    options.codeql_binary = None
    codeql_error = None
    if "codeql" in names:
        try:
            options.codeql_binary, options.codeql_info = ensure_codeql(executable("codeql"), update=not options.no_install_tools)
        except ScannerError as error:
            codeql_error = clean(str(error))
            print("CodeQL: " + codeql_error, flush=True)
    assessment = {"schema_version": "1.0", "application_version": __version__, "created_at": now.isoformat(), "target": {"path": clean(str(target)), "identity": digest(str(target).encode())}, "scanner_runs": [], "findings": [], "coverage": {"notes": ["Working-tree snapshot only; Git history is not scanned.", "Source snippets and raw scanner output are not persisted.", "Unknown reachability and deployment exposure are not inferred.", "Scanner-native inline IaC suppressions may affect coverage; inspect the target before enforcing an organization policy."]}, "ai": {"status": "disabled"}}
    with tempfile.TemporaryDirectory(prefix="repobeacon-") as temporary:
        work = Path(temporary)
        source = work / "source"
        source.mkdir()
        inventory = snapshot(target, source, output)
        assessment["target"]["snapshot_sha256"] = inventory["snapshot_sha256"]
        assessment["coverage"].update(inventory)
        supported = {"python", "javascript", "typescript"}
        assessment["coverage"]["languages_without_bundled_sast_rules"] = sorted(set(inventory["languages"]) - supported)
        assessment["coverage"]["disabled_scanners"] = sorted({"semgrep", "gitleaks", "trivy", "codeql"} - set(names))
        assessment["coverage"]["notes"].append("SAST starter pack contains six checks, not a comprehensive security ruleset. Custom rules require separate coverage review.")
        for name in names:
            if name == "semgrep" and not options.rules and not supported.intersection(inventory["languages"]):
                assessment["scanner_runs"].append({"scanner": name, "required": False, "status": "not_applicable", "version": None, "message": "No language supported by the bundled SAST rules was discovered."})
                continue
            if name == "codeql":
                plan = language_plan(inventory["languages"])
                assessment["coverage"]["codeql_languages"] = [entry["language"] for entry in plan]
                assessment["coverage"]["languages_without_codeql_support"] = sorted(set(inventory["languages"]) - FAMILIES.keys())
                if codeql_error:
                    assessment["scanner_runs"].append({"scanner": "codeql", "required": True, "status": "error", "message": codeql_error})
                    continue
                if not plan:
                    assessment["scanner_runs"].append({"scanner": "codeql", "required": bool(inventory["languages"]), "status": "unsupported" if inventory["languages"] else "not_applicable", "message": "No CodeQL-supported language was detected."})
                for entry in plan:
                    print(f"CodeQL: analyzing {entry['language']} (build mode: {entry['build_mode']})...", flush=True)
                    run, findings = run_adapter(name, source, work, options, language=entry["language"], build_mode=entry["build_mode"], requires_build_permission=entry["requires_build_permission"])
                    assessment["scanner_runs"].append(run)
                    assessment["findings"].extend(findings)
            else:
                run, findings = run_adapter(name, source, work, options)
                assessment["scanner_runs"].append(run)
                assessment["findings"].extend(findings)
        if options.image:
            run, findings = run_adapter("trivy", source, work, options, image=options.image)
            assessment["scanner_runs"].append(run)
            assessment["findings"].extend(findings)
    assessment["findings"] = unique_findings(assessment["findings"])
    rules_digest = digest((options.rules or RULES / "semgrep.yaml").read_bytes())
    signature = {"scanners": [{key: run.get(key) for key in ("scanner", "version", "language", "build_mode", "image")} for run in assessment["scanner_runs"]], "rules": rules_digest, "app": __version__}
    assessment["comparison_signature"] = digest(json.dumps(signature, sort_keys=True).encode())
    if baseline is not None:
        apply_baseline(assessment, baseline, options.new_only)
    assessment["policy_result"] = evaluate(assessment["findings"], assessment["scanner_runs"], options.fail_on, options.new_only)
    if options.ai != "off":
        try:
            assessment["ai"] = enrich(assessment["findings"], options.ai, options.ai_endpoint, options.ai_model)
        except Exception:
            assessment["ai"] = {"status": "error", "message": "AI enrichment failed validation or was unavailable; deterministic results preserved."}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".repobeacon-report-", dir=output.parent) as temporary:
        staging = Path(temporary) / "report"
        write_reports(assessment, staging)
        if output.exists() or output.is_symlink():
            raise ValueError("Output appeared during scan; refusing to overwrite it.")
        os.rename(staging, output)
    policy = assessment["policy_result"]
    print(f"{len(assessment['findings'])} findings | execution: {policy['execution_status']} | policy: {policy['policy_status']}")
    for run in assessment["scanner_runs"]:
        label = run["scanner"] + ("/" + run["language"] if run.get("language") else "")
        print(f"  {label}: {run['status']}")
    print("Report: " + clean(str(output / "index.html")))
    return policy["exit_code"]


def main(argv=None):
    options = parser().parse_args(argv)
    try:
        return doctor() if options.command == "doctor" else scan(options)
    except KeyboardInterrupt:
        print("Scan cancelled.")
        return 130
    except (ScannerError, ValueError, OSError) as error:
        print("RepoBeacon: " + clean(str(error)))
        return 2
