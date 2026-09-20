import json
from pathlib import Path
import time

from .core import clean, finding, safe_location
from .runner import ScannerError, executable, execute, read_json, tool_version


RULES = Path(__file__).parent / "rules"


def semgrep_results(payload, source):
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ScannerError("Semgrep returned an invalid report shape.")
    findings = []
    for result in payload["results"]:
        extra = result["extra"]
        findings.append(finding("semgrep", result["check_id"], extra["message"], extra["severity"], "sast", safe_location(result["path"], source), result["start"]["line"]))
    scanned = payload.get("paths", {}).get("scanned", [])
    return findings, bool(payload.get("errors")), {"scanned_files": len(scanned), "rule_coverage": "six bundled checks for Python and JavaScript/TypeScript; custom rules when supplied"}


def gitleaks_results(payload, source):
    if not isinstance(payload, list):
        raise ScannerError("Gitleaks returned an invalid report shape.")
    findings = []
    for result in payload:
        findings.append(finding("gitleaks", result["RuleID"], "Potential exposed credential", "high", "secret", safe_location(result["File"], source), result.get("StartLine", 1), remediation="Investigate exposure, revoke or rotate the credential, then remove it from source. Credential validity has not been tested."))
    return findings, False, {"history": "working tree only", "secret_values": "discarded"}


def trivy_results(payload, source, image=None):
    if not isinstance(payload, dict) or "SchemaVersion" not in payload or not isinstance(payload.get("Results") or [], list):
        raise ScannerError("Trivy returned an invalid report shape.")
    findings = []
    for result in payload.get("Results") or []:
        path = clean(image) if image else safe_location(result.get("Target", "."), source)
        for issue in result.get("Vulnerabilities") or []:
            package = {"name": clean(issue["PkgName"]), "version": clean(issue["InstalledVersion"]), "ecosystem": clean(result.get("Type", "unknown"))}
            fixed = issue.get("FixedVersion")
            instruction = f"Review and upgrade to a compatible fixed version: {fixed}." if fixed else "No fixed version reported. Review advisory mitigations and deployment context."
            findings.append(finding("trivy", issue["VulnerabilityID"], issue.get("Title") or issue["VulnerabilityID"], issue.get("Severity", "unknown"), "container" if image else "sca", path, package=package, advisory=issue["VulnerabilityID"], remediation=instruction, instance=issue.get("PkgPath")))
        for issue in result.get("Misconfigurations") or []:
            if issue.get("Status", "FAIL") != "FAIL":
                continue
            metadata = issue.get("CauseMetadata") or {}
            category = "kubernetes" if result.get("Type") == "kubernetes" else "iac"
            findings.append(finding("trivy", issue["ID"], issue.get("Title") or issue["ID"], issue.get("Severity", "unknown"), category, path, metadata.get("StartLine", 1), remediation=issue.get("Resolution") or "Review and correct the configuration.", instance=metadata.get("Resource")))
    return findings, False, {"targets": len(payload.get("Results") or []), "database_freshness": "see local Trivy cache; not independently verified", "image_metadata": {"image_id": clean(payload.get("Metadata", {}).get("ImageID", "")), "repo_digests": [clean(item) for item in payload.get("Metadata", {}).get("RepoDigests", [])]}}


def sarif_results(payload, source):
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise ScannerError("CodeQL returned invalid SARIF.")
    findings = []
    incomplete = False
    for run in payload["runs"]:
        for invocation in run.get("invocations", []):
            incomplete = incomplete or invocation.get("executionSuccessful") is False
        rules = {rule["id"]: rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result["ruleId"]
            score = rules.get(rule_id, {}).get("properties", {}).get("security-severity")
            severity = result.get("level", "warning")
            if score is not None:
                numeric = float(score)
                severity = "critical" if numeric >= 9 else "high" if numeric >= 7 else "medium" if numeric >= 4 else "low"
            locations = result.get("locations") or [{}]
            physical = locations[0].get("physicalLocation", {})
            findings.append(finding("codeql", rule_id, result.get("message", {}).get("text", rule_id), severity, "sast", safe_location(physical.get("artifactLocation", {}).get("uri", "[unknown]"), source), physical.get("region", {}).get("startLine", 1)))
    return findings, incomplete, {}


def run_adapter(name, source, work, options, language=None, image=None, build_mode="none", requires_build_permission=False):
    run = {"scanner": name, "required": True, "status": "pending", "version": None, "findings": 0}
    if language:
        run["language"] = language
    if image:
        run["image"] = clean(image)
    binary = (getattr(options, "codeql_binary", None) or executable(name)) if name == "codeql" else executable(name)
    if binary is None:
        run.update(status="missing", message=f"Install {name} and make it available on PATH. See docs/usage.md.")
        return run, []
    started = time.monotonic()
    home = work / (name + ("-" + language if language else "") + ("-image" if image else ""))
    home.mkdir(parents=True, exist_ok=True)
    findings = []
    try:
        run["version"] = clean(tool_version(name, binary, home))
        if name == "semgrep":
            rules = options.rules or RULES / "semgrep.yaml"
            command = [binary, "scan", "--config", str(rules), "--json", "--metrics=off", "--disable-version-check", "--disable-nosem", "--no-git-ignore", "--max-target-bytes", "10485760", "--timeout", str(max(1, min(options.timeout, 60))), str(source)]
            payload = json.loads(execute(command, home, home, options.timeout))
            findings, partial, details = semgrep_results(payload, source)
        elif name == "gitleaks":
            report = home / "results.json"
            command = [binary, "dir", str(source), "--config", str(RULES / "gitleaks.toml"), "--ignore-gitleaks-allow", "--gitleaks-ignore-path", str(home / "no-ignore"), "--redact=100", "--report-format", "json", "--report-path", str(report), "--no-banner"]
            execute(command, home, home, options.timeout, accepted=(0, 1))
            findings, partial, details = gitleaks_results(read_json(report), source)
        elif name == "trivy":
            configuration = home / "config.yaml"
            configuration.write_text("{}\n", encoding="utf-8")
            ignore = home / "ignore"
            ignore.write_text("", encoding="utf-8")
            command = [binary, "image" if image else "filesystem", "--format", "json", "--scanners", "vuln,misconfig", "--config", str(configuration), "--ignorefile", str(ignore), "--cache-dir", str(options.cache), "--quiet"]
            if options.no_update:
                command += ["--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan"]
            if image:
                if Path(image).is_file():
                    command += ["--input", str(Path(image).resolve())]
                else:
                    command += ["--image-src", "remote", image]
            else:
                command.append(str(source))
            payload = json.loads(execute(command, home, home, options.timeout))
            findings, partial, details = trivy_results(payload, source, image)
        elif name == "codeql":
            run["build_mode"] = build_mode
            if requires_build_permission and not options.codeql_allow_builds:
                raise ScannerError(f"CodeQL {language} analysis executes project build code. Use --codeql-allow-builds for a trusted target.")
            if language not in options.codeql_info["languages"]:
                raise ScannerError(f"The installed CodeQL bundle has no {language} extractor for this platform.")
            database = home / "database"
            report = home / "results.sarif"
            execute([binary, "database", "create", str(database), "--language", language, "--source-root", str(source), "--build-mode", build_mode], source, home, options.timeout)
            pack = "codeql/" + language + "-queries:codeql-suites/" + language + "-security-extended.qls"
            execute([binary, "database", "analyze", str(database), pack, "--format=sarif-latest", "--output", str(report)], home, home, options.timeout)
            findings, partial, details = sarif_results(read_json(report), source)
        else:
            raise ScannerError("Unknown adapter.")
        for item in findings:
            for observation in item["observations"]:
                observation["scanner_version"] = run["version"]
        run.update(status="partial" if partial else "success", findings=len(findings), details=details)
        if partial:
            run["message"] = "Scanner reported analysis errors; completed findings retained."
    except (ScannerError, OSError, ValueError, KeyError, TypeError, IndexError) as error:
        run.update(status="error", message=str(error) if isinstance(error, ScannerError) else "Scanner output could not be parsed or a required artifact was unavailable. Raw data withheld.")
    run["duration_seconds"] = round(time.monotonic() - started, 3)
    return run, findings
