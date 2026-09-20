from collections import Counter
import json
from urllib.parse import quote

from .report_html import render_html


def sarif(assessment):
    results = []
    rules = {}
    for item in assessment["findings"]:
        observation = item["observations"][0]
        rule = observation["scanner"] + "/" + observation["rule_id"]
        rules[rule] = {"id": rule, "shortDescription": {"text": item["title"]}}
        location = item["locations"][0]
        result = {"ruleId": rule, "level": "error" if item["severity"] in {"high", "critical"} else "warning" if item["severity"] in {"medium", "unknown"} else "note", "message": {"text": item["title"]}, "partialFingerprints": {"repobeacon/v1": item["fingerprint"]}, "properties": {"category": item["category"], "severity": item["severity"]}}
        if item["category"] != "container":
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": quote(location["path"], safe="/"), "uriBaseId": "%SRCROOT%"}, "region": {"startLine": location["start_line"]}}}]
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "RepoBeacon", "version": "0.1.0", "rules": list(rules.values())}}, "invocations": [{"executionSuccessful": assessment["policy_result"]["execution_status"] == "complete"}], "results": results}]}


def write_reports(assessment, output):
    output.mkdir(parents=True, mode=0o700)
    policy = assessment["policy_result"]
    findings = assessment["findings"]
    counts = dict(Counter(item["severity"] for item in findings))
    assessment["summary"] = {"unique_findings": len(findings), "by_severity": counts}
    executive = ["# RepoBeacon security assessment", "", f"Target: {assessment['target']['path']}", f"Date: {assessment['created_at']}", f"Execution: {policy['execution_status']} · Policy: {policy['policy_status']}", f"Findings: {len(findings)} · Severity counts: {json.dumps(counts, sort_keys=True)}", "", "## Coverage", ""]
    for run in assessment["scanner_runs"]:
        executive.append(f"- {run['scanner']}: {run['status']} — {run.get('message', '')}")
    executive += ["", "Scope is limited to the recorded checks. No finding count proves security. Review coverage gaps and exclusions before accepting this assessment.", "", "## Next actions", "", "Review exposed credentials first, then high-severity issues and deployment context. Assign owners, remediate, and rescan. AI suggestions require human review."]
    technical = ["# Technical findings", ""]
    for item in findings:
        location = item["locations"][0]
        technical += [f"## {item['id']} · {item['severity'].upper()}", "", item["title"], "", f"Location: {location['path']}:{location['start_line']}", f"Category: {item['category']} · Baseline: {item['baseline_state']}", "", item["remediation"], ""]
        ai = item.get("ai_enrichment")
        if ai:
            technical += ["AI suggestion (unverified): " + ai["explanation"], ai["remediation"], ""]
    document = render_html(assessment)
    artifacts = {"findings.json": json.dumps(assessment, indent=2), "coverage.json": json.dumps(assessment["coverage"], indent=2), "scan-manifest.json": json.dumps({key: value for key, value in assessment.items() if key != "findings"}, indent=2), "findings.sarif": json.dumps(sarif(assessment), indent=2), "index.html": document, "executive-summary.md": "\n".join(executive), "technical-report.md": "\n".join(technical)}
    for name, content in artifacts.items():
        path = output / name
        with path.open("x", encoding="utf-8") as handle:
            handle.write(content + "\n")
        path.chmod(0o600)
