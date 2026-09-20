from collections import Counter
import html
import json
from pathlib import Path
from urllib.parse import quote


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
    cards = []
    for item in findings:
        location = item["locations"][0]
        technical += [f"## {item['id']} · {item['severity'].upper()}", "", item["title"], "", f"Location: {location['path']}:{location['start_line']}", f"Category: {item['category']} · Baseline: {item['baseline_state']}", "", item["remediation"], ""]
        ai = item.get("ai_enrichment")
        if ai:
            technical += ["AI suggestion (unverified): " + ai["explanation"], ai["remediation"], ""]
        cards.append("<article><h3>" + html.escape(item["severity"].upper() + " · " + item["title"]) + "</h3><p>" + html.escape(location["path"] + ":" + str(location["start_line"])) + "</p><p>" + html.escape(item["remediation"]) + "</p><small>" + html.escape(item["id"] + " · " + item["category"] + " · " + item["baseline_state"]) + "</small>" + ("<p>AI suggestion (unverified): " + html.escape(ai["explanation"] + " " + ai["remediation"]) + "</p>" if ai else "") + "</article>")
    rows = "".join("<tr><td>" + html.escape(run["scanner"]) + "</td><td>" + html.escape(run["status"]) + "</td><td>" + html.escape(run.get("message", "")) + "</td></tr>" for run in assessment["scanner_runs"])
    document = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'"><title>RepoBeacon assessment</title><style>body{font:16px/1.6 system-ui,sans-serif;margin:40px auto;padding:0 24px;max-width:1050px;color:#15283b;background:#f5f7fa}h1{font-size:36px}article,section{background:white;border:1px solid #cad3dd;border-radius:8px;padding:20px;margin:16px 0}td,th{text-align:left;padding:10px;border-bottom:1px solid #ddd}table{width:100%;border-collapse:collapse}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#34495e}a{color:#124f96}</style></head><body><h1>RepoBeacon</h1>"""
    document += "<section><h2>Executive summary</h2><p>" + html.escape(assessment["target"]["path"]) + "</p><p>Execution: <strong>" + policy["execution_status"] + "</strong> · Policy: <strong>" + policy["policy_status"] + "</strong></p><p>" + str(len(findings)) + " unique findings · " + html.escape(json.dumps(counts, sort_keys=True)) + "</p><p>Scope is limited to the recorded checks. Unknown coverage is not a clean result.</p></section>"
    document += "<section><h2>Scanner coverage</h2><table><thead><tr><th>Scanner</th><th>Status</th><th>Details</th></tr></thead><tbody>" + rows + "</tbody></table><pre>" + html.escape(json.dumps(assessment["coverage"], indent=2)) + "</pre></section><h2>Technical findings</h2>" + ("".join(cards) or "<p>No findings reported. Check coverage before interpreting this result.</p>") + "</body></html>"
    artifacts = {"findings.json": json.dumps(assessment, indent=2), "coverage.json": json.dumps(assessment["coverage"], indent=2), "scan-manifest.json": json.dumps({key: value for key, value in assessment.items() if key != "findings"}, indent=2), "findings.sarif": json.dumps(sarif(assessment), indent=2), "index.html": document, "executive-summary.md": "\n".join(executive), "technical-report.md": "\n".join(technical)}
    for name, content in artifacts.items():
        path = output / name
        with path.open("x", encoding="utf-8") as handle:
            handle.write(content + "\n")
        path.chmod(0o600)
