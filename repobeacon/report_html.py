"""Self-contained, script-free HTML security assessment."""

from collections import Counter
from datetime import datetime
import html
import json
from pathlib import Path


SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
COLORS = {"critical": "#b42346", "high": "#ba3e12", "medium": "#b88408", "low": "#2563b9", "info": "#6650ad", "unknown": "#566373"}
CATEGORIES = {"sast": "Code security", "sca": "Dependencies", "secret": "Exposed secrets", "iac": "Infrastructure", "container": "Containers", "kubernetes": "Kubernetes", "license": "Licenses"}
SCANNERS = {"semgrep": "Semgrep", "gitleaks": "Gitleaks", "trivy": "Trivy", "codeql": "CodeQL"}


def escape(value):
    return html.escape(str(value), quote=True)


def severity(item):
    value = item.get("severity", "unknown")
    return value if value in SEVERITIES else "unknown"


def badge(text, tone):
    return f'<span class="badge {tone}">{escape(text)}</span>'


def finding_card(item, index, expanded=False):
    level = severity(item)
    locations = item.get("locations") or [{"path": "Not available", "start_line": "—"}]
    location = locations[0]
    observations = item.get("observations", [])
    scanners = ", ".join(dict.fromkeys(SCANNERS.get(obs.get("scanner"), obs.get("scanner", "Unknown")) for obs in observations))
    rules = ", ".join(dict.fromkeys(obs.get("rule_id", "") for obs in observations))
    category = CATEGORIES.get(item.get("category"), item.get("category", "Other"))
    package = item.get("package") or {}
    advisories = ", ".join((item.get("identifiers") or {}).get("advisories", []))
    metadata = [("Finding ID", item.get("id", "—")), ("Scanner / rule", scanners + " / " + rules), ("Baseline", item.get("baseline_state", "new"))]
    if package:
        metadata.append(("Installed package", f"{package.get('name', 'Unknown')} {package.get('version', '')} ({package.get('ecosystem', 'unknown')})"))
    if advisories:
        metadata.append(("Advisory", advisories))
    if len(locations) > 1:
        metadata.append(("Additional locations", "; ".join(f"{loc.get('path', '')}:{loc.get('start_line', '')}" for loc in locations[1:])))
    fields = "".join(f"<div><dt>{escape(label)}</dt><dd>{escape(value)}</dd></div>" for label, value in metadata)
    ai = item.get("ai_enrichment")
    ai_html = ""
    if ai:
        ai_html = f'<aside class="ai-note"><h4>AI suggestion · unverified</h4><p>{escape(ai.get("explanation", ""))}</p><p>{escape(ai.get("remediation", ""))}</p></aside>'
    opened = " open" if expanded else ""
    return f'''<details class="finding {level}" id="finding-{index}"{opened}>
<summary>{badge(level.title(), 'severity-badge')}<div class="finding-summary"><h3>{escape(item.get('title', 'Untitled finding'))}</h3>
<p class="finding-location"><code>{escape(location.get('path', ''))}:{escape(location.get('start_line', ''))}</code></p>
<div class="finding-meta"><span>{escape(category)}</span><span>{escape(scanners)}</span><span>{escape(item.get('baseline_state', 'new')).capitalize()}</span></div></div></summary>
<div class="finding-body"><div class="remediation"><h4>Recommended action</h4><p>{escape(item.get('remediation', 'Review and remediate the reported condition.'))}</p></div>
<dl class="finding-data">{fields}</dl>{ai_html}</div></details>'''


def render_html(assessment):
    findings = assessment["findings"]
    counts = Counter(severity(item) for item in findings)
    runs = assessment.get("scanner_runs", [])
    coverage = assessment.get("coverage", {})
    policy = assessment["policy_result"]
    total = len(findings)
    complete = policy.get("execution_status") == "complete"
    passed = policy.get("policy_status") == "pass"
    completed = sum(run.get("status") == "success" for run in runs)
    gated = len(policy.get("failed_finding_ids", []))
    if not complete:
        verdict, verdict_tone = "Assessment incomplete", "incomplete"
        explanation = "Some required checks did not finish successfully. Review scanner coverage before drawing conclusions."
    elif not passed:
        verdict, verdict_tone = "Action required", "fail"
        explanation = f"{gated} findings exceed the configured policy threshold. Review the prioritized findings below." if gated else "Findings exceed the configured policy threshold. Review the prioritized findings below."
    else:
        verdict, verdict_tone = "Assessment passed", "pass"
        explanation = "Completed checks meet the configured finding policy. Review scope and coverage limitations below."
    target = assessment.get("target", {}).get("path", "Unknown target")
    project = str(target).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or str(target)
    raw_date = assessment.get("created_at", "Not recorded")
    try:
        date = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        timestamp = date.strftime("%d %b %Y · %H:%M %z").strip()
        if date.utcoffset() is not None and date.utcoffset().total_seconds() == 0:
            timestamp = date.strftime("%d %b %Y · %H:%M UTC")
    except (ValueError, TypeError):
        timestamp = str(raw_date)
    metrics = "".join(f'<a class="metric {level}" href="#severity-{level if counts[level] else "overview"}"><span class="metric-label"><span class="dot"></span>{level.title()}</span><strong class="metric-value">{counts[level]}</strong><span class="metric-note">{"Needs classification" if level == "unknown" else "findings"}</span></a>' for level in SEVERITIES)
    stops, offset = [], 0.0
    for level in SEVERITIES:
        end = offset + (counts[level] * 100 / total if total else 0)
        if counts[level]:
            stops.append(f"{COLORS[level]} {offset:.4f}% {end:.4f}%")
        offset = end
    gradient = "conic-gradient(" + ",".join(stops) + ")" if total else "#e8eef3"
    legend = "".join(f'<div class="legend-row {level}"><span class="dot"></span><span>{level.title()}</span><strong>{counts[level]}</strong><span class="percent">{counts[level] * 100 / total if total else 0:.0f}%</span></div>' for level in SEVERITIES)
    categories = Counter(item.get("category", "other") for item in findings)
    category_bars = "".join(f'<div class="bar-row"><div class="bar-label"><strong>{escape(CATEGORIES.get(category, category))}</strong><span>{count} findings</span></div><div class="bar-track" aria-hidden="true"><div class="bar-fill" style="--width:{count * 100 / max(categories.values()):.2f}%"></div></div></div>' for category, count in categories.most_common())
    if not category_bars:
        category_bars = '<p class="muted">No findings were reported by the completed checks.</p>'
    scanner_cards = []
    for run in runs:
        name = SCANNERS.get(run.get("scanner"), run.get("scanner", "Unknown"))
        status = run.get("status", "unknown")
        tone = "good" if status == "success" else "neutral" if status == "not_applicable" else "warning"
        language = f' · {escape(run["language"])}' if run.get("language") else ""
        seconds = run.get("duration_seconds")
        duration = f"{seconds:.1f}s" if isinstance(seconds, (float, int)) else "—"
        amount = run.get("findings")
        amount = amount if amount is not None else "—"
        message = f'<p class="scanner-message">{escape(run["message"])}</p>' if run.get("message") else ""
        scanner_cards.append(f'<article class="scanner"><div class="scanner-top"><h3>{escape(name)}</h3>{badge("Complete" if status == "success" else status.replace("_", " ").title(), tone)}</div><p class="scanner-version">{escape(run.get("version") or "Version unavailable")}{language}</p><div class="scanner-facts"><span><strong>{escape(amount)}</strong>findings</span><span><strong>{duration}</strong>runtime</span></div>{message}</article>')
    if not scanner_cards:
        scanner_cards.append('<p class="muted">No scanner runs were recorded.</p>')
    groups = []
    jumps = []
    index = 0
    for level in SEVERITIES:
        if not counts[level]:
            continue
        jumps.append(f'<a href="#severity-{level}">{level.title()} · {counts[level]}</a>')
        cards = []
        for item in findings:
            if severity(item) == level:
                cards.append(finding_card(item, index, expanded=index == 0))
                index += 1
        groups.append(f'<section class="finding-group {level}" id="severity-{level}"><h3 class="group-heading">{level} <span>{counts[level]}</span></h3>{"".join(cards)}</section>')
    if not groups:
        groups.append('<div class="empty-state"><h3>No findings reported</h3><p>Check scanner completion and coverage before interpreting this result.</p></div>')
    files = coverage.get("files")
    file_count = str(len(files)) if isinstance(files, list) else "—"
    exclusions = coverage.get("exclusions")
    excluded = str(len(exclusions)) if isinstance(exclusions, list) else "—"
    languages = ", ".join(coverage.get("languages", [])) or "Not detected"
    notes = "".join(f"<li>{escape(note)}</li>" for note in coverage.get("notes", []))
    styles = (Path(__file__).parent / "templates" / "report.css").read_text(encoding="utf-8")
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{escape(project)} · RepoBeacon security report</title><style>{styles}</style></head><body>
<a class="skip-link" href="#overview">Skip to assessment</a>
<header class="masthead"><div class="shell"><div class="brand-row"><div class="brand"><span class="brand-mark" aria-hidden="true">r</span>RepoBeacon</div><span class="edition">Application security report</span></div>
<div class="hero"><div><p class="eyebrow">Security assessment</p><h1>{escape(project)}</h1><p class="hero-subtitle">A consolidated view of your code, dependencies, and security posture.</p></div><div class="hero-meta">Report generated<strong>{escape(timestamp)}</strong>RepoBeacon {escape(assessment.get('application_version', '0.1.0'))}</div></div></div></header>
<nav class="nav shell" aria-label="Report sections"><a href="#overview">Overview</a><a href="#scanners">Scanner coverage</a><a href="#findings">Findings <span class="muted">({total})</span></a><a class="download" href="findings.json" download>Download JSON ↗</a></nav>
<main class="shell" id="overview"><section aria-label="Assessment outcome" class="verdict {verdict_tone}"><div><div class="verdict-title">{verdict}</div><p>{explanation}</p></div><div class="statuses">{badge('Scan complete' if complete else 'Scan incomplete', 'good' if complete else 'warning')}{badge('Policy passed' if passed else 'Policy failed', 'good' if passed else 'bad')}</div></section>
<section aria-label="Findings by severity" id="severity-overview"><div class="metrics">{metrics}</div></section>
<div class="panels"><section class="panel" aria-labelledby="distribution-title"><div class="panel-head"><h3 id="distribution-title">Severity distribution</h3><span>Unique findings</span></div><div class="severity-chart"><div class="donut" style="--segments:{gradient}" aria-hidden="true"><div class="donut-center"><strong>{total}</strong><span>total findings</span></div></div><div class="legend">{legend}</div></div><p class="panel-foot">{counts['critical'] + counts['high']} critical or high · {counts['unknown']} awaiting severity classification</p></section>
<section class="panel" aria-labelledby="categories-title"><div class="panel-head"><h3 id="categories-title">Where findings occur</h3><span>By category</span></div>{category_bars}<p class="panel-foot">Prioritize using severity, deployment context, and remediation guidance.</p></section></div>
<section class="section" id="scanners"><div class="section-heading"><h2>Scanner coverage</h2><span class="aside">{completed} of {len(runs)} runs completed</span></div><div class="scanner-grid">{''.join(scanner_cards)}</div><div class="scope-strip"><span><strong>{file_count}</strong> files in snapshot</span><span><strong>{excluded}</strong> excluded paths</span><span><strong>Languages</strong> {escape(languages)}</span></div></section>
<section class="section" id="findings"><div class="section-heading findings-header"><div><p class="eyebrow">Review &amp; remediate</p><h2>Prioritized findings</h2><p>Grouped by severity. Expand any finding for remediation and supporting details.</p></div><span class="aside">{total} unique findings</span></div><nav class="jump-links" aria-label="Jump to severity">{''.join(jumps)}</nav>{''.join(groups)}</section>
<details class="coverage-details"><summary>Assessment scope &amp; technical details</summary><p><strong>Target:</strong> <code>{escape(target)}</code></p><ul>{notes}</ul><p>Full snapshot inventory, exclusions, and coverage metadata are available in <a href="coverage.json">coverage.json</a>.</p><details><summary>View coverage metadata</summary><pre>{escape(json.dumps(coverage, indent=2))}</pre></details></details>
<footer class="footer"><p>Generated by RepoBeacon · Findings reflect the recorded checks and snapshot. A passing policy or zero findings does not establish that an application is secure.</p><a href="#overview">Back to overview ↑</a></footer></main></body></html>'''
