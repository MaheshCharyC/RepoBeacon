from html.parser import HTMLParser
import unittest

from repobeacon.core import finding
from repobeacon.report_html import render_html


class Structure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.anchors = []
        self.scripts = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "a" and attrs.get("href", "").startswith("#"):
            self.anchors.append(attrs["href"][1:])
        if tag == "script" or any(name.startswith("on") for name in attrs):
            self.scripts.append((tag, attrs))


class ReportHTMLTests(unittest.TestCase):
    def assessment(self, findings=(), complete=True):
        return {"target": {"path": "/project/example"}, "created_at": "2026-09-20T02:06:48+00:00", "findings": list(findings), "scanner_runs": [], "coverage": {}, "policy_result": {"execution_status": "complete" if complete else "incomplete", "policy_status": "pass"}}

    def test_all_severities_and_internal_links(self):
        findings = [finding("test", "rule", level + " issue", level, "sast", "app.py") for level in ("critical", "high", "medium", "low", "info", "unknown")]
        document = render_html(self.assessment(findings))
        parsed = Structure()
        parsed.feed(document)
        self.assertEqual(len(parsed.ids), len(set(parsed.ids)))
        self.assertTrue(set(parsed.anchors).issubset(set(parsed.ids)))
        self.assertEqual(parsed.scripts, [])
        self.assertEqual(sum(identifier.startswith("finding-") for identifier in parsed.ids), 6)
        self.assertIn("20 Sep 2026 · 02:06 UTC", document)

    def test_empty_incomplete_assessment_does_not_claim_success(self):
        document = render_html(self.assessment(complete=False))
        self.assertIn("Assessment incomplete", document)
        self.assertIn("No findings reported", document)
        self.assertNotIn("Assessment passed", document)
        self.assertNotIn("conic-gradient()", document)
        parsed = Structure()
        parsed.feed(document)
        self.assertTrue(set(parsed.anchors).issubset(set(parsed.ids)))

    def test_untrusted_fields_remain_text(self):
        payload = '<script>alert(1)</script><img src=x onerror="alert(2)">'
        item = finding("test", payload, payload, "high", "sast", payload)
        item["remediation"] = payload
        item["package"] = {"name": payload, "version": payload, "ecosystem": payload}
        item["ai_enrichment"] = {"explanation": payload, "remediation": payload}
        assessment = self.assessment([item])
        assessment["target"]["path"] = payload
        assessment["coverage"]["notes"] = [payload]
        assessment["scanner_runs"] = [{"scanner": payload, "status": payload, "version": payload, "message": payload}]
        document = render_html(assessment)
        parsed = Structure()
        parsed.feed(document)
        self.assertFalse(parsed.scripts)
        self.assertNotIn(payload, document)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", document)
        self.assertIn("AI suggestion · unverified", document)


if __name__ == "__main__":
    unittest.main()
