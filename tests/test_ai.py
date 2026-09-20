import io
import json
import unittest
from unittest.mock import patch

from repobeacon.ai import enrich
from repobeacon.core import finding


class AITests(unittest.TestCase):
    def setUp(self):
        self.item = finding("test", "rule", "Potential eval", "high", "sast", "private/path.py")

    def test_valid_response_preserves_authoritative_fields(self):
        payload = {"summaries": [{"finding_id": self.item["id"], "explanation": "Review user input.", "remediation": "Use a parser."}]}
        with patch("repobeacon.ai.request.build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(json.dumps(payload).encode())
            result = enrich([self.item], "local", "http://127.0.0.1:8000/report", "test")
            sent = json.loads(opener.return_value.open.call_args.args[0].data)
        self.assertNotIn("private/path.py", json.dumps(sent))
        self.assertEqual(self.item["severity"], "high")
        self.assertEqual(result["enriched_findings"], 1)

    def test_unknown_finding_rejected_atomically(self):
        payload = {"summaries": [{"finding_id": "invented", "explanation": "x", "remediation": "y"}]}
        with patch("repobeacon.ai.request.build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(json.dumps(payload).encode())
            with self.assertRaises(ValueError):
                enrich([self.item], "local", "http://127.0.0.1:8000/report", "test")
        self.assertIsNone(self.item["ai_enrichment"])

    def test_ai_cannot_supply_severity(self):
        payload = {"summaries": [{"finding_id": self.item["id"], "explanation": "x", "remediation": "y", "severity": "low"}]}
        with patch("repobeacon.ai.request.build_opener") as opener:
            opener.return_value.open.return_value = io.BytesIO(json.dumps(payload).encode())
            with self.assertRaises(ValueError):
                enrich([self.item], "local", "http://127.0.0.1:8000/report", "test")
        self.assertEqual(self.item["severity"], "high")
