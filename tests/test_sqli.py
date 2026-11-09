"""SQLiScanner tests (mocked HTTP)."""
import unittest
from unittest.mock import MagicMock, patch

from models import Endpoint
from scanners.sqli import SQLiScanner


def _resp(text, status=200):
    r = MagicMock()
    r.text = text
    r.status_code = status
    return r


class TestSQLiScanner(unittest.TestCase):
    def test_error_based_detection(self):
        baseline = _resp("results page, len ok .......")
        err = _resp("You have an error in your SQL syntax; check the manual ...")
        with patch.object(SQLiScanner, "_request_with_params") as req:
            req.side_effect = [(baseline, None), (err, None)]
            findings = SQLiScanner(delay=0).scan(
                Endpoint(url="http://x.test/search", method="GET", params={"q": "x"})
            )
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "High")
        self.assertIn("SQL", findings[0].title)

    def test_no_params_no_findings(self):
        findings = SQLiScanner(delay=0).scan(Endpoint(url="http://x.test/"))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
