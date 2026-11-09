"""XSSScanner tests (mocked HTTP)."""
import unittest
from unittest.mock import MagicMock, patch

from models import Endpoint
from scanners.xss import PAYLOADS, XSSScanner


def _resp(text):
    r = MagicMock()
    r.text = text
    r.status_code = 200
    return r


class TestXSSScanner(unittest.TestCase):
    def test_reflected_payload_flagged(self):
        with patch.object(XSSScanner, "_request_with_params") as req:
            req.return_value = (_resp(f"<div>{PAYLOADS[0]}</div>"), None)
            findings = XSSScanner(delay=0).scan(
                Endpoint(url="http://x.test/search", method="GET", params={"q": "x"})
            )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "High")
        self.assertIn("XSS", findings[0].title)

    def test_encoded_payload_not_flagged(self):
        with patch.object(XSSScanner, "_request_with_params") as req:
            req.return_value = (_resp("safe output"), None)
            findings = XSSScanner(delay=0).scan(
                Endpoint(url="http://x.test/search", method="GET", params={"q": "x"})
            )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
