"""HeaderScanner tests (mocked HTTP)."""
import unittest
from unittest.mock import MagicMock, patch

from models import Endpoint
from scanners.headers import HeaderScanner


def _resp(headers):
    r = MagicMock()
    r.headers = headers
    r.status_code = 200
    r.text = "<html>ok</html>"
    return r


class TestHeaderScanner(unittest.TestCase):
    def test_missing_headers_reported(self):
        with patch("requests.get", return_value=_resp({})):
            findings = HeaderScanner(delay=0).scan(Endpoint(url="http://x.test/"))
        titles = {f.title for f in findings}
        self.assertIn("Missing Content-Security-Policy", titles)
        self.assertIn("Missing X-Frame-Options", titles)
        self.assertIn("Missing Strict-Transport-Security", titles)
        self.assertIn("Missing X-Content-Type-Options", titles)

    def test_all_present_is_clean(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
        }
        with patch("requests.get", return_value=_resp(headers)):
            findings = HeaderScanner(delay=0).scan(Endpoint(url="http://x.test/"))
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
