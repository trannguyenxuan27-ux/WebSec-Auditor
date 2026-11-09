"""Engine test (mocked crawler + scanner)."""
import unittest
from unittest.mock import patch

from engine import AuditEngine, ScanConfig
from models import SEVERITY_HIGH, Endpoint, Finding


class TestEngine(unittest.TestCase):
    def test_engine_aggregates_findings(self):
        endpoint = Endpoint(url="http://x.test/search", method="GET", params={"q": "a"})
        finding = Finding(
            endpoint=endpoint.full_url(),
            scanner="xss",
            severity=SEVERITY_HIGH,
            title="Reflected XSS",
            evidence="payload reflected",
            recommendation="Encode output.",
        )
        config = ScanConfig(target="http://x.test", scan_type="xss", threads=1, delay=0)
        engine = AuditEngine(config, on_progress=lambda msg: None)

        fake_scanner_class = lambda **kwargs: (
            type("Fake", (), {"name": "xss", "scan": lambda self, ep: [finding]})()
        )
        with patch("engine.Crawler") as CrawlerCls, \
             patch.dict("engine.SCANNER_REGISTRY", {"xss": fake_scanner_class}):
            CrawlerCls.return_value.crawl.return_value = [endpoint]
            CrawlerCls.return_value.errors = []

            result = engine.run()

        self.assertEqual(result.endpoints_scanned, 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, "High")
        self.assertEqual(result.summary()["total"], 1)

    def test_quick_scan_does_not_use_sqli(self):
        from engine import resolve_scanner_names

        names = resolve_scanner_names(ScanConfig(target="http://x.test", scan_type="quick"))
        self.assertEqual(names, ["headers", "ssl", "dir"])


if __name__ == "__main__":
    unittest.main()
