"""XSSScanner — reflected XSS detection via payload reflection."""
from __future__ import annotations

from typing import List

from models import SEVERITY_HIGH, BaseScanner, Endpoint, Finding

PAYLOADS = [
    "<script>alert(1)</script>",
    "<svg onload=alert(1)>",
    '"><script>alert(1)</script>',
]


class XSSScanner(BaseScanner):
    name = "xss"

    def scan(self, endpoint: Endpoint) -> List[Finding]:
        if not endpoint.params:
            return []

        findings: List[Finding] = []
        for param in endpoint.params:
            for payload in PAYLOADS:
                injected = dict(endpoint.params)
                injected[param] = payload
                resp, err = self._request_with_params(endpoint, injected)
                if resp is None:
                    continue
                body = resp.text or ""
                if payload in body:
                    findings.append(
                        Finding(
                            endpoint=endpoint.full_url(),
                            scanner=self.name,
                            severity=SEVERITY_HIGH,
                            title=f"Reflected XSS in '{param}'",
                            evidence=f"Payload {payload!r} was reflected verbatim in response.",
                            recommendation="Contextually encode output and add CSP.",
                        )
                    )
                    break  # one confirmed payload per param is enough
        return findings
