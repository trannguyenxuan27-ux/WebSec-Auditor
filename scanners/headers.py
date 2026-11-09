"""HeaderScanner — checks for missing security headers."""
from __future__ import annotations

from typing import Dict, List

from models import SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM, BaseScanner, Endpoint, Finding

# header name -> (severity, recommendation)
_REQUIRED: Dict[str, tuple[str, str]] = {
    "Content-Security-Policy": (
        SEVERITY_MEDIUM,
        "Add a Content-Security-Policy header to mitigate XSS.",
    ),
    "X-Frame-Options": (
        SEVERITY_MEDIUM,
        "Add X-Frame-Options (or frame-ancestors in CSP) to prevent clickjacking.",
    ),
    "Strict-Transport-Security": (
        SEVERITY_MEDIUM,
        "Add Strict-Transport-Security when serving over HTTPS.",
    ),
    "X-Content-Type-Options": (
        SEVERITY_LOW,
        "Add X-Content-Type-Options: nosniff to block MIME sniffing.",
    ),
}


class HeaderScanner(BaseScanner):
    name = "headers"

    def scan(self, endpoint: Endpoint) -> List[Finding]:
        import requests

        self._throttle()
        # Headers should be checked without injected params.
        target = endpoint.base_url()
        try:
            resp = requests.get(target, timeout=self.timeout, allow_redirects=False)
        except Exception as exc:  # noqa: BLE001
            return [
                Finding(
                    endpoint=target,
                    scanner=self.name,
                    severity=SEVERITY_LOW,
                    title="Could not fetch for header check",
                    evidence=f"{type(exc).__name__}: {exc}",
                    recommendation="Investigate connectivity / allow the target host.",
                )
            ]

        findings: List[Finding] = []
        present = {k.lower() for k in resp.headers}
        for header, (severity, recommendation) in _REQUIRED.items():
            if header.lower() not in present:
                findings.append(
                    Finding(
                        endpoint=target,
                        scanner=self.name,
                        severity=severity,
                        title=f"Missing {header}",
                        evidence=f"Response headers contained: {sorted(resp.headers)}",
                        recommendation=recommendation,
                    )
                )
        if "server" in present:
            server = resp.headers.get("Server", "")
            if server:
                findings.append(
                    Finding(
                        endpoint=target,
                        scanner=self.name,
                        severity="Low",
                        title="Server header discloses version",
                        evidence=f"Server: {server}",
                        recommendation="Remove or minimise the Server header.",
                    )
                )
        return findings
