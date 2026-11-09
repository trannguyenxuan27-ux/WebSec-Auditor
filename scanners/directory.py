"""DirectoryScanner — probes for sensitive/exposed paths."""
from __future__ import annotations

from typing import Dict, List
from urllib.parse import urljoin, urlsplit

from models import SEVERITY_HIGH, SEVERITY_LOW, BaseScanner, Endpoint, Finding

# path -> (severity, recommendation)
PATHS: Dict[str, tuple[str, str]] = {
    "/admin": (SEVERITY_LOW, "Restrict admin access by IP/VPN/MFA."),
    "/backup.zip": (SEVERITY_HIGH, "Remove backup archives from the web root."),
    "/.git/config": (SEVERITY_HIGH, "Block access to /.git/ — it exposes source code."),
    "/robots.txt": (SEVERITY_LOW, "Review robots.txt for disclosure of private paths."),
    "/.env": (SEVERITY_HIGH, "Block .env files — they often leak secrets."),
    "/config": (SEVERITY_LOW, "Review config endpoints for sensitive data."),
    "/login": (SEVERITY_LOW, "Ensure authentication is protected (MFA, rate limiting)."),
    "/wp-admin": (SEVERITY_LOW, "Hardening for WordPress admin path."),
}


class DirectoryScanner(BaseScanner):
    name = "dir"

    def scan(self, endpoint: Endpoint) -> List[Finding]:
        import requests

        base = endpoint.base_url()
        parts = urlsplit(base)
        origin = f"{parts.scheme}://{parts.netloc}"
        findings: List[Finding] = []

        for path, (severity, recommendation) in PATHS.items():
            url = urljoin(origin, path)
            self._throttle()
            try:
                resp = requests.get(url, timeout=self.timeout, allow_redirects=False)
            except Exception:  # noqa: BLE001 - skip unreachable paths quietly
                continue

            if resp.status_code == 200:
                title = "Sensitive path exposed" if severity == SEVERITY_HIGH else "Path exists"
                findings.append(
                    Finding(
                        endpoint=url,
                        scanner=self.name,
                        severity=severity,
                        title=f"{title}: {path}",
                        evidence=f"GET {url} -> HTTP 200 ({len(resp.text or '')} bytes)",
                        recommendation=recommendation,
                    )
                )
            elif resp.status_code == 403:
                findings.append(
                    Finding(
                        endpoint=url,
                        scanner=self.name,
                        severity=SEVERITY_LOW,
                        title=f"Path exists but forbidden: {path}",
                        evidence=f"GET {url} -> HTTP 403",
                        recommendation="Confirm access control is intentional.",
                    )
                )
        return findings
