"""Core data models for WebSec-Auditor.

Shared dataclasses (Endpoint, Finding, ScanResult) and the BaseScanner
ABC that every scanner inherits from.
"""
from __future__ import annotations

import abc
import datetime
import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

VALID_SEVERITIES = {SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO}


@dataclass
class Endpoint:
    """A discoverable URL + method + parameters."""

    url: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.method = (self.method or "GET").upper()

    def full_url(self) -> str:
        if not self.params or self.method.upper() != "GET":
            return self.url
        qs = "&".join(f"{k}={v}" for k, v in self.params.items())
        return f"{self.url}?{qs}" if qs else self.url

    def base_url(self) -> str:
        """Host + scheme + path, without query string."""
        from urllib.parse import urlsplit

        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"

    def key(self) -> str:
        items = sorted(self.params.items())
        return f"{self.method}|{self.url}|{items}"

    def fingerprint(self) -> str:
        return hashlib.sha256(self.key().encode("utf-8")).hexdigest()[:12]


@dataclass
class Finding:
    """One security observation produced by a scanner."""

    endpoint: str
    scanner: str
    severity: str
    title: str
    evidence: str
    recommendation: str

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity!r}")
        self.severity = self.severity.capitalize()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    findings: List[Finding] = field(default_factory=list)
    endpoints_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    scan_type: str = "full"
    metadata: Dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.start_time:
            self.start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def finish(self) -> None:
        self.end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def add_findings(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    def summary(self) -> Dict[str, int]:
        counts = {s: 0 for s in VALID_SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        counts["total"] = len(self.findings)
        counts["endpoints"] = self.endpoints_scanned
        return counts

    def to_dict(self) -> dict:
        return {
            "metadata": {
                "target": self.target,
                "scan_type": self.scan_type,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "endpoints_scanned": self.endpoints_scanned,
                "errors": self.errors,
                "summary": self.summary(),
                "extra": self.metadata,
            },
            "findings": [f.to_dict() for f in self.findings],
        }


class BaseScanner(abc.ABC):
    """Base class for all scanners.

    Subclasses MUST implement ``scan(endpoint)``. The base provides
    rate-limiting + timeout handling so subclasses stay focused on
    detection logic.
    """

    name: str = "base"

    def __init__(self, timeout: int = 10, delay: float = 0.5):
        self.timeout = timeout
        self.delay = delay

    @abc.abstractmethod
    def scan(self, endpoint: Endpoint) -> List[Finding]:
        """Scan one endpoint and return findings (empty if clean)."""
        raise NotImplementedError

    def _throttle(self) -> None:
        if self.delay and self.delay > 0:
            time.sleep(self.delay)

    # -- shared helpers for payload-based scanners -----------------------
    def _request_with_params(self, endpoint: Endpoint, params_override: Dict[str, str]):
        """One HTTP request injecting *params_override* into the endpoint.

        Returns ``(response, error_string)``. Never raises for network issues.
        """
        import requests

        self._throttle()
        try:
            if endpoint.method.upper() == "POST":
                resp = requests.post(
                    endpoint.url,
                    data=params_override,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            else:
                resp = requests.get(
                    endpoint.url,
                    params=params_override,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            return resp, None
        except Exception as exc:  # noqa: BLE001 - never crash the scan
            return None, f"{type(exc).__name__}: {exc}"
