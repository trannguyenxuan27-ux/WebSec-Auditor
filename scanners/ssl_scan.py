"""SSLScanner — TLS version, certificate expiry, weak cipher checks."""
from __future__ import annotations

import datetime
import socket
import ssl
from typing import List
from urllib.parse import urlsplit

from models import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, BaseScanner, Endpoint, Finding

_WEAK_CIPHER_HINTS = ("RC4", "MD5", "DES", "EXPORT", "NULL", "anon", "3DES")


class SSLScanner(BaseScanner):
    name = "ssl"

    def scan(self, endpoint: Endpoint) -> List[Finding]:
        parsed = urlsplit(endpoint.url)
        target = endpoint.base_url()
        if parsed.scheme != "https":
            return [
                Finding(
                    endpoint=target,
                    scanner=self.name,
                    severity=SEVERITY_INFO,
                    title="No TLS (plain HTTP)",
                    evidence=f"Endpoint uses scheme '{parsed.scheme}'.",
                    recommendation="Serve the site over HTTPS with HSTS.",
                )
            ]

        host = parsed.hostname or ""
        port = parsed.port or 443
        findings: List[Finding] = []
        try:
            context = ssl.create_default_context()
            # No custom check_hostname disabling: we want real validation.
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    cipher = ssock.cipher() or ("", "", 0)

                    findings.extend(self._check_version(target, version))
                    findings.extend(self._check_expiry(target, cert))
                    findings.extend(self._check_cipher(target, cipher[0]))
        except ssl.SSLCertVerificationError as exc:
            findings.append(
                Finding(
                    endpoint=target,
                    scanner=self.name,
                    severity=SEVERITY_HIGH,
                    title="Certificate verification failed",
                    evidence=str(exc),
                    recommendation="Replace the certificate with a valid, trusted one.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                Finding(
                    endpoint=target,
                    scanner=self.name,
                    severity=SEVERITY_LOW,
                    title="SSL check failed",
                    evidence=f"{type(exc).__name__}: {exc}",
                    recommendation="Verify the host is reachable on TLS and re-run the scan.",
                )
            )
        return findings

    # -- helpers ----------------------------------------------------------
    def _check_version(self, target: str, version: str) -> List[Finding]:
        ver = (version or "").upper()
        if ver in ("TLSv1", "TLSV1", "SSLv3"):
            return [
                Finding(
                    endpoint=target,
                    scanner=self.name,
                    severity=SEVERITY_MEDIUM,
                    title=f"Deprecated TLS version: {version}",
                    evidence=f"Negotiated protocol version: {version}",
                    recommendation="Disable TLS < 1.2 on the server.",
                )
            ]
        return []

    def _check_expiry(self, target: str, cert: dict) -> List[Finding]:
        not_after = (cert or {}).get("notAfter")
        if not not_after:
            return []
        try:
            expiry = datetime.datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return []
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (expiry - now).days
        if days_left < 0:
            return [
                Finding(
                    endpoint=target,
                    scanner=self.name,
                    severity=SEVERITY_HIGH,
                    title="Certificate expired",
                    evidence=f"notAfter={not_after} ({-days_left} days ago)",
                    recommendation="Renew the TLS certificate immediately.",
                )
            ]
        if days_left < 30:
            return [
                Finding(
                    endpoint=target,
                    scanner=self.name,
                    severity=SEVERITY_MEDIUM,
                    title="Certificate expiring soon",
                    evidence=f"Expires in {days_left} days ({not_after})",
                    recommendation="Renew the TLS certificate before it expires.",
                )
            ]
        return []

    def _check_cipher(self, target: str, cipher_name: str) -> List[Finding]:
        upper = (cipher_name or "").upper()
        if any(hint in upper for hint in _WEAK_CIPHER_HINTS):
            return [
                Finding(
                    endpoint=target,
                    scanner=self.name,
                    severity=SEVERITY_MEDIUM,
                    title="Weak cipher suite negotiated",
                    evidence=f"Cipher: {cipher_name}",
                    recommendation="Disable weak ciphers and prefer ECDHE+AESGCM suites.",
                )
            ]
        return []
