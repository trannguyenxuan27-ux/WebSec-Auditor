"""SQLiScanner — error/difference-based SQL injection detection."""
from __future__ import annotations

import re
from typing import List

from models import SEVERITY_HIGH, SEVERITY_MEDIUM, BaseScanner, Endpoint, Finding

PAYLOADS = ["'", '"', "1' OR '1'='1", "' OR '1'='1'--"]

_SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql|mysqli|sqlite|postgresql|ORA-|ODBC|syntax error|unclosed quotation)",
    re.IGNORECASE,
)


class SQLiScanner(BaseScanner):
    name = "sqli"

    def scan(self, endpoint: Endpoint) -> List[Finding]:
        if not endpoint.params:
            return []  # nothing injectable on this endpoint

        findings: List[Finding] = []
        baseline_resp, baseline_err = self._request_with_params(endpoint, endpoint.params)
        if baseline_resp is None:
            findings.append(
                Finding(
                    endpoint=endpoint.full_url(),
                    scanner=self.name,
                    severity="Low",
                    title="SQLi check failed (baseline unreachable)",
                    evidence=baseline_err or "unknown error",
                    recommendation="Verify target is reachable; re-run the scan.",
                )
            )
            return findings

        baseline_len = len(baseline_resp.text or "")
        baseline_status = baseline_resp.status_code

        for param in endpoint.params:
            for payload in PAYLOADS:
                injected = dict(endpoint.params)
                injected[param] = payload
                resp, err = self._request_with_params(endpoint, injected)
                if resp is None:
                    continue
                body = resp.text or ""
                length_diff = abs(len(body) - baseline_len)
                status_changed = resp.status_code != baseline_status

                if _SQL_ERRORS.search(body):
                    findings.append(
                        Finding(
                            endpoint=endpoint.full_url(),
                            scanner=self.name,
                            severity=SEVERITY_HIGH,
                            title=f"Possible SQL injection (error-based) in '{param}'",
                            evidence=f"Payload {payload!r} produced a database error in response "
                            f"(status {resp.status_code}, len {len(body)} vs baseline {baseline_len}).",
                            recommendation="Validate/sanitise input, use parameterised queries.",
                        )
                    )
                    break  # confirmed for this param, no need to test more payloads
                if length_diff > 200 or status_changed:
                    findings.append(
                        Finding(
                            endpoint=endpoint.full_url(),
                            scanner=self.name,
                            severity=SEVERITY_MEDIUM,
                            title=f"Possible SQL injection (difference-based) in '{param}'",
                            evidence=f"Payload {payload!r} changed response: status "
                            f"{baseline_status}->{resp.status_code}, length {baseline_len}->{len(body)}.",
                            recommendation="Use parameterised queries and test further with a "
                            "dedicated SQLi tool (e.g. sqlmap) on authorised targets.",
                        )
                    )
                    break
        return findings
