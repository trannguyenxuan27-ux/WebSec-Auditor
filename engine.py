"""Scan engine — orchestrates crawler + scanners (optionally in parallel)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from models import Finding, ScanResult
from scanners.directory import DirectoryScanner
from scanners.headers import HeaderScanner
from scanners.sqli import SQLiScanner
from scanners.ssl_scan import SSLScanner
from scanners.xss import XSSScanner
from utils.crawler import Crawler

SCANNER_REGISTRY = {
    "headers": HeaderScanner,
    "sqli": SQLiScanner,
    "xss": XSSScanner,
    "ssl": SSLScanner,
    "dir": DirectoryScanner,
}

QUICK_SCANNERS = ["headers", "ssl", "dir"]


@dataclass
class ScanConfig:
    target: str
    scan_type: str = "full"
    max_depth: int = 2
    max_urls: int = 100
    timeout: int = 10
    threads: int = 5
    delay: float = 0.5
    enabled_scanners: Optional[List[str]] = None  # None = use scan_type mapping


def resolve_scanner_names(config: ScanConfig) -> List[str]:
    if config.enabled_scanners:
        return [s for s in config.enabled_scanners if s in SCANNER_REGISTRY]
    if config.scan_type in SCANNER_REGISTRY:
        return [config.scan_type]
    if config.scan_type == "quick":
        return list(QUICK_SCANNERS)
    return list(SCANNER_REGISTRY.keys())  # full


class AuditEngine:
    def __init__(self, config: ScanConfig, on_progress: Optional[Callable[[str], None]] = None):
        self.config = config
        self.on_progress = on_progress or (lambda msg: print(msg))

    def run(self) -> ScanResult:
        cfg = self.config
        result = ScanResult(target=cfg.target, scan_type=cfg.scan_type)
        self.on_progress(f"[+] Target: {cfg.target} (scan-type={cfg.scan_type})")

        # 1. Crawl ------------------------------------------------------
        self.on_progress(f"[+] Crawling (max_depth={cfg.max_depth}, max_urls={cfg.max_urls})...")
        crawler = Crawler(
            max_depth=cfg.max_depth,
            max_urls=cfg.max_urls,
            timeout=cfg.timeout,
            delay=cfg.delay,
        )
        endpoints = crawler.crawl(cfg.target)
        result.errors.extend(crawler.errors)
        self.on_progress(f"[+] Found {len(endpoints)} endpoint(s)")

        # 2. Build scanner instances ------------------------------------
        names = resolve_scanner_names(cfg)
        scanners = [
            SCANNER_REGISTRY[n](timeout=cfg.timeout, delay=cfg.delay) for n in names
        ]
        self.on_progress(f"[+] Scanners enabled: {', '.join(names)}")

        # 3. Scan --------------------------------------------------------
        # Header/SSL/Dir scanners are host-level checks: running them once
        # per origin avoids duplicate findings on every parameterized URL.
        jobs = []  # list of (scanner, endpoint)
        seen_origin_scans: set[str] = set()
        for ep in endpoints:
            for scanner in scanners:
                if scanner.name in ("headers", "ssl", "dir"):
                    key = f"{scanner.name}|{ep.base_url()}"
                    if key in seen_origin_scans:
                        continue
                    seen_origin_scans.add(key)
                jobs.append((scanner, ep))

        result.endpoints_scanned = len(endpoints)
        self.on_progress(f"[+] Scanning {len(jobs)} (endpoint, scanner) job(s)...")

        findings = self._run_jobs(jobs)

        # Dedup: same scanner + endpoint + title (keep first)
        seen: set[str] = set()
        unique: List[Finding] = []
        for f in findings:
            key = f"{f.scanner}|{f.endpoint}|{f.title}|{f.evidence[:80]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        result.add_findings(unique)
        result.finish()
        summary = result.summary()
        self.on_progress(
            f"[+] Done. Findings: {summary['total']} "
            f"(High={summary.get('High', 0)}, Medium={summary.get('Medium', 0)}, "
            f"Low={summary.get('Low', 0)}, Info={summary.get('Info', 0)})"
        )
        return result

    # -- internals --------------------------------------------------------
    def _run_jobs(self, jobs):
        findings: List[Finding] = []
        if self.config.threads and self.config.threads > 1 and len(jobs) > 1:
            with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
                future_map = {
                    pool.submit(self._safe_scan, scanner, ep): (scanner, ep)
                    for scanner, ep in jobs
                }
                for fut in as_completed(future_map):
                    findings.extend(fut.result())
        else:
            for scanner, ep in jobs:
                findings.extend(self._safe_scan(scanner, ep))
        return findings

    def _safe_scan(self, scanner, endpoint):
        self.on_progress(
            f"  [-] [{scanner.name}] {endpoint.method} {endpoint.full_url()}"
        )
        try:
            return scanner.scan(endpoint)
        except Exception as exc:  # noqa: BLE001 - one scanner must not kill the run
            self.on_progress(f"  [!] {scanner.name} error on {endpoint.url}: {exc}")
            return []


def run_scan(
    target: str,
    scan_type: str = "full",
    max_depth: int = 2,
    timeout: int = 10,
    threads: int = 5,
    delay: float = 0.5,
) -> ScanResult:
    """Convenience wrapper used by CLI and tests."""
    config = ScanConfig(
        target=target,
        scan_type=scan_type,
        max_depth=max_depth,
        timeout=timeout,
        threads=threads,
        delay=delay,
    )
    return AuditEngine(config).run()
