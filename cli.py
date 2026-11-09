#!/usr/bin/env python3
"""WebSec-Auditor CLI.

Only use this tool on systems you own or have explicit written permission
to test. Unauthorised scanning may be illegal.
"""
from __future__ import annotations

import argparse
import sys

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init()
    _C = Fore
    _S = Style
except ImportError:  # colorama is optional
    class _C:  # minimal shim
        GREEN = CYAN = YELLOW = RED = ""

    class _S:
        RESET_ALL = ""

from engine import AuditEngine, ScanConfig
from report.html_report import save_html
from report.json_report import save_json

VALID_SCAN_TYPES = ["full", "quick", "headers", "sqli", "xss", "ssl", "dir"]

ETHICAL_WARNING = (
    f"{_C.YELLOW}[!] WARNING: only scan hosts you own or have explicit "
    f"written permission to test.{_S.RESET_ALL}"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="websec-auditor",
        description="WebSec-Auditor — automated web security auditor (OWASP Top 10).",
    )
    p.add_argument("--url", required=True, help="Target URL, e.g. https://example.com")
    p.add_argument(
        "--scan-type",
        default="full",
        choices=VALID_SCAN_TYPES,
        help="full | quick | headers | sqli | xss | ssl | dir (default: full)",
    )
    p.add_argument("--output", default="json", choices=["json", "html"],
                   help="Report format (default: json)")
    p.add_argument("--output-file", default=None,
                   help="Report path (default: report.json / report.html)")
    p.add_argument("--max-depth", type=int, default=2, help="Crawl depth (default: 2)")
    p.add_argument("--max-urls", type=int, default=100, help="Max URLs to crawl (default: 100)")
    p.add_argument("--timeout", type=int, default=10, help="Per-request timeout seconds (default: 10)")
    p.add_argument("--threads", type=int, default=5, help="Parallel scan threads (default: 5)")
    p.add_argument("--delay", type=float, default=0.5, help="Delay between requests (default: 0.5)")
    p.add_argument("--quiet", action="store_true", help="Suppress progress output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.quiet:
        print(ETHICAL_WARNING)

    output_file = args.output_file or (
        "report.json" if args.output == "json" else "report.html"
    )

    config = ScanConfig(
        target=args.url,
        scan_type=args.scan_type,
        max_depth=args.max_depth,
        max_urls=args.max_urls,
        timeout=args.timeout,
        threads=args.threads,
        delay=args.delay,
    )
    on_progress = (lambda msg: None) if args.quiet else print
    result = AuditEngine(config, on_progress=on_progress).run()

    if args.output == "json":
        save_json(result, output_file)
    else:
        save_html(result, output_file)

    summary = result.summary()
    if not args.quiet:
        print(f"{_C.GREEN}[+] Report written to {output_file}{_S.RESET_ALL}")
        print(
            f"    Total={summary.get('total', 0)} "
            f"High={summary.get('High', 0)} Medium={summary.get('Medium', 0)} "
            f"Low={summary.get('Low', 0)} Info={summary.get('Info', 0)}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
