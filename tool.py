#!/usr/bin/env python3
"""Bulk mailbox provisioner for self-hosted Mailcow.

For legitimate administration of mail servers you own or are authorised to
manage. See the Ethical Note in README.md.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import secrets
import string
import sys
import time
from dataclasses import dataclass
from urllib.parse import quote

import requests
from requests.exceptions import RequestException

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*()-_=+[]{};:,.?"
ALL_CHARS = UPPER + LOWER + DIGITS + SPECIAL


class ProvisioningError(RuntimeError):
    """Raised when the Mailcow API returns an unexpected result."""


@dataclass
class User:
    email: str
    name: str


@dataclass
class Result:
    user: User
    password: str
    status: str
    detail: str = ""


def generate_password(length: int = 16) -> str:
    """Return a random password containing upper, lower, digit and special chars."""
    if length < 4:
        raise ValueError("password length must be at least 4")
    chars = [
        secrets.choice(UPPER),
        secrets.choice(LOWER),
        secrets.choice(DIGITS),
        secrets.choice(SPECIAL),
    ]
    chars.extend(secrets.choice(ALL_CHARS) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class MailServerProvisioner:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        domain: str,
        *,
        timeout: float = 15.0,
        rate_limit: float = 0.25,
        dry_run: bool = False,
        session: requests.Session | None = None,
    ) -> None:
        if not (base_url.startswith("http://") or base_url.startswith("https://")):
            raise ValueError("--url must start with http:// or https://")
        if not domain or not domain.strip():
            raise ValueError("--domain must not be empty")

        self.base_url = base_url.rstrip("/")
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.rate_limit = max(rate_limit, 0.0)
        self.dry_run = dry_run
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "X-API-Key": api_key or "",
                "Accept": "application/json",
                "User-Agent": "mailbox-provisioner/1.0",
            }
        )
        self._last_request = 0.0

    def _throttle(self) -> None:
        if self.rate_limit <= 0:
            return
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request = time.monotonic()

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        self._throttle()
        url = f"{self.base_url}{path}"
        try:
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        except RequestException as exc:
            raise ProvisioningError(f"{method} {url} failed: {exc}") from exc

    @staticmethod
    def _parse_json(response: requests.Response):
        content_type = response.headers.get("Content-Type", "").lower()
        body = response.text or ""
        if "json" not in content_type and body.lstrip().startswith("<"):
            raise ProvisioningError(
                f"Expected JSON but received HTML (HTTP {response.status_code}); "
                "a WAF or reverse proxy may be blocking the API."
            )
        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            snippet = " ".join(body.split())[:160]
            raise ProvisioningError(
                f"Invalid JSON response (HTTP {response.status_code}): {snippet!r}"
            ) from exc

    @staticmethod
    def _raise_on_api_error(payload, email: str) -> None:
        errors: list[str] = []
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "error" or item.get("error"):
                errors.append(str(item.get("msg") or item))
        if errors:
            raise ProvisioningError(f"Mailcow rejected {email}: {'; '.join(errors)}")

    def mailbox_exists(self, email: str) -> bool:
        path = f"/api/v1/get/mailbox/{quote(email, safe='@')}"
        response = self._request("GET", path)
        if response.status_code == 404:
            return False
        payload = self._parse_json(response)
        self._raise_on_api_error(payload, email)
        if response.status_code != 200:
            raise ProvisioningError(
                f"Existence check failed for {email}: HTTP {response.status_code}"
            )
        if isinstance(payload, list):
            return any(isinstance(item, dict) for item in payload)
        if isinstance(payload, dict):
            return bool(payload)
        return bool(payload)

    def create_mailbox(self, user: User, password: str, quota_mb: int = 1024) -> None:
        local_part = user.email.split("@", 1)[0]
        payload = {
            "local_part": local_part,
            "domain": self.domain,
            "name": user.name,
            "password": password,
            "password2": password,
            "quota": str(quota_mb),
            "active": "1",
            "force_pw_update": "0",
            "tls_enforce_in": "0",
            "tls_enforce_out": "0",
        }
        response = self._request("POST", "/api/v1/add/mailbox", json=payload)
        data = self._parse_json(response)
        self._raise_on_api_error(data, user.email)
        if response.status_code >= 400:
            raise ProvisioningError(
                f"Mailcow returned HTTP {response.status_code} for {user.email}"
            )

    def provision(self, user: User, quota_mb: int = 1024) -> Result:
        if self.dry_run:
            return Result(user, generate_password(), "planned", "dry-run: no network calls")
        if self.mailbox_exists(user.email):
            return Result(user, "", "exists", "skipped (idempotent)")
        password = generate_password()
        self.create_mailbox(user, password, quota_mb=quota_mb)
        return Result(user, password, "created")


def load_users(batch_path: str, domain: str) -> list[User]:
    users: list[User] = []
    seen: set[str] = set()
    with open(batch_path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        for lineno, row in enumerate(reader, 1):
            cells = [cell.strip() for cell in row]
            if not any(cells):
                continue
            identity = cells[0]
            if identity.lower() in {"local_part", "username", "email", "user"}:
                continue
            name = cells[1] if len(cells) > 1 and cells[1] else identity
            email = identity if "@" in identity else f"{identity}@{domain}"
            local_part = email.split("@", 1)[0]
            if not local_part or any(ch in local_part for ch in " \t/@:"):
                print(f"warning: skipping invalid row {lineno}: {row}", file=sys.stderr)
                continue
            email = email.lower()
            if email in seen:
                continue
            seen.add(email)
            users.append(User(email=email, name=name))
    return users


def safe_output_path(path: str, base_dir: str | None = None) -> str:
    base = os.path.realpath(base_dir or os.getcwd())
    target = os.path.realpath(os.path.expanduser(path))
    try:
        common = os.path.commonpath([base, target])
    except ValueError as exc:
        raise ProvisioningError(f"Invalid output path: {path}") from exc
    if common != base:
        raise ProvisioningError(f"Refusing to write outside {base}: {target}")
    return target


def write_results(path: str, results: list[Result], base_dir: str | None = None) -> str:
    target = safe_output_path(path, base_dir=base_dir)
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    created = [result for result in results if result.status == "created"]
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["email", "name", "password"])
        for result in created:
            writer.writerow([result.user.email, result.user.name, result.password])
    os.chmod(target, 0o600)
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tool.py",
        description="Provision Mailcow mailboxes in bulk through the admin API.",
    )
    parser.add_argument("--url", required=True, help="Mailcow base URL, e.g. https://mail.lab.local")
    parser.add_argument(
        "--key",
        default=os.environ.get("MAILCOW_API_KEY"),
        help="Mailcow admin API key (or set MAILCOW_API_KEY)",
    )
    parser.add_argument("--domain", required=True, help="Target mail domain, e.g. lab.local")
    parser.add_argument("--batch", required=True, help="CSV file with local_part,name rows")
    parser.add_argument("--out", default="credentials.csv", help="Credential CSV output path")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without network calls")
    parser.add_argument("--quota", type=int, default=1024, help="Mailbox quota in MiB (default: 1024)")
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.25,
        help="Minimum seconds between API requests (default: 0.25)",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.dry_run and not args.key:
        print(
            "error: --key (or MAILCOW_API_KEY) is required unless --dry-run is used",
            file=sys.stderr,
        )
        return 2
    if not os.path.isfile(args.batch):
        print(f"error: batch file not found: {args.batch}", file=sys.stderr)
        return 2

    try:
        users = load_users(args.batch, args.domain)
    except OSError as exc:
        print(f"error: cannot read batch file: {exc}", file=sys.stderr)
        return 2

    if not users:
        print("error: no valid users found in batch file", file=sys.stderr)
        return 1

    try:
        provisioner = MailServerProvisioner(
            args.url,
            args.key,
            args.domain,
            timeout=args.timeout,
            rate_limit=args.rate_limit,
            dry_run=args.dry_run,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    results: list[Result] = []
    failures = 0
    for user in users:
        try:
            result = provisioner.provision(user, quota_mb=args.quota)
        except ProvisioningError as exc:
            failures += 1
            result = Result(user, "", "failed", str(exc))
        results.append(result)

        if result.status == "planned":
            print(f"[dry-run] would create {user.email} ({user.name}) password={result.password}")
        elif result.status == "exists":
            print(f"[skip] {user.email} already exists")
        elif result.status == "created":
            print(f"[ok] created {user.email}")
        else:
            print(f"[fail] {user.email}: {result.detail}", file=sys.stderr)

    created = [result for result in results if result.status == "created"]
    if not args.dry_run and created:
        try:
            target = write_results(args.out, results)
        except (ProvisioningError, OSError) as exc:
            print(f"error: could not write credentials: {exc}", file=sys.stderr)
            return 1
        print(f"Wrote {len(created)} credential(s) to {target} with mode 0600")

    existing = sum(result.status == "exists" for result in results)
    planned = sum(result.status == "planned" for result in results)
    print(
        f"Summary: {len(created)} created, {existing} existing, "
        f"{failures} failed, {planned} planned"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
