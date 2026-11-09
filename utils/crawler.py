"""Breadth-first web crawler.

Discovers <a href> links and <form> elements from HTML pages and returns
them as a de-duplicated list of Endpoint objects (URL + method + params).
"""
from __future__ import annotations

import collections
import time
from typing import Deque, Dict, List, Set

import requests
from bs4 import BeautifulSoup
from urllib.parse import parse_qsl, urljoin, urlsplit

from models import Endpoint


class Crawler:
    def __init__(
        self,
        max_depth: int = 2,
        max_urls: int = 100,
        timeout: int = 10,
        delay: float = 0.5,
        same_host_only: bool = True,
    ):
        if max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.delay = delay
        self.same_host_only = same_host_only
        self.errors: List[str] = []

    # -- public ----------------------------------------------------------
    def crawl(self, start_url: str) -> List[Endpoint]:
        """BFS-crawl *start_url* and return all unique endpoints found."""
        start_url = start_url.rstrip("/")
        queue: Deque[tuple[str, int]] = collections.deque([(start_url, 0)])
        visited: Set[str] = set()
        endpoints: Dict[str, Endpoint] = {}
        netloc = urlsplit(start_url).netloc

        endpoints[Endpoint(url=start_url, method="GET").key()] = Endpoint(
            url=start_url, method="GET"
        )

        while queue and len(visited) < self.max_urls:
            url, depth = queue.popleft()
            if url in visited:
                continue
            if depth > self.max_depth:
                continue
            visited.add(url)

            html = self._fetch(url)
            if html is None:
                continue

            links, forms = self._parse(html, base=url)

            for link in links:
                ep = self._link_to_endpoint(link)
                if ep is None:
                    continue
                if self.same_host_only and urlsplit(ep.url).netloc != netloc:
                    continue
                key = ep.key()
                if key not in endpoints:
                    endpoints[key] = ep
                clean = ep.url.split("#")[0]
                if clean not in visited and depth + 1 <= self.max_depth:
                    queue.append((clean, depth + 1))

            for form_ep in forms:
                key = form_ep.key()
                if key not in endpoints:
                    endpoints[key] = form_ep

            if self.delay:
                time.sleep(self.delay)

        return sorted(endpoints.values(), key=lambda e: (e.url, e.method))

    # -- internals --------------------------------------------------------
    def _fetch(self, url: str):
        try:
            resp = requests.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code >= 400:
                self.errors.append(f"GET {url} -> HTTP {resp.status_code}")
            return resp.text
        except Exception as exc:  # noqa: BLE001
            self.errors.append(f"GET {url} failed: {exc}")
            return None

    def _parse(self, html: str, base: str):
        soup = BeautifulSoup(html, "lxml")
        links: List[str] = []
        for a in soup.find_all("a", href=True):
            absolute = urljoin(base, a["href"])
            links.append(self._strip_fragment(absolute))

        forms: List[Endpoint] = []
        for form in soup.find_all("form"):
            action = form.get("action") or base
            action = urljoin(base, action).split("#")[0]
            method = (form.get("method") or "GET").upper()
            params = {}
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if name:
                    params[name] = field.get("value") or ""
            forms.append(Endpoint(url=action, method=method, params=params))
        return links, forms

    @staticmethod
    def _strip_fragment(url: str) -> str:
        return url.split("#")[0]

    @staticmethod
    def _link_to_endpoint(url: str):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return None  # skip mailto:, javascript:, etc.
        params = dict(parse_qsl(parts.query, keep_blank_values=True))
        base = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
        return Endpoint(url=base, method="GET", params=params)
