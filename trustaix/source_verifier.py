"""Bounded, SSRF-aware retrieval used to verify URL-backed model claims."""

from __future__ import annotations

import ipaddress
import re
import time
from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx

from trustaix.models import Finding, RiskLevel


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def text(self) -> str:
        return " ".join(self.parts)


class SourceVerifier:
    """Fetch cited public pages and check whether answer claims have textual support.

    This is deliberately conservative: it neither treats a URL as proof nor attempts to
    resolve local/private addresses. A failed retrieval becomes a review signal rather
    than silently accepting an unverifiable citation.
    """

    _url_pattern = re.compile(r"https?://[^\s)\]}>]+", re.IGNORECASE)
    _claim_pattern = re.compile(r"[^.!?。！？\n]+")
    _token_pattern = re.compile(r"[\w-]{3,}", re.UNICODE)

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = 4.0,
        cache_ttl_seconds: int = 600,
    ) -> None:
        self.transport = transport
        self.timeout_seconds = timeout_seconds
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, tuple[float, str]] = {}

    def verify(self, response_text: str, allowed_sources: list[str] | None = None) -> list[Finding]:
        allowed_sources = allowed_sources or []
        urls = self._url_pattern.findall(response_text)
        if not urls:
            return []
        source_texts: list[str] = []
        findings: list[Finding] = []
        for url in dict.fromkeys(urls):
            try:
                source_texts.append(self._fetch_text(url, allowed_sources))
            except ValueError as error:
                findings.append(self._finding("CIT-004", str(error), "[UNVERIFIABLE_SOURCE]"))
            except httpx.HTTPError:
                findings.append(
                    self._finding("CIT-004", "Citation source could not be retrieved.", "[UNREACHABLE_SOURCE]")
                )
        if source_texts:
            combined_source = " ".join(source_texts).lower()
            for claim in self._claims(response_text):
                if not self._claim_supported(claim, combined_source):
                    findings.append(
                        self._finding(
                            "CIT-005",
                            "A factual claim is not textually supported by the retrieved citation.",
                            claim[:160],
                        )
                    )
        return findings

    def _fetch_text(self, url: str, allowed_sources: list[str]) -> str:
        if not self._safe_url(url):
            raise ValueError("Citation URL is not eligible for retrieval.")
        if allowed_sources and not any(url.startswith(source.rstrip("/")) for source in allowed_sources):
            raise ValueError("Citation URL is outside the allowed source list.")
        cached = self._cache.get(url)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        with httpx.Client(
            timeout=self.timeout_seconds,
            transport=self.transport,
            follow_redirects=True,
            headers={"User-Agent": "TrustAIX-SourceVerifier/0.1"},
        ) as client:
            response = client.get(url)
            response.raise_for_status()
        if not self._safe_url(str(response.url)):
            raise ValueError("Citation redirected to an ineligible URL.")
        content_type = response.headers.get("content-type", "").lower()
        if content_type and not any(kind in content_type for kind in ("text/", "application/json")):
            raise ValueError("Citation content is not textual.")
        text = self._to_text(response.text[:250_000])
        if not text.strip():
            raise ValueError("Citation source did not contain readable text.")
        self._cache[url] = (time.monotonic() + self.cache_ttl_seconds, text)
        return text

    @staticmethod
    def _safe_url(url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return False
        host = parsed.hostname.lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return True
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)

    @staticmethod
    def _to_text(body: str) -> str:
        parser = _TextExtractor()
        parser.feed(body)
        return re.sub(r"\s+", " ", parser.text()).strip()

    def _claims(self, response_text: str) -> list[str]:
        without_urls = self._url_pattern.sub("", response_text)
        return [claim.strip() for claim in self._claim_pattern.findall(without_urls) if len(claim.strip()) >= 12]

    def _claim_supported(self, claim: str, source_text: str) -> bool:
        tokens = {token.lower() for token in self._token_pattern.findall(claim)}
        meaningful = {token for token in tokens if not token.isdigit()}
        if not meaningful:
            return True
        overlap = sum(token in source_text for token in meaningful)
        return overlap >= min(2, len(meaningful))

    @staticmethod
    def _finding(rule_id: str, message: str, evidence: str) -> Finding:
        return Finding(
            rule_id=rule_id,
            category="citation",
            level=RiskLevel.HIGH,
            message=message,
            evidence=evidence,
            location="response",
        )
