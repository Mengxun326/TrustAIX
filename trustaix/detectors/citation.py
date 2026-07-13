"""Citation presence and allow-list checks for knowledge-grounded responses."""

import re
from urllib.parse import urlparse

from trustaix.models import Finding, RiskLevel


class CitationDetector:
    _url_pattern = re.compile(r"https?://[^\s)\]}>]+", re.IGNORECASE)

    def detect(self, text: str, location: str, allowed_sources: list[str]) -> list[Finding]:
        urls = self._url_pattern.findall(text)
        if not urls:
            return [
                Finding(
                    rule_id="CIT-001", category="citation", level=RiskLevel.HIGH,
                    message="A citation-grounded response was required but no URL citation was found.",
                    evidence="[MISSING_CITATION]", location=location,
                )
            ]
        findings: list[Finding] = []
        for url in urls:
            parsed = urlparse(url)
            if not parsed.netloc:
                findings.append(Finding(rule_id="CIT-002", category="citation", level=RiskLevel.HIGH, message="Malformed URL citation detected.", evidence="[MALFORMED_CITATION]", location=location))
            elif allowed_sources and not any(url.startswith(source.rstrip("/")) for source in allowed_sources):
                findings.append(Finding(rule_id="CIT-003", category="citation", level=RiskLevel.HIGH, message="Citation is outside the allowed source list.", evidence=parsed.netloc, location=location))
        return findings
