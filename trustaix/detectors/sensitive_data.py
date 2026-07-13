"""PII and credential-pattern detector."""

import re

from trustaix.models import Finding, RiskLevel


class SensitiveDataDetector:
    _patterns = (
        (
            "PII-001",
            "pii",
            RiskLevel.MEDIUM,
            r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
            "Email address detected.",
            "[REDACTED_EMAIL]",
        ),
        (
            "PII-002",
            "pii",
            RiskLevel.HIGH,
            r"\b\d{17}[\dXx]\b",
            "Chinese resident ID pattern detected.",
            "[REDACTED_CHINESE_ID]",
        ),
        (
            "PII-003",
            "pii",
            RiskLevel.MEDIUM,
            r"(?<!\d)1[3-9]\d{9}(?!\d)",
            "Chinese mobile number detected.",
            "[REDACTED_MOBILE]",
        ),
        (
            "SEC-001",
            "secret",
            RiskLevel.CRITICAL,
            r"\bsk-[A-Za-z0-9_-]{16,}\b",
            "API key pattern detected.",
            "[REDACTED_API_KEY]",
        ),
    )

    def detect(self, text: str, location: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule_id, category, level, pattern, message, replacement in self._patterns:
            for match in re.finditer(pattern, text):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category=category,
                        level=level,
                        message=message,
                        evidence=replacement,
                        location=location,
                    )
                )
        return findings

    def redact(self, text: str) -> str:
        """Remove values matched by the detector while preserving useful context."""
        for _, _, _, pattern, _, replacement in self._patterns:
            text = re.sub(pattern, replacement, text)
        return text
