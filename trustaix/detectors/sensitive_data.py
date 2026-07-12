"""PII and credential-pattern detector."""

import re

from trustaix.models import Finding, RiskLevel


class SensitiveDataDetector:
    _patterns = (
        ("PII-001", "pii", RiskLevel.MEDIUM, r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b", "Email address detected."),
        ("PII-002", "pii", RiskLevel.HIGH, r"\b\d{17}[\dXx]\b", "Chinese resident ID pattern detected."),
        ("PII-003", "pii", RiskLevel.MEDIUM, r"(?<!\d)1[3-9]\d{9}(?!\d)", "Chinese mobile number detected."),
        (
            "SEC-001",
            "secret",
            RiskLevel.CRITICAL,
            r"\bsk-[A-Za-z0-9_-]{16,}\b",
            "API key pattern detected.",
        ),
    )

    def detect(self, text: str, location: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule_id, category, level, pattern, message in self._patterns:
            for match in re.finditer(pattern, text):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category=category,
                        level=level,
                        message=message,
                        evidence=match.group(0),
                        location=location,
                    )
                )
        return findings
