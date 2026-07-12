"""Small, conservative example content-policy detector."""

import re

from trustaix.models import Finding, RiskLevel


class ContentPolicyDetector:
    _patterns = (
        ("CP-001", RiskLevel.HIGH, r"\bhow to (?:make|build) (?:a )?bomb\b"),
        ("CP-002", RiskLevel.HIGH, r"\b(?:buy|sell) (?:illegal )?(?:drugs|weapons)\b"),
    )

    def detect(self, text: str, location: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule_id, level, pattern in self._patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="content_policy",
                        level=level,
                        message="Content matches a restricted-policy pattern.",
                        evidence=match.group(0),
                        location=location,
                    )
                )
        return findings
