"""Heuristic detector for common prompt-injection attempts."""

import re

from trustaix.models import Finding, RiskLevel


class PromptInjectionDetector:
    _patterns = (
        ("PI-001", RiskLevel.HIGH, r"ignore (?:all |any |the )?(?:previous|prior|above) instructions?"),
        ("PI-002", RiskLevel.HIGH, r"(?:reveal|show|print|repeat) (?:the )?(?:system|developer) prompt"),
        ("PI-003", RiskLevel.MEDIUM, r"you are now (?:a|an) (?:unrestricted|different)"),
        ("PI-004", RiskLevel.MEDIUM, r"disregard (?:all |any |the )?(?:rules|instructions|constraints)"),
        ("PI-005", RiskLevel.HIGH, r"忽略(?:之前|先前|以上|所有)?(?:的)?(?:指令|规则|要求)"),
        ("PI-006", RiskLevel.HIGH, r"(?:泄露|显示|输出|重复)(?:系统|开发者)(?:提示词|指令)"),
        ("PI-007", RiskLevel.MEDIUM, r"\b(?:DAN|jailbreak)\b|越狱模式"),
    )

    def detect(self, text: str, location: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule_id, level, pattern in self._patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="prompt_injection",
                        level=level,
                        message="Possible prompt-injection instruction detected.",
                        evidence=match.group(0),
                        location=location,
                    )
                )
        return findings
