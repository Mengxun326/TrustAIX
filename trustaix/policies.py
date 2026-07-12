"""Risk scoring and enforcement policy."""

from trustaix.models import Action, Finding, RiskLevel

_WEIGHTS = {
    RiskLevel.LOW: 10,
    RiskLevel.MEDIUM: 25,
    RiskLevel.HIGH: 50,
    RiskLevel.CRITICAL: 100,
}


def risk_score(findings: list[Finding]) -> int:
    """Calculate a capped score from independent risk findings."""
    return min(100, sum(_WEIGHTS[finding.level] for finding in findings))


def decide(findings: list[Finding]) -> Action:
    """Map findings to the MVP enforcement action."""
    if any(finding.level is RiskLevel.CRITICAL for finding in findings):
        return Action.BLOCK
    if any(finding.category == "prompt_injection" and finding.level is RiskLevel.HIGH for finding in findings):
        return Action.BLOCK
    if any(finding.category == "content_policy" and finding.level is RiskLevel.HIGH for finding in findings):
        return Action.BLOCK
    if any(finding.category in {"pii", "secret"} for finding in findings):
        return Action.REDACT
    if risk_score(findings) >= 50:
        return Action.REVIEW
    return Action.ALLOW
