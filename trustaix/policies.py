"""Risk scoring and enforcement policy."""

from trustaix.config import DEFAULT_POLICY, PolicyProfile
from trustaix.models import Action, Finding, RiskLevel


def risk_score(findings: list[Finding], policy: PolicyProfile = DEFAULT_POLICY) -> int:
    """Calculate a capped score from independent risk findings."""
    weights = policy.weights or {}
    return min(100, sum(weights[finding.level] for finding in findings))


def decide(findings: list[Finding], policy: PolicyProfile = DEFAULT_POLICY) -> Action:
    """Map findings to the MVP enforcement action."""
    if policy.block_critical and any(finding.level is RiskLevel.CRITICAL for finding in findings):
        return Action.BLOCK
    if any(
        finding.category in policy.block_categories
        and policy.at_least(finding.level, policy.block_minimum_level)
        for finding in findings
    ):
        return Action.BLOCK
    if any(finding.category in policy.redact_categories for finding in findings):
        return Action.REDACT
    if risk_score(findings, policy) >= policy.review_score:
        return Action.REVIEW
    return Action.ALLOW
