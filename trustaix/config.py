"""Configuration loading for TrustAIX risk policies."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from trustaix.models import Finding, RiskLevel

_LEVEL_RANK = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


@dataclass(frozen=True)
class PolicyProfile:
    """The risk policy applied to each evaluation."""

    enabled_rules: frozenset[str] | None = None
    weights: dict[RiskLevel, int] | None = None
    review_score: int = 50
    redact_categories: frozenset[str] = frozenset({"pii", "secret"})
    block_critical: bool = True
    block_categories: frozenset[str] = frozenset({"prompt_injection", "content_policy"})
    block_minimum_level: RiskLevel = RiskLevel.HIGH

    def __post_init__(self) -> None:
        if not 0 <= self.review_score <= 100:
            raise ValueError("enforcement.review_score must be between 0 and 100.")

    def allows(self, finding: Finding) -> bool:
        return self.enabled_rules is None or finding.rule_id in self.enabled_rules

    def at_least(self, level: RiskLevel, minimum: RiskLevel) -> bool:
        return _LEVEL_RANK[level] >= _LEVEL_RANK[minimum]

    def public_dict(self) -> dict[str, Any]:
        return {
            "enabled_rules": sorted(self.enabled_rules) if self.enabled_rules is not None else "all",
            "weights": {level.value: value for level, value in (self.weights or {}).items()},
            "review_score": self.review_score,
            "redact_categories": sorted(self.redact_categories),
            "block_critical": self.block_critical,
            "block_categories": sorted(self.block_categories),
            "block_minimum_level": self.block_minimum_level.value,
        }


DEFAULT_WEIGHTS = {
    RiskLevel.LOW: 10,
    RiskLevel.MEDIUM: 25,
    RiskLevel.HIGH: 50,
    RiskLevel.CRITICAL: 100,
}
DEFAULT_POLICY = PolicyProfile(weights=DEFAULT_WEIGHTS)


def load_policy_profile(path: str | Path) -> PolicyProfile:
    """Load and validate a YAML policy file."""
    with Path(path).open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream) or {}
    if not isinstance(document, dict):
        raise ValueError("Policy configuration must be a YAML mapping.")

    rules = _mapping(document, "rules")
    scoring = _mapping(document, "scoring")
    enforcement = _mapping(document, "enforcement")
    block = _mapping(enforcement, "block")

    enabled = rules.get("enabled")
    if enabled is not None and (not isinstance(enabled, list) or not all(isinstance(rule, str) for rule in enabled)):
        raise ValueError("rules.enabled must be a list of rule IDs or null.")

    weights = {
        level: _integer(scoring.get(level.value, DEFAULT_WEIGHTS[level]), f"scoring.{level.value}")
        for level in RiskLevel
    }
    if any(weight < 0 for weight in weights.values()):
        raise ValueError("Risk weights must be non-negative.")

    minimum_level = _risk_level(block.get("minimum_level", RiskLevel.HIGH.value))
    return PolicyProfile(
        enabled_rules=frozenset(enabled) if enabled is not None else None,
        weights=weights,
        review_score=_integer(enforcement.get("review_score", 50), "enforcement.review_score"),
        redact_categories=_string_set(enforcement.get("redact_categories", ["pii", "secret"])),
        block_critical=_boolean(block.get("critical", True), "enforcement.block.critical"),
        block_categories=_string_set(block.get("categories", ["prompt_injection", "content_policy"])),
        block_minimum_level=minimum_level,
    )


def load_policy_from_environment() -> PolicyProfile:
    path = os.getenv("TRUSTAIX_POLICY_PATH")
    return load_policy_profile(path) if path else DEFAULT_POLICY


def _mapping(document: dict[str, Any], name: str) -> dict[str, Any]:
    value = document.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a YAML mapping.")
    return value


def _integer(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer.")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean.")
    return value


def _string_set(value: Any) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("Policy category lists must contain strings only.")
    return frozenset(value)


def _risk_level(value: Any) -> RiskLevel:
    try:
        return RiskLevel(value)
    except ValueError as error:
        allowed = ", ".join(level.value for level in RiskLevel)
        raise ValueError(f"block.minimum_level must be one of: {allowed}.") from error
