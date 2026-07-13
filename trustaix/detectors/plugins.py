"""Extensible rule-pack and classifier adapters for TrustAIX detectors."""

from __future__ import annotations

import importlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml

from trustaix.models import Finding, RiskLevel


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    terms: tuple[str, ...]
    level: RiskLevel
    category: str = "custom"
    message: str = "Custom rule matched configured text."


class ClassifierAdapter(Protocol):
    """Adapter boundary for an ML model hosted locally or by another service."""

    def classify(self, text: str) -> tuple[str, float] | None:
        """Return (label, confidence) or None when the model has no finding."""


class KeywordClassifier:
    """A baseline adapter that makes classifier integration testable without model weights."""

    def __init__(self, labels: dict[str, tuple[str, ...]]) -> None:
        self.labels = labels

    def classify(self, text: str) -> tuple[str, float] | None:
        lower = text.lower()
        for label, terms in self.labels.items():
            if any(term.lower() in lower for term in terms):
                return label, 0.90
        return None


class RulePackDetector:
    def __init__(self, rules: list[RuleDefinition]) -> None:
        self.rules = rules

    def detect(self, text: str, location: str) -> list[Finding]:
        lower = text.lower()
        findings: list[Finding] = []
        for rule in self.rules:
            matching_term = next((term for term in rule.terms if term.lower() in lower), None)
            if matching_term:
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,  # type: ignore[arg-type]
                        level=rule.level,
                        message=rule.message,
                        evidence=matching_term,
                        location=location,  # type: ignore[arg-type]
                    )
                )
        return findings


class ClassifierDetector:
    def __init__(self, adapter: ClassifierAdapter, minimum_confidence: float = 0.80) -> None:
        self.adapter = adapter
        self.minimum_confidence = minimum_confidence

    def detect(self, text: str, location: str) -> list[Finding]:
        result = self.adapter.classify(text)
        if result is None:
            return []
        label, confidence = result
        if confidence < self.minimum_confidence:
            return []
        return [
            Finding(
                rule_id=f"ML-{label.upper().replace('_', '-')}",
                category="custom",
                level=RiskLevel.MEDIUM,
                message=f"Classifier flagged '{label}' with confidence {confidence:.2f}.",
                evidence=f"[CLASSIFIER:{label}:{confidence:.2f}]",
                location=location,  # type: ignore[arg-type]
            )
        ]


def load_rule_packs(paths: str | None = None) -> list[RuleDefinition]:
    configured = paths if paths is not None else os.getenv("TRUSTAIX_RULE_PACKS", "")
    rules: list[RuleDefinition] = []
    for path_text in filter(None, (part.strip() for part in configured.split(","))):
        with Path(path_text).open(encoding="utf-8") as stream:
            document = yaml.safe_load(stream) or {}
        entries = document.get("rules") if isinstance(document, dict) else None
        if not isinstance(entries, list):
            raise ValueError(f"Rule pack {path_text} must contain a rules list.")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Rule pack entries must be mappings.")
            rule_id, terms = entry.get("id"), entry.get("terms")
            if not isinstance(rule_id, str) or not isinstance(terms, list) or not all(isinstance(term, str) for term in terms):
                raise ValueError("Rule pack entries require string id and terms fields.")
            category = entry.get("category", "custom")
            if category not in {"prompt_injection", "pii", "secret", "content_policy", "citation", "custom"}:
                raise ValueError(f"Unsupported rule-pack category: {category}")
            rules.append(
                RuleDefinition(
                    rule_id=rule_id,
                    terms=tuple(terms),
                    level=RiskLevel(entry.get("level", "medium")),
                    category=category,
                    message=str(entry.get("message", "Custom rule matched configured text.")),
                )
            )
    return rules


def load_classifier(path: str | None = None) -> ClassifierAdapter | None:
    """Load an adapter factory using ``package.module:factory`` only when configured."""
    target = path if path is not None else os.getenv("TRUSTAIX_CLASSIFIER_ADAPTER", "")
    if not target:
        return None
    module_name, separator, attribute = target.partition(":")
    if not separator:
        raise ValueError("TRUSTAIX_CLASSIFIER_ADAPTER must use package.module:factory syntax.")
    factory = getattr(importlib.import_module(module_name), attribute)
    adapter = factory()
    if not hasattr(adapter, "classify"):
        raise ValueError("Classifier adapter factory must return an object with classify(text).")
    return adapter
