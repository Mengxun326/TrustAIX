"""Small JSONL evaluation harness for comparing detector or policy changes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from trustaix.models import Action, EvaluationRequest
from trustaix.service import EvaluationService


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    action_accuracy: float
    false_positive_rate: float
    missed_expected_rules: int


def run_evaluation_set(service: EvaluationService, path: str | Path) -> EvaluationReport:
    """Run JSONL cases: prompt/response, expected_action, expected_rules and safe fields."""
    cases = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if not cases:
        raise ValueError("Evaluation set is empty.")
    correct_actions = false_positives = missed = 0
    for case in cases:
        result = service.evaluate(EvaluationRequest(prompt=case.get("prompt", ""), response=case.get("response", "")))
        expected_action = case.get("expected_action")
        if expected_action is None or result.action.value == expected_action:
            correct_actions += 1
        expected_rules = set(case.get("expected_rules", []))
        actual_rules = {finding.rule_id for finding in result.findings}
        missed += len(expected_rules - actual_rules)
        if case.get("safe", False) and result.action is not Action.ALLOW:
            false_positives += 1
    return EvaluationReport(
        cases=len(cases),
        action_accuracy=correct_actions / len(cases),
        false_positive_rate=false_positives / len(cases),
        missed_expected_rules=missed,
    )
