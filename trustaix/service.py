"""Evaluation orchestration."""

from datetime import UTC, datetime
from uuid import uuid4

from trustaix.audit import AuditRepository
from trustaix.detectors import ContentPolicyDetector, PromptInjectionDetector, SensitiveDataDetector
from trustaix.models import AuditEvent, EvaluationRequest, EvaluationResult
from trustaix.policies import decide, risk_score


class EvaluationService:
    def __init__(self, audit_repository: AuditRepository) -> None:
        self.audit_repository = audit_repository
        self.detectors = (PromptInjectionDetector(), SensitiveDataDetector(), ContentPolicyDetector())

    def evaluate(self, request: EvaluationRequest) -> EvaluationResult:
        findings = []
        for location, text in (("prompt", request.prompt), ("response", request.response)):
            if text.strip():
                for detector in self.detectors:
                    findings.extend(detector.detect(text, location))

        event = AuditEvent(
            event_id=str(uuid4()),
            request_id=request.request_id,
            action=decide(findings),
            risk_score=risk_score(findings),
            findings=findings,
            evaluated_at=datetime.now(UTC).isoformat(),
            prompt_length=len(request.prompt),
            response_length=len(request.response),
        )
        self.audit_repository.save(event)
        return EvaluationResult(**event.model_dump(exclude={"prompt_length", "response_length"}))
