"""Evaluation orchestration."""

from datetime import UTC, datetime
from uuid import uuid4

from trustaix.audit import AuditRepository
from trustaix.config import PolicyProfile, load_policy_from_environment
from trustaix.detectors import ContentPolicyDetector, PromptInjectionDetector, SensitiveDataDetector
from trustaix.models import AuditEvent, EvaluationRequest, EvaluationResult
from trustaix.policies import decide, risk_score


class EvaluationService:
    def __init__(self, audit_repository: AuditRepository, policy: PolicyProfile | None = None) -> None:
        self.audit_repository = audit_repository
        self.policy = policy or load_policy_from_environment()
        self.detectors = (PromptInjectionDetector(), SensitiveDataDetector(), ContentPolicyDetector())

    def evaluate(
        self,
        request: EvaluationRequest,
        tenant_id: str = "default",
        actor_id: str | None = None,
        policy: PolicyProfile | None = None,
        policy_version_id: str | None = None,
    ) -> EvaluationResult:
        policy = policy or self.policy
        findings = []
        for location, text in (("prompt", request.prompt), ("response", request.response)):
            if text.strip():
                for detector in self.detectors:
                    findings.extend(detector.detect(text, location))
        findings = [finding for finding in findings if policy.allows(finding)]

        event = AuditEvent(
            event_id=str(uuid4()),
            request_id=request.request_id,
            action=decide(findings, policy),
            risk_score=risk_score(findings, policy),
            findings=findings,
            evaluated_at=datetime.now(UTC).isoformat(),
            prompt_length=len(request.prompt),
            response_length=len(request.response),
            tenant_id=tenant_id,
            actor_id=actor_id,
            policy_version_id=policy_version_id,
        )
        self.audit_repository.save(event)
        return EvaluationResult(
            **event.model_dump(exclude={"prompt_length", "response_length", "tenant_id", "actor_id", "policy_version_id"})
        )
