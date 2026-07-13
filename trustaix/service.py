"""Evaluation orchestration."""

from datetime import UTC, datetime
from collections.abc import Callable
from uuid import uuid4

from trustaix.audit import AuditRepository
from trustaix.config import PolicyProfile, load_policy_from_environment
from trustaix.detectors import (
    CitationDetector,
    ClassifierDetector,
    ContentPolicyDetector,
    PromptInjectionDetector,
    RulePackDetector,
    SensitiveDataDetector,
    load_classifier,
    load_rule_packs,
)
from trustaix.models import AuditEvent, EvaluationRequest, EvaluationResult
from trustaix.policies import decide, risk_score
from trustaix.source_verifier import SourceVerifier


class EvaluationService:
    def __init__(
        self,
        audit_repository: AuditRepository,
        policy: PolicyProfile | None = None,
        on_evaluation: Callable[[str], None] | None = None,
    ) -> None:
        self.audit_repository = audit_repository
        self.policy = policy or load_policy_from_environment()
        self.on_evaluation = on_evaluation
        plugin_detectors = []
        rule_pack = load_rule_packs()
        if rule_pack:
            plugin_detectors.append(RulePackDetector(rule_pack))
        classifier = load_classifier()
        if classifier:
            plugin_detectors.append(ClassifierDetector(classifier))
        self.detectors = (PromptInjectionDetector(), SensitiveDataDetector(), ContentPolicyDetector(), *plugin_detectors)
        self.citation_detector = CitationDetector()
        self.source_verifier = SourceVerifier()

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
        if request.require_citations and request.response.strip():
            findings.extend(self.citation_detector.detect(request.response, "response", request.allowed_sources))
            findings.extend(self.source_verifier.verify(request.response, request.allowed_sources))
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
        if self.on_evaluation:
            self.on_evaluation(event.action.value)
        return EvaluationResult(
            **event.model_dump(exclude={"prompt_length", "response_length", "tenant_id", "actor_id", "policy_version_id"})
        )
