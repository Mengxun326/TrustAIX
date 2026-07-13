"""FastAPI application for TrustAIX."""

import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from trustaix.audit import AuditRepository
from trustaix.auth import AuthService, Principal, Role, require_roles
from trustaix.config import PolicyProfile, policy_document, policy_from_document
from trustaix.gateway import (
    ChatGatewayService,
    GatewayBlockedError,
    OpenAICompatibleClient,
    UpstreamConfigurationError,
    UpstreamRequestError,
)
from trustaix.models import (
    AuditEvent,
    AuditFeedback,
    ChatCompletionRequest,
    EvaluationRequest,
    EvaluationResult,
    FeedbackRequest,
    PolicyVersionDraftRequest,
)
from trustaix.policy_store import PolicyVersion, PolicyVersionRepository
from trustaix.service import EvaluationService

app = FastAPI(title="TrustAIX", version="0.1.0", description="LLM risk-control gateway")
web_directory = Path(__file__).parent / "web"
app.mount("/static", StaticFiles(directory=web_directory), name="static")
database_path = os.getenv("TRUSTAIX_AUDIT_DB", "trustaix.db")
service = EvaluationService(AuditRepository(database_path))
chat_gateway = ChatGatewayService(service, OpenAICompatibleClient())
auth_service = AuthService.from_environment()
policy_versions = PolicyVersionRepository(database_path)


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(web_directory / "index.html")


def active_policy(principal: Principal) -> tuple[PolicyProfile, PolicyVersion]:
    version = policy_versions.ensure_active(principal.tenant_id, service.policy, principal.key_id)
    return policy_from_document(version.document), version


def version_response(version: PolicyVersion) -> dict[str, object]:
    result = policy_from_document(version.document).public_dict()
    result["version"] = version.public_dict()
    return result


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/evaluate", response_model=EvaluationResult)
def evaluate(
    request: EvaluationRequest,
    principal: Principal = Depends(require_roles(Role.DEVELOPER, Role.ADMIN)),
) -> EvaluationResult:
    policy, version = active_policy(principal)
    return service.evaluate(
        request,
        tenant_id=principal.tenant_id,
        actor_id=principal.key_id,
        policy=policy,
        policy_version_id=version.id,
    )


@app.post("/v1/chat/completions")
def chat_completions(
    request: ChatCompletionRequest,
    principal: Principal = Depends(require_roles(Role.DEVELOPER, Role.ADMIN)),
) -> dict:
    """Evaluate, forward, and re-evaluate a non-streaming chat completion."""
    try:
        policy, version = active_policy(principal)
        return chat_gateway.complete(
            request,
            tenant_id=principal.tenant_id,
            actor_id=principal.key_id,
            policy=policy,
            policy_version_id=version.id,
        )
    except GatewayBlockedError as error:
        raise HTTPException(
            status_code=400,
            detail={
                "message": str(error),
                "code": "trustaix_risk_blocked",
                "trustaix": error.evaluation.model_dump(mode="json"),
            },
        ) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail={"message": str(error)}) from error
    except UpstreamConfigurationError as error:
        raise HTTPException(status_code=503, detail={"message": str(error)}) from error
    except UpstreamRequestError as error:
        raise HTTPException(status_code=502, detail={"message": str(error)}) from error


@app.get("/v1/audit-events", response_model=list[AuditEvent])
def audit_events(
    limit: int = Query(default=50, ge=1, le=100),
    principal: Principal = Depends(require_roles(Role.AUDITOR, Role.ADMIN)),
) -> list[AuditEvent]:
    return service.audit_repository.latest(limit, tenant_id=principal.tenant_id)


@app.get("/v1/analytics")
def analytics(principal: Principal = Depends(require_roles(Role.AUDITOR, Role.ADMIN))) -> dict:
    return service.audit_repository.analytics(tenant_id=principal.tenant_id)


@app.post("/v1/audit-events/{event_id}/feedback", response_model=AuditFeedback)
def add_audit_feedback(
    event_id: str,
    feedback: FeedbackRequest,
    principal: Principal = Depends(require_roles(Role.AUDITOR, Role.ADMIN)),
) -> AuditFeedback:
    saved = service.audit_repository.add_feedback(event_id, feedback, tenant_id=principal.tenant_id)
    if saved is None:
        raise HTTPException(status_code=404, detail={"message": "Audit event was not found."})
    return saved


@app.get("/v1/policy")
def policy(principal: Principal = Depends(require_roles(Role.AUDITOR, Role.ADMIN))) -> dict:
    """Return the active risk-policy settings without exposing any secret values."""
    _, version = active_policy(principal)
    return version_response(version)


@app.put("/v1/policy/review-score")
def update_review_score(
    review_score: int = Query(ge=0, le=100),
    principal: Principal = Depends(require_roles(Role.ADMIN)),
) -> dict:
    active_profile, active_version = active_policy(principal)
    updated = PolicyProfile(
        enabled_rules=active_profile.enabled_rules,
        weights=active_profile.weights,
        review_score=review_score,
        redact_categories=active_profile.redact_categories,
        block_critical=active_profile.block_critical,
        block_categories=active_profile.block_categories,
        block_minimum_level=active_profile.block_minimum_level,
    )
    draft = policy_versions.create_draft(
        principal.tenant_id,
        policy_document(updated),
        principal.key_id,
        f"Set review score to {review_score}",
        active_version.id,
    )
    if not auth_service.enabled:
        policy_versions.submit(draft.id, principal.tenant_id)
        approved = policy_versions.approve(draft.id, principal.tenant_id, principal.key_id)
        return version_response(approved) if approved else version_response(draft)
    return version_response(draft)


@app.get("/v1/policy-versions")
def list_policy_versions(
    principal: Principal = Depends(require_roles(Role.AUDITOR, Role.ADMIN)),
) -> list[dict[str, object]]:
    active_policy(principal)
    return [version.public_dict() for version in policy_versions.list(principal.tenant_id)]


@app.post("/v1/policy-versions")
def create_policy_draft(
    request: PolicyVersionDraftRequest,
    principal: Principal = Depends(require_roles(Role.ADMIN)),
) -> dict[str, object]:
    _, active_version = active_policy(principal)
    draft = policy_versions.create_draft(
        principal.tenant_id, request.document, principal.key_id, request.note, active_version.id
    )
    return draft.public_dict()


@app.post("/v1/policy-versions/{version_id}/submit")
def submit_policy_version(
    version_id: str, principal: Principal = Depends(require_roles(Role.ADMIN))
) -> dict[str, object]:
    version = policy_versions.submit(version_id, principal.tenant_id)
    if version is None:
        raise HTTPException(status_code=409, detail={"message": "Only a draft policy can be submitted."})
    return version.public_dict()


@app.post("/v1/policy-versions/{version_id}/approve")
def approve_policy_version(
    version_id: str, principal: Principal = Depends(require_roles(Role.ADMIN))
) -> dict[str, object]:
    try:
        version = policy_versions.approve(version_id, principal.tenant_id, principal.key_id)
    except ValueError as error:
        raise HTTPException(status_code=409, detail={"message": str(error)}) from error
    if version is None:
        raise HTTPException(status_code=404, detail={"message": "Policy version was not found."})
    return version.public_dict()


@app.post("/v1/policy-versions/{version_id}/rollback")
def rollback_policy_version(
    version_id: str, principal: Principal = Depends(require_roles(Role.ADMIN))
) -> dict[str, object]:
    draft = policy_versions.rollback_draft(version_id, principal.tenant_id, principal.key_id)
    if draft is None:
        raise HTTPException(status_code=404, detail={"message": "Policy version was not found."})
    return draft.public_dict()
