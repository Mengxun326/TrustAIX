"""FastAPI application for TrustAIX."""

import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from trustaix.audit import AuditRepository
from trustaix.auth import AuthService, Principal, Role, require_roles
from trustaix.config import PolicyProfile, save_policy_profile
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
)
from trustaix.service import EvaluationService

app = FastAPI(title="TrustAIX", version="0.1.0", description="LLM risk-control gateway")
web_directory = Path(__file__).parent / "web"
app.mount("/static", StaticFiles(directory=web_directory), name="static")
service = EvaluationService(AuditRepository(os.getenv("TRUSTAIX_AUDIT_DB", "trustaix.db")))
chat_gateway = ChatGatewayService(service, OpenAICompatibleClient())
auth_service = AuthService.from_environment()


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(web_directory / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/evaluate", response_model=EvaluationResult)
def evaluate(
    request: EvaluationRequest,
    principal: Principal = Depends(require_roles(Role.DEVELOPER, Role.ADMIN)),
) -> EvaluationResult:
    return service.evaluate(request, tenant_id=principal.tenant_id, actor_id=principal.key_id)


@app.post("/v1/chat/completions")
def chat_completions(
    request: ChatCompletionRequest,
    principal: Principal = Depends(require_roles(Role.DEVELOPER, Role.ADMIN)),
) -> dict:
    """Evaluate, forward, and re-evaluate a non-streaming chat completion."""
    try:
        return chat_gateway.complete(request, tenant_id=principal.tenant_id, actor_id=principal.key_id)
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
    return service.policy.public_dict()


@app.put("/v1/policy/review-score")
def update_review_score(
    review_score: int = Query(ge=0, le=100),
    principal: Principal = Depends(require_roles(Role.ADMIN)),
) -> dict:
    policy_path = os.getenv("TRUSTAIX_POLICY_PATH")
    if not policy_path:
        raise HTTPException(
            status_code=409,
            detail={"message": "Set TRUSTAIX_POLICY_PATH before editing the policy from the console."},
        )
    updated = PolicyProfile(
        enabled_rules=service.policy.enabled_rules,
        weights=service.policy.weights,
        review_score=review_score,
        redact_categories=service.policy.redact_categories,
        block_critical=service.policy.block_critical,
        block_categories=service.policy.block_categories,
        block_minimum_level=service.policy.block_minimum_level,
    )
    save_policy_profile(policy_path, updated)
    service.policy = updated
    return service.policy.public_dict()
