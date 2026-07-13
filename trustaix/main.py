"""FastAPI application for TrustAIX."""

import os
import logging
import csv
import io
import json
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response, StreamingResponse
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
from trustaix.observability import MetricsRegistry
from trustaix.service import EvaluationService

app = FastAPI(title="TrustAIX", version="0.1.0", description="LLM risk-control gateway")
logger = logging.getLogger("trustaix")
web_directory = Path(__file__).parent / "web"
app.mount("/static", StaticFiles(directory=web_directory), name="static")
database_path = os.getenv("TRUSTAIX_DATABASE_URL") or os.getenv("TRUSTAIX_AUDIT_DB", "trustaix.db")
service = EvaluationService(AuditRepository(database_path))
chat_gateway = ChatGatewayService(service, OpenAICompatibleClient())
auth_service = AuthService.from_environment()
policy_versions = PolicyVersionRepository(database_path)
metrics = MetricsRegistry()
service.on_evaluation = metrics.record_evaluation


@app.middleware("http")
async def observe_request(request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid4()))
    started = perf_counter()
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    metrics.record_request(request.method, request.url.path, response.status_code)
    logger.info(
        "request_completed request_id=%s method=%s path=%s status=%s duration_ms=%.1f",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        (perf_counter() - started) * 1000,
    )
    return response


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


@app.post("/v1/chat/completions", response_model=None)
def chat_completions(
    request: ChatCompletionRequest,
    principal: Principal = Depends(require_roles(Role.DEVELOPER, Role.ADMIN)),
) -> dict | StreamingResponse:
    """Evaluate, forward, inspect, then return a normal or safely buffered SSE response."""
    try:
        policy, version = active_policy(principal)
        if request.stream:
            return StreamingResponse(
                chat_gateway.complete_buffered_stream(
                    request, tenant_id=principal.tenant_id, actor_id=principal.key_id,
                    policy=policy, policy_version_id=version.id,
                ),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-TrustAIX-Streaming": "buffered-safe"},
            )
        return chat_gateway.complete(request, tenant_id=principal.tenant_id, actor_id=principal.key_id, policy=policy, policy_version_id=version.id)
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


@app.get("/v1/audit-events/export")
def export_audit_events(
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    limit: int = Query(default=1_000, ge=1, le=10_000),
    principal: Principal = Depends(require_roles(Role.AUDITOR, Role.ADMIN)),
) -> Response:
    events = service.audit_repository.latest(limit, tenant_id=principal.tenant_id)
    if format == "json":
        return Response(
            json.dumps([event.model_dump(mode="json") for event in events], ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=trustaix-audit.json"},
        )

    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=[
            "event_id", "evaluated_at", "tenant_id", "actor_id", "policy_version_id", "action",
            "risk_score", "finding_rules", "feedback_verdict", "feedback_note",
        ],
    )
    writer.writeheader()
    for event in events:
        writer.writerow(
            {
                "event_id": event.event_id,
                "evaluated_at": event.evaluated_at,
                "tenant_id": event.tenant_id,
                "actor_id": event.actor_id or "",
                "policy_version_id": event.policy_version_id or "",
                "action": event.action.value,
                "risk_score": event.risk_score,
                "finding_rules": ";".join(finding.rule_id for finding in event.findings),
                "feedback_verdict": event.feedback.verdict.value if event.feedback else "",
                "feedback_note": event.feedback.note if event.feedback else "",
            }
        )
    return Response(
        "\ufeff" + stream.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=trustaix-audit.csv"},
    )


@app.get("/v1/analytics")
def analytics(principal: Principal = Depends(require_roles(Role.AUDITOR, Role.ADMIN))) -> dict:
    return service.audit_repository.analytics(tenant_id=principal.tenant_id)


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics(principal: Principal = Depends(require_roles(Role.ADMIN))):
    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(metrics.render_prometheus(), media_type="text/plain; version=0.0.4")


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


@app.delete("/v1/audit-events/retention")
def apply_retention_policy(
    before: datetime = Query(description="Delete events before this ISO-8601 timestamp."),
    principal: Principal = Depends(require_roles(Role.ADMIN)),
) -> dict[str, int]:
    if before.tzinfo is None:
        before = before.replace(tzinfo=UTC)
    return {"deleted": service.audit_repository.purge_before(before, tenant_id=principal.tenant_id)}


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
