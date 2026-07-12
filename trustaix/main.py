"""FastAPI application for TrustAIX."""

from fastapi import FastAPI, Query

from trustaix.audit import AuditRepository
from trustaix.models import AuditEvent, EvaluationRequest, EvaluationResult
from trustaix.service import EvaluationService

app = FastAPI(title="TrustAIX", version="0.1.0", description="LLM risk-control gateway")
service = EvaluationService(AuditRepository())


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/evaluate", response_model=EvaluationResult)
def evaluate(request: EvaluationRequest) -> EvaluationResult:
    return service.evaluate(request)


@app.get("/v1/audit-events", response_model=list[AuditEvent])
def audit_events(limit: int = Query(default=50, ge=1, le=100)) -> list[AuditEvent]:
    return service.audit_repository.latest(limit)
