"""FastAPI application for TrustAIX."""

from fastapi import FastAPI, HTTPException, Query

from trustaix.audit import AuditRepository
from trustaix.gateway import (
    ChatGatewayService,
    GatewayBlockedError,
    OpenAICompatibleClient,
    UpstreamConfigurationError,
    UpstreamRequestError,
)
from trustaix.models import AuditEvent, ChatCompletionRequest, EvaluationRequest, EvaluationResult
from trustaix.service import EvaluationService

app = FastAPI(title="TrustAIX", version="0.1.0", description="LLM risk-control gateway")
service = EvaluationService(AuditRepository())
chat_gateway = ChatGatewayService(service, OpenAICompatibleClient())


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/evaluate", response_model=EvaluationResult)
def evaluate(request: EvaluationRequest) -> EvaluationResult:
    return service.evaluate(request)


@app.post("/v1/chat/completions")
def chat_completions(request: ChatCompletionRequest) -> dict:
    """Evaluate, forward, and re-evaluate a non-streaming chat completion."""
    try:
        return chat_gateway.complete(request)
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
def audit_events(limit: int = Query(default=50, ge=1, le=100)) -> list[AuditEvent]:
    return service.audit_repository.latest(limit)
