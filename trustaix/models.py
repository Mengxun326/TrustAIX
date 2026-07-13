"""Public request and response models."""

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"
    REDACT = "redact"


class Finding(BaseModel):
    rule_id: str
    category: Literal["prompt_injection", "pii", "secret", "content_policy"]
    level: RiskLevel
    message: str
    evidence: str
    location: Literal["prompt", "response"]


class EvaluationRequest(BaseModel):
    request_id: str | None = Field(default=None, max_length=128)
    prompt: str = Field(default="", max_length=100_000)
    response: str = Field(default="", max_length=100_000)

    @model_validator(mode="after")
    def contains_content(self) -> "EvaluationRequest":
        if not self.prompt.strip() and not self.response.strip():
            raise ValueError("At least one of prompt or response must contain text.")
        return self


class EvaluationResult(BaseModel):
    event_id: str
    request_id: str | None
    action: Action
    risk_score: int = Field(ge=0, le=100)
    findings: list[Finding]
    evaluated_at: str


class AuditEvent(EvaluationResult):
    prompt_length: int
    response_length: int


class ChatMessage(BaseModel):
    """A permissive subset of an OpenAI-compatible chat message."""

    model_config = ConfigDict(extra="allow")

    role: str
    content: str | list[dict[str, Any]] | None = None


class ChatCompletionRequest(BaseModel):
    """A non-streaming OpenAI-compatible Chat Completions request."""

    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[ChatMessage] = Field(min_length=1)
    stream: bool = False
    trustaix_request_id: str | None = Field(default=None, max_length=128)

    def upstream_payload(self) -> dict[str, Any]:
        """Keep TrustAIX metadata local rather than forwarding it upstream."""
        return self.model_dump(mode="json", exclude={"trustaix_request_id"}, exclude_none=True)
