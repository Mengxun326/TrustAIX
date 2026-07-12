"""Public request and response models."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, model_validator


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
