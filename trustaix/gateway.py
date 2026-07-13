"""OpenAI-compatible, non-streaming chat gateway."""

import os
from copy import deepcopy
from typing import Any, Protocol

import httpx

from trustaix.models import Action, ChatCompletionRequest, EvaluationRequest, EvaluationResult
from trustaix.redaction import redact_content, text_from_content
from trustaix.service import EvaluationService


class GatewayBlockedError(Exception):
    def __init__(self, evaluation: EvaluationResult) -> None:
        self.evaluation = evaluation
        super().__init__("The request was blocked by the TrustAIX risk policy.")


class UpstreamConfigurationError(Exception):
    pass


class UpstreamRequestError(Exception):
    pass


class ChatCompletionClient(Protocol):
    def create_chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send a validated request to an OpenAI-compatible upstream."""


class OpenAICompatibleClient:
    """Minimal HTTP client for any Chat Completions-compatible provider."""

    def create_chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise UpstreamConfigurationError("OPENAI_API_KEY is not configured.")

        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        try:
            with httpx.Client(timeout=60.0) as client:
                response = client.post(
                    f"{base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}"},
                    json=payload,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as error:
            raise UpstreamRequestError("The upstream chat provider request failed.") from error


class ChatGatewayService:
    def __init__(self, evaluation_service: EvaluationService, client: ChatCompletionClient) -> None:
        self.evaluation_service = evaluation_service
        self.client = client

    def complete(
        self, request: ChatCompletionRequest, tenant_id: str = "default", actor_id: str | None = None
    ) -> dict[str, Any]:
        if request.stream:
            raise ValueError("Streaming is not supported because output must be evaluated before release.")

        prompt = "\n".join(text_from_content(message.content) for message in request.messages)
        input_evaluation = self.evaluation_service.evaluate(
            EvaluationRequest(request_id=request.trustaix_request_id, prompt=prompt),
            tenant_id=tenant_id,
            actor_id=actor_id,
        )
        if input_evaluation.action is Action.BLOCK:
            raise GatewayBlockedError(input_evaluation)

        upstream_request = request.model_copy(deep=True)
        if input_evaluation.action is Action.REDACT:
            for message in upstream_request.messages:
                message.content = redact_content(message.content)

        upstream_response = self.client.create_chat_completion(upstream_request.upstream_payload())
        response_text = _response_text(upstream_response)
        output_evaluation = self.evaluation_service.evaluate(
            EvaluationRequest(request_id=request.trustaix_request_id, response=response_text),
            tenant_id=tenant_id,
            actor_id=actor_id,
        )

        safe_response = deepcopy(upstream_response)
        if output_evaluation.action is Action.BLOCK:
            _replace_response_content(
                safe_response, "The model response was blocked by the TrustAIX risk policy."
            )
        elif output_evaluation.action is Action.REDACT:
            _redact_response_content(safe_response)

        safe_response["trustaix"] = {
            "input": input_evaluation.model_dump(mode="json"),
            "output": output_evaluation.model_dump(mode="json"),
        }
        return safe_response


def _response_text(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise UpstreamRequestError("The upstream response did not include inspectable choices.")

    texts: list[str] = []
    for choice in choices:
        message = choice.get("message") if isinstance(choice, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        texts.append(text_from_content(content))
    return "\n".join(texts)


def _replace_response_content(response: dict[str, Any], replacement: str) -> None:
    for choice in response["choices"]:
        message = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(message, dict):
            message["content"] = replacement


def _redact_response_content(response: dict[str, Any]) -> None:
    for choice in response["choices"]:
        message = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(message, dict):
            message["content"] = redact_content(message.get("content"))
