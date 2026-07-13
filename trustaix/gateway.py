"""OpenAI-compatible, non-streaming chat gateway."""

import os
import json
import time
from copy import deepcopy
from collections.abc import Callable
from collections.abc import Iterator
from typing import Any, Protocol

import httpx

from trustaix.models import Action, ChatCompletionRequest, EvaluationRequest, EvaluationResult
from trustaix.config import PolicyProfile
from trustaix.redaction import redact_content, redact_text, text_from_content
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
    """Resilient HTTP client for OpenAI-compatible Chat Completions providers."""

    def __init__(
        self,
        base_urls: list[str] | None = None,
        retries: int | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        configured_urls = os.getenv("TRUSTAIX_UPSTREAM_BASE_URLS", "")
        fallback = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.base_urls = base_urls or [url.strip() for url in configured_urls.split(",") if url.strip()] or [fallback]
        self.retries = retries if retries is not None else int(os.getenv("TRUSTAIX_UPSTREAM_RETRIES", "2"))
        self.transport = transport
        self.sleep = sleep

    def create_chat_completion(self, payload: dict[str, Any]) -> dict[str, Any]:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise UpstreamConfigurationError("OPENAI_API_KEY is not configured.")

        last_error: Exception | None = None
        for base_url in self.base_urls:
            for attempt in range(self.retries + 1):
                try:
                    with httpx.Client(timeout=60.0, transport=self.transport) as client:
                        response = client.post(
                            f"{base_url.rstrip('/')}/chat/completions",
                            headers={"Authorization": f"Bearer {api_key}"},
                            json=payload,
                        )
                    if response.status_code < 400:
                        return response.json()
                    if response.status_code not in {408, 429} and response.status_code < 500:
                        response.raise_for_status()
                    last_error = httpx.HTTPStatusError(
                        "Retryable upstream response.", request=response.request, response=response
                    )
                except httpx.HTTPError as error:
                    last_error = error
                if attempt < self.retries:
                    self.sleep(0.2 * (2**attempt))
        raise UpstreamRequestError("All configured upstream chat providers failed.") from last_error


class ChatGatewayService:
    def __init__(self, evaluation_service: EvaluationService, client: ChatCompletionClient) -> None:
        self.evaluation_service = evaluation_service
        self.client = client

    def complete(
        self,
        request: ChatCompletionRequest,
        tenant_id: str = "default",
        actor_id: str | None = None,
        policy: PolicyProfile | None = None,
        policy_version_id: str | None = None,
    ) -> dict[str, Any]:
        prompt = "\n".join(text_from_content(message.content) for message in request.messages)
        input_evaluation = self.evaluation_service.evaluate(
            EvaluationRequest(request_id=request.trustaix_request_id, prompt=prompt),
            tenant_id=tenant_id,
            actor_id=actor_id,
            policy=policy,
            policy_version_id=policy_version_id,
        )
        if input_evaluation.action is Action.BLOCK:
            raise GatewayBlockedError(input_evaluation)

        upstream_request = request.model_copy(deep=True)
        # Upstream output is fully buffered and inspected before any client chunk is released.
        upstream_request.stream = False
        if input_evaluation.action is Action.REDACT:
            for message in upstream_request.messages:
                message.content = redact_content(message.content)

        upstream_response = self.client.create_chat_completion(upstream_request.upstream_payload())
        response_text = _response_text(upstream_response)
        output_evaluation = self.evaluation_service.evaluate(
            EvaluationRequest(
                request_id=request.trustaix_request_id,
                response=response_text,
                require_citations=request.trustaix_require_citations,
                allowed_sources=request.trustaix_allowed_sources,
            ),
            tenant_id=tenant_id,
            actor_id=actor_id,
            policy=policy,
            policy_version_id=policy_version_id,
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

    def complete_buffered_stream(
        self,
        request: ChatCompletionRequest,
        tenant_id: str = "default",
        actor_id: str | None = None,
        policy: PolicyProfile | None = None,
        policy_version_id: str | None = None,
        chunk_size: int = 160,
    ) -> Iterator[str]:
        """Emit OpenAI-compatible SSE only after the complete output passes inspection."""
        safe_response = self.complete(
            request.model_copy(update={"stream": False}),
            tenant_id=tenant_id,
            actor_id=actor_id,
            policy=policy,
            policy_version_id=policy_version_id,
        )
        text = _response_text(safe_response)
        response_id = safe_response.get("id", "trustaix-buffered")
        for index in range(0, len(text), chunk_size):
            payload = {
                "id": response_id,
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": text[index:index + chunk_size]}, "finish_reason": None}],
            }
            yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
        final = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "trustaix": safe_response["trustaix"],
        }
        yield f"data: {json.dumps(final, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"


def _response_text(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise UpstreamRequestError("The upstream response did not include inspectable choices.")

    texts: list[str] = []
    for choice in choices:
        message = choice.get("message") if isinstance(choice, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        texts.append(text_from_content(content))
        if isinstance(message, dict) and message.get("tool_calls"):
            texts.append(json.dumps(message["tool_calls"], ensure_ascii=False))
    return "\n".join(texts)


def _replace_response_content(response: dict[str, Any], replacement: str) -> None:
    for choice in response["choices"]:
        message = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(message, dict):
            message["content"] = replacement
            message.pop("tool_calls", None)
            message.pop("function_call", None)


def _redact_response_content(response: dict[str, Any]) -> None:
    for choice in response["choices"]:
        message = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(message, dict):
            message["content"] = redact_content(message.get("content"))
            for tool_call in message.get("tool_calls", []):
                function = tool_call.get("function") if isinstance(tool_call, dict) else None
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    function["arguments"] = redact_text(function["arguments"])
