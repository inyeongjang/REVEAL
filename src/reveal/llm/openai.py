"""OpenAI implementation of the shared LLM client interface."""

from __future__ import annotations

from typing import Any, Protocol, cast

from openai import OpenAI, OpenAIError

from reveal.exceptions import LlmError
from reveal.llm.base import LlmRequest, LlmResponse


class _OpenAIUsage(Protocol):
    """Subset of OpenAI token usage consumed by REVEAL."""

    input_tokens: int
    output_tokens: int


class _OpenAIResponse(Protocol):
    """Subset of an OpenAI response consumed by REVEAL."""

    output_text: str
    model: str
    status: str | None
    usage: _OpenAIUsage | None


class _OpenAIResponsesApi(Protocol):
    """Subset of the OpenAI Responses API used by REVEAL."""

    def create(self, **kwargs: Any) -> _OpenAIResponse:
        """Create one model response."""
        ...


class _OpenAISdkClient(Protocol):
    """Subset of the OpenAI SDK client used by REVEAL."""

    responses: _OpenAIResponsesApi


class OpenAILlmClient:
    """Generate normalized LLM responses using the OpenAI Responses API."""

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        timeout_seconds: float = 120.0,
        client: _OpenAISdkClient | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("model must not be empty")

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        self.model = model
        self.timeout_seconds = timeout_seconds

        if client is not None:
            self._client = client
            return

        try:
            self._client = cast(
                _OpenAISdkClient,
                OpenAI(
                    api_key=api_key,
                    timeout=timeout_seconds,
                ),
            )
        except OpenAIError as error:
            raise LlmError(
                f"Failed to initialize the OpenAI client: {error}"
            ) from error

    def generate(self, request: LlmRequest) -> LlmResponse:
        """Generate a response and normalize provider-specific metadata."""

        parameters: dict[str, Any] = {
            "model": self.model,
            "instructions": request.system_prompt,
            "input": request.user_prompt,
            "temperature": request.temperature,
        }

        if request.max_tokens is not None:
            parameters["max_output_tokens"] = request.max_tokens

        if request.json_schema is not None:
            parameters["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": "reveal_response",
                    "schema": dict(request.json_schema),
                    "strict": True,
                }
            }

        try:
            response = self._client.responses.create(**parameters)
        except OpenAIError as error:
            raise LlmError(
                f"OpenAI request failed for model {self.model}: {error}"
            ) from error

        if response.status not in (None, "completed"):
            raise LlmError(
                "OpenAI response did not complete successfully: "
                f"{response.status}"
            )

        text = response.output_text.strip()

        if not text:
            raise LlmError("OpenAI returned an empty text response.")

        prompt_tokens: int | None = None
        completion_tokens: int | None = None

        if response.usage is not None:
            prompt_tokens = response.usage.input_tokens
            completion_tokens = response.usage.output_tokens

        return LlmResponse(
            text=text,
            provider="openai",
            model=str(response.model),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )