"""Tests for the OpenAI LLM client."""

from __future__ import annotations

from typing import Any

import pytest
from openai import OpenAIError

from reveal.exceptions import LlmError
from reveal.llm import LlmRequest
from reveal.llm.openai import OpenAILlmClient


class FakeUsage:
    """Deterministic token usage for tests."""

    def __init__(
        self,
        input_tokens: int = 20,
        output_tokens: int = 10,
    ) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class FakeResponse:
    """Deterministic OpenAI response for tests."""

    def __init__(
        self,
        output_text: str = '{"result": "ok"}',
        model: str = "test-model",
        status: str | None = "completed",
        usage: FakeUsage | None = None,
    ) -> None:
        self.output_text = output_text
        self.model = model
        self.status = status
        self.usage = usage


class FakeResponsesApi:
    """Fake Responses API that records submitted parameters."""

    def __init__(
        self,
        response: FakeResponse | None = None,
        error: OpenAIError | None = None,
    ) -> None:
        self.response = response or FakeResponse()
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> FakeResponse:
        self.calls.append(kwargs)

        if self.error is not None:
            raise self.error

        return self.response


class FakeOpenAIClient:
    """Fake OpenAI SDK client."""

    def __init__(self, responses: FakeResponsesApi) -> None:
        self.responses = responses


def test_generate_normalizes_openai_response() -> None:
    responses = FakeResponsesApi(
        response=FakeResponse(
            output_text="  generated response  ",
            model="test-model",
            usage=FakeUsage(
                input_tokens=32,
                output_tokens=14,
            ),
        )
    )
    client = OpenAILlmClient(
        model="test-model",
        client=FakeOpenAIClient(responses),
    )

    result = client.generate(
        LlmRequest(
            system_prompt="System instructions.",
            user_prompt="User input.",
            temperature=0.0,
            max_tokens=512,
        )
    )

    assert result.text == "generated response"
    assert result.provider == "openai"
    assert result.model == "test-model"
    assert result.prompt_tokens == 32
    assert result.completion_tokens == 14

    assert responses.calls == [
        {
            "model": "test-model",
            "instructions": "System instructions.",
            "input": "User input.",
            "temperature": 0.0,
            "max_output_tokens": 512,
        }
    ]


def test_generate_passes_json_schema_as_structured_output() -> None:
    responses = FakeResponsesApi()
    client = OpenAILlmClient(
        model="test-model",
        client=FakeOpenAIClient(responses),
    )
    schema: dict[str, object] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "target_apis": {
                "type": "array",
                "items": {"type": "string"},
            }
        },
        "required": ["target_apis"],
    }

    client.generate(
        LlmRequest(
            system_prompt="Return JSON.",
            user_prompt="Select target APIs.",
            json_schema=schema,
        )
    )

    call = responses.calls[0]

    assert call["text"] == {
        "format": {
            "type": "json_schema",
            "name": "reveal_response",
            "schema": schema,
            "strict": True,
        }
    }


def test_generate_omits_max_tokens_when_not_configured() -> None:
    responses = FakeResponsesApi()
    client = OpenAILlmClient(
        model="test-model",
        client=FakeOpenAIClient(responses),
    )

    client.generate(
        LlmRequest(
            system_prompt="System.",
            user_prompt="User.",
        )
    )

    assert "max_output_tokens" not in responses.calls[0]


def test_generate_wraps_openai_error() -> None:
    responses = FakeResponsesApi(
        error=OpenAIError("request failed"),
    )
    client = OpenAILlmClient(
        model="test-model",
        client=FakeOpenAIClient(responses),
    )

    with pytest.raises(
        LlmError,
        match="OpenAI request failed",
    ):
        client.generate(
            LlmRequest(
                system_prompt="System.",
                user_prompt="User.",
            )
        )


def test_generate_rejects_empty_response() -> None:
    responses = FakeResponsesApi(
        response=FakeResponse(output_text="   "),
    )
    client = OpenAILlmClient(
        model="test-model",
        client=FakeOpenAIClient(responses),
    )

    with pytest.raises(
        LlmError,
        match="empty text response",
    ):
        client.generate(
            LlmRequest(
                system_prompt="System.",
                user_prompt="User.",
            )
        )


def test_generate_rejects_incomplete_response() -> None:
    responses = FakeResponsesApi(
        response=FakeResponse(
            status="incomplete",
        )
    )
    client = OpenAILlmClient(
        model="test-model",
        client=FakeOpenAIClient(responses),
    )

    with pytest.raises(
        LlmError,
        match="did not complete successfully",
    ):
        client.generate(
            LlmRequest(
                system_prompt="System.",
                user_prompt="User.",
            )
        )


def test_client_rejects_empty_model() -> None:
    with pytest.raises(
        ValueError,
        match="must not be empty",
    ):
        OpenAILlmClient(
            model=" ",
            client=FakeOpenAIClient(FakeResponsesApi()),
        )


def test_client_rejects_invalid_timeout() -> None:
    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        OpenAILlmClient(
            model="test-model",
            timeout_seconds=0,
            client=FakeOpenAIClient(FakeResponsesApi()),
        )