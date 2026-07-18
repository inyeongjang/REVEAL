"""Tests for the provider-independent LLM abstraction."""

import pytest

from reveal.llm import LlmClient, LlmRequest, LlmResponse


class FakeLlmClient:
    """Minimal client used to verify the shared interface."""

    def generate(self, request: LlmRequest) -> LlmResponse:
        return LlmResponse(
            text=f"response to: {request.user_prompt}",
            provider="fake",
            model="fake-model",
            prompt_tokens=10,
            completion_tokens=5,
        )


def run_client(
    client: LlmClient,
    request: LlmRequest,
) -> LlmResponse:
    """Execute any implementation satisfying the LLM client protocol."""

    return client.generate(request)


def test_client_protocol_accepts_structural_implementation() -> None:
    request = LlmRequest(
        system_prompt="You are a security analyst.",
        user_prompt="Identify the vulnerable API.",
    )

    response = run_client(
        client=FakeLlmClient(),
        request=request,
    )

    assert response.text == "response to: Identify the vulnerable API."
    assert response.provider == "fake"
    assert response.model == "fake-model"
    assert response.prompt_tokens == 10
    assert response.completion_tokens == 5


def test_request_accepts_json_schema() -> None:
    schema: dict[str, object] = {
        "type": "object",
        "properties": {
            "target_apis": {
                "type": "array",
                "items": {"type": "string"},
            }
        },
    }

    request = LlmRequest(
        system_prompt="Return JSON.",
        user_prompt="Select target APIs.",
        json_schema=schema,
    )

    assert request.json_schema == schema


def test_request_rejects_negative_temperature() -> None:
    with pytest.raises(
        ValueError,
        match="must not be negative",
    ):
        LlmRequest(
            system_prompt="system",
            user_prompt="user",
            temperature=-0.1,
        )


def test_request_rejects_non_positive_max_tokens() -> None:
    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        LlmRequest(
            system_prompt="system",
            user_prompt="user",
            max_tokens=0,
        )