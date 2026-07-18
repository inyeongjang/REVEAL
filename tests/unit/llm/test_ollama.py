"""Tests for the Ollama LLM client."""

from __future__ import annotations

import json
from types import TracebackType
from urllib.error import URLError
from urllib.request import Request

import pytest

from reveal.exceptions import LlmError
from reveal.llm import LlmRequest
from reveal.llm.ollama import OllamaLlmClient


class FakeHttpResponse:
    """Context-managed HTTP response used by Ollama client tests."""

    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> FakeHttpResponse:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


def create_response_body(
    *,
    response: str = '{"result": "ok"}',
    model: str = "qwen2.5-coder:7b",
    done: bool = True,
) -> bytes:
    return json.dumps(
        {
            "model": model,
            "response": response,
            "done": done,
            "prompt_eval_count": 24,
            "eval_count": 12,
        }
    ).encode("utf-8")


def test_generate_normalizes_ollama_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_request: Request | None = None
    captured_timeout: float | None = None

    def fake_urlopen(
        request: Request,
        timeout: float,
    ) -> FakeHttpResponse:
        nonlocal captured_request, captured_timeout

        captured_request = request
        captured_timeout = timeout

        return FakeHttpResponse(
            create_response_body(response="  generated response  ")
        )

    monkeypatch.setattr(
        "reveal.llm.ollama.urlopen",
        fake_urlopen,
    )

    client = OllamaLlmClient(
        model="qwen2.5-coder:7b",
        timeout_seconds=60,
    )

    result = client.generate(
        LlmRequest(
            system_prompt="System instructions.",
            user_prompt="User input.",
            temperature=0.2,
            max_tokens=512,
        )
    )

    assert result.text == "generated response"
    assert result.provider == "ollama"
    assert result.model == "qwen2.5-coder:7b"
    assert result.prompt_tokens == 24
    assert result.completion_tokens == 12

    assert captured_request is not None
    assert captured_timeout == 60

    payload = json.loads(
        captured_request.data.decode("utf-8")
    )

    assert payload == {
        "model": "qwen2.5-coder:7b",
        "system": "System instructions.",
        "prompt": "User input.",
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 512,
        },
    }


def test_generate_passes_json_schema_as_format(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_payload: dict[str, object] = {}

    def fake_urlopen(
        request: Request,
        timeout: float,
    ) -> FakeHttpResponse:
        del timeout

        captured_payload.update(
            json.loads(request.data.decode("utf-8"))
        )

        return FakeHttpResponse(create_response_body())

    monkeypatch.setattr(
        "reveal.llm.ollama.urlopen",
        fake_urlopen,
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

    client = OllamaLlmClient(model="qwen2.5-coder:7b")

    client.generate(
        LlmRequest(
            system_prompt="Return JSON.",
            user_prompt="Select target APIs.",
            json_schema=schema,
        )
    )

    assert captured_payload["format"] == schema


def test_generate_omits_num_predict_without_max_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_payload: dict[str, object] = {}

    def fake_urlopen(
        request: Request,
        timeout: float,
    ) -> FakeHttpResponse:
        del timeout

        captured_payload.update(
            json.loads(request.data.decode("utf-8"))
        )

        return FakeHttpResponse(create_response_body())

    monkeypatch.setattr(
        "reveal.llm.ollama.urlopen",
        fake_urlopen,
    )

    client = OllamaLlmClient(model="qwen2.5-coder:7b")

    client.generate(
        LlmRequest(
            system_prompt="System.",
            user_prompt="User.",
        )
    )

    options = captured_payload["options"]

    assert isinstance(options, dict)
    assert "num_predict" not in options


def test_generate_wraps_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Request,
        timeout: float,
    ) -> FakeHttpResponse:
        del request, timeout
        raise URLError("connection refused")

    monkeypatch.setattr(
        "reveal.llm.ollama.urlopen",
        fake_urlopen,
    )

    client = OllamaLlmClient(model="qwen2.5-coder:7b")

    with pytest.raises(
        LlmError,
        match="Failed to connect to Ollama",
    ):
        client.generate(
            LlmRequest(
                system_prompt="System.",
                user_prompt="User.",
            )
        )


def test_generate_rejects_invalid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Request,
        timeout: float,
    ) -> FakeHttpResponse:
        del request, timeout
        return FakeHttpResponse(b"not valid JSON")

    monkeypatch.setattr(
        "reveal.llm.ollama.urlopen",
        fake_urlopen,
    )

    client = OllamaLlmClient(model="qwen2.5-coder:7b")

    with pytest.raises(
        LlmError,
        match="invalid JSON",
    ):
        client.generate(
            LlmRequest(
                system_prompt="System.",
                user_prompt="User.",
            )
        )


def test_generate_rejects_error_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Request,
        timeout: float,
    ) -> FakeHttpResponse:
        del request, timeout

        return FakeHttpResponse(
            json.dumps(
                {
                    "error": "model not found",
                }
            ).encode("utf-8")
        )

    monkeypatch.setattr(
        "reveal.llm.ollama.urlopen",
        fake_urlopen,
    )

    client = OllamaLlmClient(model="missing-model")

    with pytest.raises(
        LlmError,
        match="model not found",
    ):
        client.generate(
            LlmRequest(
                system_prompt="System.",
                user_prompt="User.",
            )
        )


def test_generate_rejects_incomplete_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Request,
        timeout: float,
    ) -> FakeHttpResponse:
        del request, timeout

        return FakeHttpResponse(
            create_response_body(done=False)
        )

    monkeypatch.setattr(
        "reveal.llm.ollama.urlopen",
        fake_urlopen,
    )

    client = OllamaLlmClient(model="qwen2.5-coder:7b")

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


def test_generate_rejects_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(
        request: Request,
        timeout: float,
    ) -> FakeHttpResponse:
        del request, timeout

        return FakeHttpResponse(
            create_response_body(response="   ")
        )

    monkeypatch.setattr(
        "reveal.llm.ollama.urlopen",
        fake_urlopen,
    )

    client = OllamaLlmClient(model="qwen2.5-coder:7b")

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


@pytest.mark.parametrize(
    ("model", "endpoint", "timeout_seconds", "message"),
    [
        ("", "http://localhost:11434/api/generate", 120.0, "model"),
        ("model", "", 120.0, "endpoint"),
        (
            "model",
            "http://localhost:11434/api/generate",
            0,
            "timeout_seconds",
        ),
    ],
)
def test_client_rejects_invalid_configuration(
    model: str,
    endpoint: str,
    timeout_seconds: float,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        OllamaLlmClient(
            model=model,
            endpoint=endpoint,
            timeout_seconds=timeout_seconds,
        )