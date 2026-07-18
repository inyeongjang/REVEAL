"""Ollama implementation of the shared LLM client interface."""

from __future__ import annotations

import json
from typing import Any, cast
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from reveal.exceptions import LlmError
from reveal.llm.base import LlmRequest, LlmResponse


class OllamaLlmClient:
    """Generate normalized LLM responses using the Ollama generate API."""

    def __init__(
        self,
        model: str,
        endpoint: str = "http://localhost:11434/api/generate",
        timeout_seconds: float = 120.0,
    ) -> None:
        if not model.strip():
            raise ValueError("model must not be empty")

        if not endpoint.strip():
            raise ValueError("endpoint must not be empty")

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        self.model = model
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds

    def generate(self, request: LlmRequest) -> LlmResponse:
        """Generate a response and normalize Ollama-specific metadata."""

        options: dict[str, object] = {
            "temperature": request.temperature,
        }

        if request.max_tokens is not None:
            options["num_predict"] = request.max_tokens

        payload: dict[str, Any] = {
            "model": self.model,
            "system": request.system_prompt,
            "prompt": request.user_prompt,
            "stream": False,
            "options": options,
        }

        if request.json_schema is not None:
            payload["format"] = dict(request.json_schema)

        http_request = Request(
            url=self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(
                http_request,
                timeout=self.timeout_seconds,
            ) as response:
                response_body = response.read()
        except HTTPError as error:
            message = _read_http_error(error)
            raise LlmError(
                f"Ollama request failed with HTTP {error.code}: {message}"
            ) from error
        except URLError as error:
            raise LlmError(
                f"Failed to connect to Ollama at {self.endpoint}: {error.reason}"
            ) from error
        except TimeoutError as error:
            raise LlmError(
                f"Ollama request timed out after {self.timeout_seconds} seconds"
            ) from error
        except OSError as error:
            raise LlmError(
                f"Failed to communicate with Ollama: {error}"
            ) from error

        return _parse_response(
            response_body=response_body,
            configured_model=self.model,
        )


def _parse_response(
    response_body: bytes,
    configured_model: str,
) -> LlmResponse:
    try:
        decoded_body = response_body.decode("utf-8")
        value: object = json.loads(decoded_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LlmError("Ollama returned invalid JSON.") from error

    if not isinstance(value, dict):
        raise LlmError("Ollama response must be a JSON object.")

    document = cast(dict[str, object], value)

    raw_error = document.get("error")

    if isinstance(raw_error, str) and raw_error:
        raise LlmError(f"Ollama generation failed: {raw_error}")

    if document.get("done") is not True:
        raise LlmError("Ollama generation did not complete successfully.")

    raw_text = document.get("response")

    if not isinstance(raw_text, str) or not raw_text.strip():
        raise LlmError("Ollama returned an empty text response.")

    model = _optional_string(document.get("model")) or configured_model

    return LlmResponse(
        text=raw_text.strip(),
        provider="ollama",
        model=model,
        prompt_tokens=_optional_nonnegative_int(
            document.get("prompt_eval_count")
        ),
        completion_tokens=_optional_nonnegative_int(
            document.get("eval_count")
        ),
    )


def _read_http_error(error: HTTPError) -> str:
    try:
        response_body = error.read()
    except OSError:
        return str(error)

    try:
        value: object = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        message = response_body.decode(
            "utf-8",
            errors="replace",
        ).strip()

        return message or str(error)

    if isinstance(value, dict):
        document = cast(dict[str, object], value)
        raw_error = document.get("error")

        if isinstance(raw_error, str) and raw_error:
            return raw_error

    return str(error)


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value

    return None


def _optional_nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int) and value >= 0:
        return value

    return None