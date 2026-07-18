"""Provider-independent interfaces for LLM clients."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class LlmRequest:
    """A provider-independent request sent to an LLM."""

    system_prompt: str
    user_prompt: str
    temperature: float = 0.0
    max_tokens: int | None = None
    json_schema: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if self.temperature < 0:
            raise ValueError("temperature must not be negative")

        if self.max_tokens is not None and self.max_tokens < 1:
            raise ValueError("max_tokens must be greater than zero")


@dataclass(frozen=True, slots=True)
class LlmResponse:
    """A normalized response returned by an LLM provider."""

    text: str
    provider: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class LlmClient(Protocol):
    """Interface implemented by supported LLM providers."""

    def generate(self, request: LlmRequest) -> LlmResponse:
        """Generate a response for the supplied request."""
        ...