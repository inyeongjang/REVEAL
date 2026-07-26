"""LLM request and response tracing."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from reveal.llm.base import LlmClient, LlmRequest, LlmResponse


class TracingLlmClient:
    """Write every LLM request and response to a JSONL file."""

    def __init__(
        self,
        *,
        client: LlmClient,
        output_path: str | Path,
    ) -> None:
        self._client = client
        self._output_path = Path(output_path)
        self._output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def generate(
        self,
        request: LlmRequest,
    ) -> LlmResponse:
        call_id = str(uuid4())
        started_at = datetime.now(UTC)
        started = time.monotonic()

        try:
            response = self._client.generate(request)
        except Exception as error:
            self._append(
                {
                    "call_id": call_id,
                    "started_at": started_at.isoformat(),
                    "duration_ms": self._duration_ms(started),
                    "request": self._serialize(request),
                    "response": None,
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                }
            )
            raise

        self._append(
            {
                "call_id": call_id,
                "started_at": started_at.isoformat(),
                "duration_ms": self._duration_ms(started),
                "request": self._serialize(request),
                "response": self._serialize(response),
                "error": None,
            }
        )
        return response

    def _append(
        self,
        record: dict[str, Any],
    ) -> None:
        with self._output_path.open(
            "a",
            encoding="utf-8",
        ) as output_file:
            json.dump(
                record,
                output_file,
                ensure_ascii=False,
                default=str,
            )
            output_file.write("\n")

    @staticmethod
    def _duration_ms(started: float) -> int:
        return round(
            (time.monotonic() - started) * 1000
        )

    @staticmethod
    def _serialize(value: object) -> object:
        if is_dataclass(value) and not isinstance(
            value,
            type,
        ):
            return asdict(value)

        if isinstance(
            value,
            (str, int, float, bool, list, dict),
        ):
            return value

        return vars(value)