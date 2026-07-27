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


_TRACE_FILENAMES = {
    "api_mapping": "llm-api-mapping.jsonl",
    "poc_generation": "llm-poc-generation.jsonl",
    "poc_refinement": "llm-poc-refinement.jsonl",
}


class TracingLlmClient:
    """Write LLM requests and responses to stage-specific JSONL files."""

    def __init__(self, *, client: LlmClient, output_dir: str | Path) -> None:
        self._client = client
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

        self._output_paths = {
            stage: self._output_dir / filename
            for stage, filename in _TRACE_FILENAMES.items()
        }

        for output_path in self._output_paths.values():
            output_path.write_text("", encoding="utf-8")

    def generate(self, request: LlmRequest) -> LlmResponse:
        stage = request.metadata.get("stage", "").strip() or "unknown"
        call_id = str(uuid4())
        started_at = datetime.now(UTC)
        started = time.monotonic()

        try:
            response = self._client.generate(request)
        except Exception as error:
            self._append(
                stage=stage,
                record={
                    "schema_version": 1,
                    "call_id": call_id,
                    "stage": stage,
                    "started_at": started_at.isoformat(),
                    "duration_ms": self._duration_ms(started),
                    "metadata": dict(request.metadata),
                    "request": self._serialize(request),
                    "response": None,
                    "error": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                },
            )
            raise

        self._append(
            stage=stage,
            record={
                "schema_version": 1,
                "call_id": call_id,
                "stage": stage,
                "started_at": started_at.isoformat(),
                "duration_ms": self._duration_ms(started),
                "metadata": dict(request.metadata),
                "request": self._serialize(request),
                "response": self._serialize(response),
                "error": None,
            },
        )

        return response

    def _append(self, *, stage: str, record: dict[str, Any]) -> None:
        output_path = self._output_paths.get(
            stage,
            self._output_dir / "llm-other.jsonl",
        )

        with output_path.open("a", encoding="utf-8") as output_file:
            json.dump(
                record,
                output_file,
                ensure_ascii=False,
                default=str,
            )
            output_file.write("\n")

    @staticmethod
    def _duration_ms(started: float) -> int:
        return round((time.monotonic() - started) * 1000)

    @staticmethod
    def _serialize(value: object) -> object:
        if is_dataclass(value) and not isinstance(value, type):
            return asdict(value)

        if isinstance(
            value,
            (str, int, float, bool, list, dict),
        ):
            return value

        return vars(value)