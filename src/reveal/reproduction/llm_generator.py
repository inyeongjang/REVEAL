"""LLM-based proof-of-concept generation."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import cast

from reveal.exceptions import PocGenerationError
from reveal.llm import LlmClient, LlmRequest
from reveal.models import (
    PocCandidate,
    ReachabilityStatus,
    TaintResult,
    Vulnerability,
)

_CONTEXT_RADIUS = 8
_MAX_CONTEXT_LOCATIONS = 5

_POC_GENERATION_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "language": {
                        "type": "string",
                    },
                    "code": {
                        "type": "string",
                    },
                    "expected_signal": {
                        "type": "string",
                    },
                    "description": {
                        "type": "string",
                    },
                },
                "required": [
                    "language",
                    "code",
                    "expected_signal",
                    "description",
                ],
            },
        }
    },
    "required": ["candidates"],
}


class LlmPocGenerator:
    """Generate PoC candidates from vulnerability and taint evidence."""

    def __init__(self, client: LlmClient) -> None:
        self.client = client

    def generate(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        """Generate bounded PoC candidates for a reachable vulnerability."""

        if max_candidates < 1:
            raise ValueError("max_candidates must be at least one")

        if taint.status is not ReachabilityStatus.REACHABLE:
            return ()

        if taint.vulnerability_id != vulnerability.id:
            raise PocGenerationError(
                "Taint result vulnerability does not match the requested vulnerability."
            )

        if not taint.paths:
            raise PocGenerationError(
                "Reachable taint result contains no data-flow paths."
            )

        if not source.is_dir():
            raise PocGenerationError(
                f"Source directory does not exist: {source}"
            )

        source_context = _collect_source_context(
            source=source,
            taint=taint,
        )

        request = LlmRequest(
            system_prompt=_load_system_prompt(),
            user_prompt=_build_user_prompt(
                vulnerability=vulnerability,
                taint=taint,
                source_context=source_context,
                max_candidates=max_candidates,
            ),
            temperature=0.0,
            max_tokens=4096,
            json_schema=_POC_GENERATION_SCHEMA,
        )

        response = self.client.generate(request)

        return _parse_candidates(
            response_text=response.text,
            max_candidates=max_candidates,
        )


def _load_system_prompt() -> str:
    try:
        return (
            files("reveal")
            .joinpath("resources/prompts/poc_generation.txt")
            .read_text(encoding="utf-8")
        )
    except OSError as error:
        raise PocGenerationError(
            "Failed to load the PoC generation prompt."
        ) from error


def _build_user_prompt(
    vulnerability: Vulnerability,
    taint: TaintResult,
    source_context: tuple[dict[str, object], ...],
    max_candidates: int,
) -> str:
    payload = {
        "vulnerability": {
            "id": vulnerability.id,
            "aliases": list(vulnerability.aliases),
            "package": vulnerability.component.name,
            "version": vulnerability.component.version,
            "ecosystem": vulnerability.component.ecosystem,
            "description": vulnerability.description,
            "fixed_versions": list(vulnerability.fixed_versions),
            "urls": list(vulnerability.urls),
        },
        "target_api": taint.target_api,
        "taint_paths": [
            {
                "source_file": path.source_file.as_posix(),
                "source_line": path.source_line,
                "source": path.source,
                "sink_file": path.sink_file.as_posix(),
                "sink_line": path.sink_line,
                "sink": path.sink,
                "sink_argument": path.sink_argument,
                "steps": list(path.steps),
            }
            for path in taint.paths
        ],
        "source_context": list(source_context),
        "max_candidates": max_candidates,
    }

    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
    )


def _collect_source_context(
    source: Path,
    taint: TaintResult,
) -> tuple[dict[str, object], ...]:
    source_root = source.resolve()
    contexts: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()

    for path in taint.paths:
        relative_path = path.sink_file
        key = (
            relative_path.as_posix(),
            path.sink_line,
        )

        if key in seen:
            continue

        seen.add(key)

        file_path = _resolve_project_file(
            source_root=source_root,
            relative_path=relative_path,
        )
        snippet = _read_source_snippet(
            file_path=file_path,
            line=path.sink_line,
        )

        contexts.append(
            {
                "file": relative_path.as_posix(),
                "sink_line": path.sink_line,
                "snippet": snippet,
            }
        )

        if len(contexts) >= _MAX_CONTEXT_LOCATIONS:
            break

    return tuple(contexts)


def _resolve_project_file(
    source_root: Path,
    relative_path: Path,
) -> Path:
    file_path = (source_root / relative_path).resolve()

    if not file_path.is_relative_to(source_root):
        raise PocGenerationError(
            f"Taint path escapes the project directory: {relative_path}"
        )

    if not file_path.is_file():
        raise PocGenerationError(
            f"Taint sink source file does not exist: {relative_path}"
        )

    return file_path


def _read_source_snippet(
    file_path: Path,
    line: int,
) -> str:
    if line < 1:
        raise PocGenerationError(
            f"Invalid taint sink line for {file_path}: {line}"
        )

    try:
        source_lines = file_path.read_text(
            encoding="utf-8",
        ).splitlines()
    except (OSError, UnicodeError) as error:
        raise PocGenerationError(
            f"Failed to read taint sink source file: {file_path}"
        ) from error

    if line > len(source_lines):
        raise PocGenerationError(
            f"Taint sink line {line} exceeds the length of {file_path}"
        )

    start = max(1, line - _CONTEXT_RADIUS)
    end = min(len(source_lines), line + _CONTEXT_RADIUS)

    return "\n".join(
        f"{line_number}: {source_lines[line_number - 1]}"
        for line_number in range(start, end + 1)
    )


def _parse_candidates(
    response_text: str,
    max_candidates: int,
) -> tuple[PocCandidate, ...]:
    try:
        value: object = json.loads(response_text)
    except json.JSONDecodeError as error:
        raise PocGenerationError(
            "The PoC generator returned invalid JSON."
        ) from error

    if not isinstance(value, dict):
        raise PocGenerationError(
            "The PoC generator response must be a JSON object."
        )

    document = cast(dict[str, object], value)
    raw_candidates = document.get("candidates")

    if not isinstance(raw_candidates, list):
        raise PocGenerationError(
            "The PoC generator response must contain a candidates array."
        )

    candidates: list[PocCandidate] = []
    seen: set[tuple[str, str, str]] = set()

    for index, raw_candidate in enumerate(
        cast(list[object], raw_candidates),
        start=1,
    ):
        if not isinstance(raw_candidate, dict):
            raise PocGenerationError(
                f"PoC candidate {index} must be a JSON object."
            )

        candidate_document = cast(
            dict[str, object],
            raw_candidate,
        )

        candidate = PocCandidate(
            language=_required_string(
                candidate_document.get("language"),
                field="language",
                index=index,
            ),
            code=_required_string(
                candidate_document.get("code"),
                field="code",
                index=index,
            ),
            expected_signal=_required_string(
                candidate_document.get("expected_signal"),
                field="expected_signal",
                index=index,
            ),
            description=_required_string(
                candidate_document.get("description"),
                field="description",
                index=index,
            ),
        )

        key = (
            candidate.language.casefold(),
            candidate.code,
            candidate.expected_signal,
        )

        if key in seen:
            continue

        seen.add(key)
        candidates.append(candidate)

        if len(candidates) >= max_candidates:
            break

    return tuple(candidates)


def _required_string(
    value: object,
    *,
    field: str,
    index: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PocGenerationError(
            f"PoC candidate {index} field {field} "
            "must be a non-empty string."
        )

    return value.strip()