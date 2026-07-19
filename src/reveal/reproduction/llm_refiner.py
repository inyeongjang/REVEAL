"""LLM-based proof-of-concept refinement."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import cast

from reveal.exceptions import PocRefinementError
from reveal.llm import LlmClient, LlmRequest
from reveal.models import (
    PocCandidate,
    PocResult,
    ReachabilityStatus,
    ReproductionStatus,
    TaintResult,
    Vulnerability,
)

_MAX_CODE_CONTEXT_CHARS = 20_000
_MAX_DIAGNOSTIC_CHARS = 8_000

_POC_REFINEMENT_SCHEMA: dict[str, object] = {
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


class LlmPocRefiner:
    """Refine unsuccessful PoC candidates using execution evidence."""

    def __init__(self, client: LlmClient) -> None:
        self.client = client

    def refine(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        previous_result: PocResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        """Generate revised PoC candidates from previous attempts."""

        if max_candidates < 1:
            raise ValueError("max_candidates must be at least one")

        _validate_evidence(
            vulnerability=vulnerability,
            taint=taint,
            previous_result=previous_result,
        )

        if taint.status is not ReachabilityStatus.REACHABLE:
            return ()

        if previous_result.status in {
            ReproductionStatus.REPRODUCED,
            ReproductionStatus.SKIPPED,
        }:
            return ()

        if not previous_result.attempts:
            return ()

        if not source.is_dir():
            raise PocRefinementError(
                f"Source directory does not exist: {source}"
            )

        allowed_languages = {
            attempt.candidate.language.strip().casefold()
            for attempt in previous_result.attempts
            if attempt.candidate.language.strip()
        }
        allowed_signals = {
            attempt.candidate.expected_signal.strip()
            for attempt in previous_result.attempts
            if attempt.candidate.expected_signal.strip()
        }
        previous_codes = {
            _normalize_code(attempt.candidate.code)
            for attempt in previous_result.attempts
        }

        request = LlmRequest(
            system_prompt=_load_system_prompt(),
            user_prompt=_build_user_prompt(
                vulnerability=vulnerability,
                taint=taint,
                previous_result=previous_result,
                max_candidates=max_candidates,
            ),
            temperature=0.0,
            max_tokens=4096,
            json_schema=_POC_REFINEMENT_SCHEMA,
        )

        response = self.client.generate(request)

        return _parse_candidates(
            response_text=response.text,
            max_candidates=max_candidates,
            allowed_languages=allowed_languages,
            allowed_signals=allowed_signals,
            previous_codes=previous_codes,
        )


def _validate_evidence(
    *,
    vulnerability: Vulnerability,
    taint: TaintResult,
    previous_result: PocResult,
) -> None:
    if taint.vulnerability_id != vulnerability.id:
        raise PocRefinementError(
            "Taint result vulnerability does not match the requested "
            "vulnerability."
        )

    if previous_result.vulnerability_id != vulnerability.id:
        raise PocRefinementError(
            "Previous PoC result vulnerability does not match the requested "
            "vulnerability."
        )

    if previous_result.target_api != taint.target_api:
        raise PocRefinementError(
            "Previous PoC result target API does not match the taint result."
        )


def _load_system_prompt() -> str:
    try:
        return (
            files("reveal")
            .joinpath("resources/prompts/poc_refinement.txt")
            .read_text(encoding="utf-8")
        )
    except OSError as error:
        raise PocRefinementError(
            "Failed to load the PoC refinement prompt."
        ) from error


def _build_user_prompt(
    *,
    vulnerability: Vulnerability,
    taint: TaintResult,
    previous_result: PocResult,
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
        "previous_result": {
            "status": previous_result.status.value,
            "evidence": previous_result.evidence,
            "reason": previous_result.reason,
            "attempts": [
                {
                    "number": attempt.number,
                    "candidate": {
                        "language": attempt.candidate.language,
                        "code": _truncate_context(
                            attempt.candidate.code,
                            _MAX_CODE_CONTEXT_CHARS,
                        ),
                        "expected_signal": (
                            attempt.candidate.expected_signal
                        ),
                        "description": attempt.candidate.description,
                    },
                    "exit_code": attempt.exit_code,
                    "stdout": _truncate_context(
                        attempt.stdout,
                        _MAX_DIAGNOSTIC_CHARS,
                    ),
                    "stderr": _truncate_context(
                        attempt.stderr,
                        _MAX_DIAGNOSTIC_CHARS,
                    ),
                    "timed_out": attempt.timed_out,
                    "reproduced": attempt.reproduced,
                    "error": attempt.error,
                }
                for attempt in previous_result.attempts
            ],
        },
        "max_candidates": max_candidates,
    }

    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
    )


def _parse_candidates(
    *,
    response_text: str,
    max_candidates: int,
    allowed_languages: set[str],
    allowed_signals: set[str],
    previous_codes: set[str],
) -> tuple[PocCandidate, ...]:
    try:
        value: object = json.loads(response_text)
    except json.JSONDecodeError as error:
        raise PocRefinementError(
            "The PoC refiner returned invalid JSON."
        ) from error

    if not isinstance(value, dict):
        raise PocRefinementError(
            "The PoC refiner response must be a JSON object."
        )

    document = cast(dict[str, object], value)
    raw_candidates = document.get("candidates")

    if not isinstance(raw_candidates, list):
        raise PocRefinementError(
            "The PoC refiner response must contain a candidates array."
        )

    candidates: list[PocCandidate] = []
    seen: set[tuple[str, str, str]] = set()

    for index, raw_candidate in enumerate(
        cast(list[object], raw_candidates),
        start=1,
    ):
        if not isinstance(raw_candidate, dict):
            raise PocRefinementError(
                f"Refined PoC candidate {index} must be a JSON object."
            )

        candidate_document = cast(
            dict[str, object],
            raw_candidate,
        )

        language = _required_string(
            candidate_document.get("language"),
            field="language",
            index=index,
        )
        code = _normalize_code(
            _required_string(
                candidate_document.get("code"),
                field="code",
                index=index,
            )
        )
        expected_signal = _required_string(
            candidate_document.get("expected_signal"),
            field="expected_signal",
            index=index,
        )
        description = _required_string(
            candidate_document.get("description"),
            field="description",
            index=index,
        )

        if language.casefold() not in allowed_languages:
            raise PocRefinementError(
                "A refined PoC candidate changed to an unsupported language: "
                f"{language}"
            )

        if expected_signal not in allowed_signals:
            raise PocRefinementError(
                "A refined PoC candidate changed the expected signal: "
                f"{expected_signal}"
            )

        if code in previous_codes:
            continue

        key = (
            language.casefold(),
            code,
            expected_signal,
        )

        if key in seen:
            continue

        seen.add(key)
        candidates.append(
            PocCandidate(
                language=language,
                code=code,
                expected_signal=expected_signal,
                description=description,
            )
        )

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
        raise PocRefinementError(
            f"Refined PoC candidate {index} field {field} "
            "must be a non-empty string."
        )

    return value.strip()


def _normalize_code(value: str) -> str:
    return (
        value.replace("\r\n", "\n")
        .replace("\r", "\n")
        .strip()
    )


def _truncate_context(
    value: str,
    maximum: int,
) -> str:
    if len(value) <= maximum:
        return value

    marker = "\n...[context truncated by REVEAL]"

    return value[: maximum - len(marker)] + marker