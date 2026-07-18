"""LLM-based vulnerable API selector."""

from __future__ import annotations

import json
from collections.abc import Sequence
from importlib.resources import files
from typing import cast

from reveal.exceptions import LlmError
from reveal.llm import LlmClient, LlmRequest
from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    ApiUsage,
    Vulnerability,
)

_API_MAPPING_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "target_apis": {
            "type": "array",
            "items": {"type": "string"},
        },
        "rationale": {
            "type": "string",
        },
        "confidence": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
    },
    "required": [
        "target_apis",
        "rationale",
        "confidence",
    ],
}


class LlmVulnerableApiSelector:
    """Map vulnerabilities to observed APIs using an LLM."""

    def __init__(self, client: LlmClient) -> None:
        self.client = client

    def select(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
    ) -> ApiMappingResult:
        """Select vulnerable APIs from observed usages."""

        package_usages = tuple(
            usage
            for usage in usages
            if usage.package == vulnerability.component.name
        )

        if not package_usages:
            return ApiMappingResult(
                vulnerability_id=vulnerability.id,
                status=ApiMappingStatus.UNUSED,
                rationale=(
                    "No usage of the vulnerable package was observed "
                    "in the target application."
                ),
            )

        observed_apis = _unique_apis(package_usages)
        request = LlmRequest(
            system_prompt=_load_system_prompt(),
            user_prompt=_build_user_prompt(
                vulnerability=vulnerability,
                usages=package_usages,
            ),
            temperature=0.0,
            max_tokens=1024,
            json_schema=_API_MAPPING_SCHEMA,
        )

        response = self.client.generate(request)

        return _parse_mapping_response(
            vulnerability=vulnerability,
            observed_apis=observed_apis,
            response_text=response.text,
        )


def _load_system_prompt() -> str:
    return (
        files("reveal")
        .joinpath("resources/prompts/api_mapping.txt")
        .read_text(encoding="utf-8")
    )


def _build_user_prompt(
    vulnerability: Vulnerability,
    usages: Sequence[ApiUsage],
) -> str:
    payload = {
        "vulnerability": {
            "id": vulnerability.id,
            "aliases": list(vulnerability.aliases),
            "package": vulnerability.component.name,
            "version": vulnerability.component.version,
            "description": vulnerability.description,
            "fixed_versions": list(vulnerability.fixed_versions),
        },
        "observed_usages": [
            {
                "api": usage.api,
                "file": str(usage.file),
                "line": usage.line,
                "column": usage.column,
            }
            for usage in usages
        ],
    }

    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
    )


def _parse_mapping_response(
    vulnerability: Vulnerability,
    observed_apis: tuple[str, ...],
    response_text: str,
) -> ApiMappingResult:
    try:
        value: object = json.loads(response_text)
    except json.JSONDecodeError as error:
        raise LlmError(
            "The API selector returned invalid JSON."
        ) from error

    if not isinstance(value, dict):
        raise LlmError(
            "The API selector response must be a JSON object."
        )

    response = cast(dict[str, object], value)

    target_apis = _parse_target_apis(
        response.get("target_apis"),
        observed_apis,
    )
    rationale = _parse_rationale(response.get("rationale"))
    confidence = _parse_confidence(response.get("confidence"))

    status = (
        ApiMappingStatus.MAPPED
        if target_apis
        else ApiMappingStatus.UNRESOLVED
    )

    return ApiMappingResult(
        vulnerability_id=vulnerability.id,
        status=status,
        target_apis=target_apis,
        rationale=rationale,
        confidence=confidence,
    )


def _parse_target_apis(
    value: object,
    observed_apis: tuple[str, ...],
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise LlmError(
            "The API selector response must contain a target_apis array."
        )

    targets: list[str] = []

    for item in cast(list[object], value):
        if not isinstance(item, str) or not item:
            raise LlmError(
                "Every target API must be a non-empty string."
            )

        if item not in observed_apis:
            raise LlmError(
                f"The API selector returned an unobserved API: {item}"
            )

        if item not in targets:
            targets.append(item)

    return tuple(targets)


def _parse_rationale(value: object) -> str:
    if not isinstance(value, str):
        raise LlmError(
            "The API selector response must contain a rationale string."
        )

    return value


def _parse_confidence(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
    ):
        raise LlmError(
            "The API selector response must contain numeric confidence."
        )

    confidence = float(value)

    if not 0.0 <= confidence <= 1.0:
        raise LlmError(
            "The API selector confidence must be between 0.0 and 1.0."
        )

    return confidence


def _unique_apis(
    usages: Sequence[ApiUsage],
) -> tuple[str, ...]:
    unique: list[str] = []

    for usage in usages:
        if usage.api not in unique:
            unique.append(usage.api)

    return tuple(unique)