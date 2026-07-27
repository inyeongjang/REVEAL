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
    Vulnerability
)


_API_MAPPING_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "target_apis": {
            "type": "array",
            "items": {
                "type": "string",
            },
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
    """Map vulnerabilities to vulnerable package APIs using an LLM."""

    def __init__(
        self,
        client: LlmClient,
        min_confidence: float = 0.75,
    ) -> None:
        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError(
                "min_confidence must be between 0.0 and 1.0"
            )

        self.client = client
        self.min_confidence = min_confidence

    def select(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
    ) -> ApiMappingResult:
        """Select vulnerable APIs for one vulnerability."""

        package_usages = tuple(
            usage
            for usage in usages
            if usage.package
            == vulnerability.component.name
        )

        if not package_usages:
            return ApiMappingResult(
                vulnerability_id=vulnerability.id,
                status=ApiMappingStatus.UNUSED,
                rationale=(
                    "No usage of the vulnerable package was "
                    "observed in the target application."
                ),
            )

        observed_apis = _unique_apis(package_usages)

        result = self._select_once(
            vulnerability=vulnerability,
            usages=package_usages,
            observed_apis=observed_apis,
        )

        return self._apply_confidence_threshold(result)

    def _select_once(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
        observed_apis: tuple[str, ...],
    ) -> ApiMappingResult:
        system_prompt = _load_system_prompt()

        user_prompt = _build_user_prompt(
            vulnerability=vulnerability,
            usages=usages,
        )

        request = LlmRequest(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=_API_MAPPING_SCHEMA,
            metadata={
                "stage": "api_mapping",
                "vulnerability_id": vulnerability.id,
                "component": (
                    f"{vulnerability.component.name}@"
                    f"{vulnerability.component.version}"
                ),
            },
        )

        response = self.client.generate(request)

        return _parse_mapping_response(
            vulnerability=vulnerability,
            observed_apis=observed_apis,
            response_text=response.text,
        )

    def _apply_confidence_threshold(
        self,
        result: ApiMappingResult,
    ) -> ApiMappingResult:
        if result.status is not ApiMappingStatus.MAPPED:
            return result

        if result.confidence is None:
            return ApiMappingResult(
                vulnerability_id=result.vulnerability_id,
                status=ApiMappingStatus.UNRESOLVED,
                rationale=(
                    "The LLM returned a mapped result without "
                    "a confidence value."
                ),
            )

        if result.confidence >= self.min_confidence:
            return result

        return ApiMappingResult(
            vulnerability_id=result.vulnerability_id,
            status=ApiMappingStatus.UNRESOLVED,
            target_apis=(),
            rationale=(
                f"LLM mapping confidence "
                f"{result.confidence:.3f} is below the "
                f"configured threshold "
                f"{self.min_confidence:.3f}. "
                f"Original rationale: {result.rationale}"
            ),
            confidence=result.confidence,
        )


def _load_system_prompt() -> str:
    return (
        files("reveal")
        .joinpath(
            "resources/prompts/api_mapping.txt"
        )
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
            "fixed_versions": list(
                vulnerability.fixed_versions
            ),
            "urls": list(vulnerability.urls),
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
            "The API selector response must be "
            "a JSON object."
        )

    response = cast(dict[str, object], value)

    target_apis = _parse_target_apis(
        response.get("target_apis")
    )
    rationale = _parse_rationale(
        response.get("rationale")
    )
    confidence = _parse_confidence(
        response.get("confidence")
    )

    status = (
        ApiMappingStatus.MAPPED
        if target_apis
        else ApiMappingStatus.UNRESOLVED
    )

    observed_targets = tuple(
        api
        for api in target_apis
        if api in observed_apis
    )

    if target_apis and not observed_targets:
        rationale = (
            f"{rationale} The vulnerable API was mapped, "
            "but none of the mapped APIs were observed in "
            "the target application."
        )

    return ApiMappingResult(
        vulnerability_id=vulnerability.id,
        status=status,
        target_apis=target_apis,
        rationale=rationale,
        confidence=confidence,
    )


def _parse_target_apis(value: object,) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise LlmError(
            "The API selector response must contain "
            "a target_apis array."
        )

    targets: list[str] = []

    for item in cast(list[object], value):
        if not isinstance(item, str):
            raise LlmError(
                "Every target API must be a string."
            )

        normalized = item.strip()

        if not normalized:
            raise LlmError(
                "Every target API must be "
                "a non-empty string."
            )

        if normalized not in targets:
            targets.append(normalized)

    return tuple(targets)


def _parse_rationale(value: object,) -> str:
    if not isinstance(value, str):
        raise LlmError(
            "The API selector response must contain "
            "a rationale string."
        )

    rationale = value.strip()

    if not rationale:
        raise LlmError(
            "The API selector rationale must not be empty."
        )

    return rationale


def _parse_confidence(
    value: object,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
    ):
        raise LlmError(
            "The API selector response must contain "
            "numeric confidence."
        )

    confidence = float(value)

    if not 0.0 <= confidence <= 1.0:
        raise LlmError(
            "The API selector confidence must be "
            "between 0.0 and 1.0."
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