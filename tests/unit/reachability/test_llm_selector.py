"""Tests for the LLM-based vulnerable API selector."""

from __future__ import annotations

from pathlib import Path

import pytest

from reveal.exceptions import LlmError
from reveal.llm import LlmRequest, LlmResponse
from reveal.models import (
    ApiMappingStatus,
    ApiUsage,
    Component,
    Vulnerability,
)
from reveal.reachability.llm_selector import (
    LlmVulnerableApiSelector,
)


class FakeLlmClient:
    """Deterministic LLM client for selector tests."""

    def __init__(self, response_text: str) -> None:
        self.response_text = response_text
        self.requests: list[LlmRequest] = []

    def generate(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)

        return LlmResponse(
            text=self.response_text,
            provider="fake",
            model="fake-model",
        )


def create_vulnerability() -> Vulnerability:
    component = Component(
        name="minimist",
        version="0.0.8",
        ecosystem="npm",
        purl="pkg:npm/minimist@0.0.8",
    )

    return Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=component,
        aliases=("CVE-2021-44906",),
        description="Prototype pollution in minimist.",
        fixed_versions=("1.2.6",),
    )


def create_usages() -> tuple[ApiUsage, ...]:
    return (
        ApiUsage(
            package="minimist",
            api="<module>",
            file=Path("src/app.js"),
            line=10,
            column=5,
        ),
        ApiUsage(
            package="minimist",
            api="parse",
            file=Path("src/app.js"),
            line=12,
            column=3,
        ),
        ApiUsage(
            package="lodash",
            api="get",
            file=Path("src/util.js"),
            line=7,
            column=8,
        ),
    )


def test_selector_maps_observed_api() -> None:
    client = FakeLlmClient(
        """
        {
          "target_apis": ["<module>"],
          "rationale": "The vulnerable behavior is exposed by the module call.",
          "confidence": 0.9
        }
        """
    )
    selector = LlmVulnerableApiSelector(client)

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=create_usages(),
    )

    assert result.status is ApiMappingStatus.MAPPED
    assert result.target_apis == ("<module>",)
    assert result.confidence == 0.9
    assert len(client.requests) == 1

    request = client.requests[0]

    assert request.temperature == 0.0
    assert request.json_schema is not None
    assert "GHSA-xvch-5gv4-984h" in request.user_prompt
    assert '"api": "<module>"' in request.user_prompt
    assert '"api": "parse"' in request.user_prompt
    assert '"api": "get"' not in request.user_prompt


def test_selector_skips_llm_when_package_is_unused() -> None:
    client = FakeLlmClient(
        """
        {
          "target_apis": [],
          "rationale": "Unused.",
          "confidence": 1.0
        }
        """
    )
    selector = LlmVulnerableApiSelector(client)

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=(
            ApiUsage(
                package="lodash",
                api="get",
                file=Path("src/util.js"),
                line=7,
            ),
        ),
    )

    assert result.status is ApiMappingStatus.UNUSED
    assert result.target_apis == ()
    assert client.requests == []


def test_selector_returns_unresolved_for_empty_targets() -> None:
    client = FakeLlmClient(
        """
        {
          "target_apis": [],
          "rationale": "The description does not identify a specific API.",
          "confidence": 0.2
        }
        """
    )
    selector = LlmVulnerableApiSelector(client)

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=create_usages(),
    )

    assert result.status is ApiMappingStatus.UNRESOLVED
    assert result.target_apis == ()
    assert result.confidence == 0.2


def test_selector_rejects_unobserved_api() -> None:
    client = FakeLlmClient(
        """
        {
          "target_apis": ["constructor.prototype"],
          "rationale": "Potential vulnerable API.",
          "confidence": 0.8
        }
        """
    )
    selector = LlmVulnerableApiSelector(client)

    with pytest.raises(
        LlmError,
        match="unobserved API",
    ):
        selector.select(
            vulnerability=create_vulnerability(),
            usages=create_usages(),
        )


def test_selector_rejects_invalid_json() -> None:
    client = FakeLlmClient("not valid JSON")
    selector = LlmVulnerableApiSelector(client)

    with pytest.raises(
        LlmError,
        match="invalid JSON",
    ):
        selector.select(
            vulnerability=create_vulnerability(),
            usages=create_usages(),
        )


def test_selector_removes_duplicate_targets() -> None:
    client = FakeLlmClient(
        """
        {
          "target_apis": ["parse", "parse"],
          "rationale": "The parse member is relevant.",
          "confidence": 0.7
        }
        """
    )
    selector = LlmVulnerableApiSelector(client)

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=create_usages(),
    )

    assert result.target_apis == ("parse",)