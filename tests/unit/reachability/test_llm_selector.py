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
    VulnerabilityEvidence,
)
from reveal.reachability.llm_selector import (
    LlmVulnerableApiSelector,
)


class FakeLlmClient:
    """Deterministic LLM client supporting multiple responses."""

    def __init__(self, responses: tuple[str, ...]) -> None:
        self.responses = responses
        self.requests: list[LlmRequest] = []

    def generate(self, request: LlmRequest) -> LlmResponse:
        response_index = len(self.requests)

        if response_index >= len(self.responses):
            raise AssertionError("Unexpected additional LLM request")

        self.requests.append(request)

        return LlmResponse(
            text=self.responses[response_index],
            provider="fake",
            model="fake-model",
        )


class FakeEvidenceRetriever:
    """Deterministic evidence retriever for selector tests."""

    def __init__(
        self,
        evidence: tuple[VulnerabilityEvidence, ...],
    ) -> None:
        self.evidence = evidence
        self.calls: list[tuple[Vulnerability, int]] = []

    def retrieve(
        self,
        vulnerability: Vulnerability,
        *,
        limit: int = 5,
    ) -> tuple[VulnerabilityEvidence, ...]:
        self.calls.append((vulnerability, limit))

        return self.evidence[:limit]


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


def test_selector_maps_observed_api_without_fallback() -> None:
    client = FakeLlmClient(
        (
            """
            {
              "target_apis": ["<module>"],
              "rationale": "The module call exposes the vulnerable parser.",
              "confidence": 0.9
            }
            """,
        )
    )
    retriever = FakeEvidenceRetriever(
        (
            VulnerabilityEvidence(
                source="github-advisory",
                content="Additional evidence.",
            ),
        )
    )
    selector = LlmVulnerableApiSelector(
        client=client,
        retriever=retriever,
    )

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=create_usages(),
    )

    assert result.status is ApiMappingStatus.MAPPED
    assert result.target_apis == ("<module>",)
    assert result.confidence == 0.9
    assert len(client.requests) == 1
    assert retriever.calls == []
    assert '"retrieved_evidence": []' in client.requests[0].user_prompt


def test_selector_skips_llm_and_retriever_when_package_is_unused() -> None:
    client = FakeLlmClient(())
    retriever = FakeEvidenceRetriever(())
    selector = LlmVulnerableApiSelector(
        client=client,
        retriever=retriever,
    )

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
    assert retriever.calls == []


def test_selector_returns_unresolved_without_retriever() -> None:
    client = FakeLlmClient(
        (
            """
            {
              "target_apis": [],
              "rationale": "The available description is insufficient.",
              "confidence": 0.2
            }
            """,
        )
    )
    selector = LlmVulnerableApiSelector(client)

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=create_usages(),
    )

    assert result.status is ApiMappingStatus.UNRESOLVED
    assert result.target_apis == ()
    assert result.confidence == 0.2
    assert len(client.requests) == 1


def test_selector_retries_with_retrieved_evidence() -> None:
    initial_response = """
    {
      "target_apis": [],
      "rationale": "The description does not identify the API.",
      "confidence": 0.2
    }
    """
    fallback_response = """
    {
      "target_apis": ["<module>"],
      "rationale": "The advisory confirms that the exported parser is affected.",
      "confidence": 0.95
    }
    """
    evidence = VulnerabilityEvidence(
        source="github-advisory",
        title="Prototype pollution in minimist",
        content=(
            "The vulnerability is triggered when the exported minimist "
            "function parses crafted property paths."
        ),
        reference="GHSA-xvch-5gv4-984h",
        score=1.0,
    )
    client = FakeLlmClient(
        (
            initial_response,
            fallback_response,
        )
    )
    retriever = FakeEvidenceRetriever((evidence,))
    selector = LlmVulnerableApiSelector(
        client=client,
        retriever=retriever,
        evidence_limit=3,
    )
    vulnerability = create_vulnerability()

    result = selector.select(
        vulnerability=vulnerability,
        usages=create_usages(),
    )

    assert result.status is ApiMappingStatus.MAPPED
    assert result.target_apis == ("<module>",)
    assert result.confidence == 0.95
    assert len(client.requests) == 2
    assert retriever.calls == [(vulnerability, 3)]

    fallback_prompt = client.requests[1].user_prompt

    assert "github-advisory" in fallback_prompt
    assert "The vulnerability is triggered" in fallback_prompt
    assert "GHSA-xvch-5gv4-984h" in fallback_prompt


def test_selector_does_not_retry_when_no_evidence_is_found() -> None:
    client = FakeLlmClient(
        (
            """
            {
              "target_apis": [],
              "rationale": "Insufficient evidence.",
              "confidence": 0.1
            }
            """,
        )
    )
    retriever = FakeEvidenceRetriever(())
    selector = LlmVulnerableApiSelector(
        client=client,
        retriever=retriever,
    )

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=create_usages(),
    )

    assert result.status is ApiMappingStatus.UNRESOLVED
    assert len(client.requests) == 1
    assert len(retriever.calls) == 1


def test_selector_returns_fallback_unresolved_result() -> None:
    client = FakeLlmClient(
        (
            """
            {
              "target_apis": [],
              "rationale": "Initial evidence is insufficient.",
              "confidence": 0.1
            }
            """,
            """
            {
              "target_apis": [],
              "rationale": "Retrieved evidence still does not identify an API.",
              "confidence": 0.4
            }
            """,
        )
    )
    retriever = FakeEvidenceRetriever(
        (
            VulnerabilityEvidence(
                source="advisory",
                content="General vulnerability information.",
            ),
        )
    )
    selector = LlmVulnerableApiSelector(
        client=client,
        retriever=retriever,
    )

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=create_usages(),
    )

    assert result.status is ApiMappingStatus.UNRESOLVED
    assert result.confidence == 0.4
    assert result.rationale.startswith("Retrieved evidence")


def test_selector_rejects_unobserved_api_from_fallback() -> None:
    client = FakeLlmClient(
        (
            """
            {
              "target_apis": [],
              "rationale": "Initial mapping failed.",
              "confidence": 0.1
            }
            """,
            """
            {
              "target_apis": ["constructor.prototype"],
              "rationale": "Potential vulnerable API.",
              "confidence": 0.8
            }
            """,
        )
    )
    retriever = FakeEvidenceRetriever(
        (
            VulnerabilityEvidence(
                source="advisory",
                content="Prototype pollution details.",
            ),
        )
    )
    selector = LlmVulnerableApiSelector(
        client=client,
        retriever=retriever,
    )

    with pytest.raises(
        LlmError,
        match="unobserved API",
    ):
        selector.select(
            vulnerability=create_vulnerability(),
            usages=create_usages(),
        )


def test_selector_rejects_invalid_json() -> None:
    client = FakeLlmClient(("not valid JSON",))
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
        (
            """
            {
              "target_apis": ["parse", "parse"],
              "rationale": "The parse member is relevant.",
              "confidence": 0.7
            }
            """,
        )
    )
    selector = LlmVulnerableApiSelector(client)

    result = selector.select(
        vulnerability=create_vulnerability(),
        usages=create_usages(),
    )

    assert result.target_apis == ("parse",)


def test_selector_rejects_non_positive_evidence_limit() -> None:
    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        LlmVulnerableApiSelector(
            client=FakeLlmClient(()),
            evidence_limit=0,
        )