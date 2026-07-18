"""Tests for the vulnerability evidence retriever abstraction."""

from __future__ import annotations

import pytest

from reveal.models import (
    Component,
    Vulnerability,
    VulnerabilityEvidence,
)
from reveal.reachability import VulnerabilityEvidenceRetriever


class FakeEvidenceRetriever:
    """Minimal retriever used to verify the shared interface."""

    def __init__(
        self,
        evidence: tuple[VulnerabilityEvidence, ...],
    ) -> None:
        self.evidence = evidence
        self.retrieved_vulnerabilities: list[Vulnerability] = []

    def retrieve(
        self,
        vulnerability: Vulnerability,
        *,
        limit: int = 5,
    ) -> tuple[VulnerabilityEvidence, ...]:
        self.retrieved_vulnerabilities.append(vulnerability)

        return self.evidence[:limit]


def run_retriever(
    retriever: VulnerabilityEvidenceRetriever,
    vulnerability: Vulnerability,
    *,
    limit: int = 5,
) -> tuple[VulnerabilityEvidence, ...]:
    """Execute any implementation satisfying the retriever protocol."""

    return retriever.retrieve(
        vulnerability,
        limit=limit,
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
    )


def test_retriever_accepts_structural_implementation() -> None:
    vulnerability = create_vulnerability()
    first = VulnerabilityEvidence(
        source="github-advisory",
        title="Prototype pollution in minimist",
        content="Affected versions allow prototype pollution through parsed keys.",
        reference="GHSA-xvch-5gv4-984h",
        score=0.95,
    )
    second = VulnerabilityEvidence(
        source="package-documentation",
        title="minimist usage",
        content="The package exports a function that parses argument arrays.",
        reference="minimist-readme",
        score=0.75,
    )
    retriever = FakeEvidenceRetriever((first, second))

    result = run_retriever(
        retriever,
        vulnerability,
        limit=1,
    )

    assert result == (first,)
    assert retriever.retrieved_vulnerabilities == [vulnerability]


def test_retriever_returns_empty_tuple_without_evidence() -> None:
    vulnerability = create_vulnerability()
    retriever = FakeEvidenceRetriever(())

    result = run_retriever(
        retriever,
        vulnerability,
    )

    assert result == ()


def test_evidence_rejects_empty_source() -> None:
    with pytest.raises(
        ValueError,
        match="source must not be empty",
    ):
        VulnerabilityEvidence(
            source=" ",
            content="Relevant vulnerability information.",
        )


def test_evidence_rejects_empty_content() -> None:
    with pytest.raises(
        ValueError,
        match="content must not be empty",
    ):
        VulnerabilityEvidence(
            source="github-advisory",
            content=" ",
        )


def test_evidence_rejects_invalid_score() -> None:
    with pytest.raises(
        ValueError,
        match="score must be between",
    ):
        VulnerabilityEvidence(
            source="github-advisory",
            content="Relevant vulnerability information.",
            score=1.1,
        )