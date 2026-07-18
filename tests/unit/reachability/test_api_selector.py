"""Tests for the vulnerable API selector abstraction."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    ApiUsage,
    Component,
    Vulnerability,
)
from reveal.reachability import VulnerableApiSelector


class FakeVulnerableApiSelector:
    """Minimal selector used to verify the shared interface."""

    def select(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
    ) -> ApiMappingResult:
        matching_apis = tuple(
            usage.api
            for usage in usages
            if usage.package == vulnerability.component.name
        )

        if not matching_apis:
            return ApiMappingResult(
                vulnerability_id=vulnerability.id,
                status=ApiMappingStatus.UNUSED,
                rationale="No usage of the vulnerable package was observed.",
            )

        return ApiMappingResult(
            vulnerability_id=vulnerability.id,
            status=ApiMappingStatus.MAPPED,
            target_apis=matching_apis,
            rationale="Observed APIs were selected for analysis.",
            confidence=1.0,
        )


def run_selector(
    selector: VulnerableApiSelector,
    vulnerability: Vulnerability,
    usages: Sequence[ApiUsage],
) -> ApiMappingResult:
    """Execute any implementation satisfying the selector protocol."""

    return selector.select(
        vulnerability=vulnerability,
        usages=usages,
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


def test_selector_accepts_structural_implementation() -> None:
    vulnerability = create_vulnerability()
    usages = (
        ApiUsage(
            package="minimist",
            api="<module>",
            file=Path("src/app.js"),
            line=10,
        ),
        ApiUsage(
            package="lodash",
            api="get",
            file=Path("src/util.js"),
            line=5,
        ),
    )

    result = run_selector(
        selector=FakeVulnerableApiSelector(),
        vulnerability=vulnerability,
        usages=usages,
    )

    assert result.vulnerability_id == vulnerability.id
    assert result.status is ApiMappingStatus.MAPPED
    assert result.target_apis == ("<module>",)
    assert result.confidence == 1.0


def test_selector_reports_unused_package() -> None:
    vulnerability = create_vulnerability()
    usages = (
        ApiUsage(
            package="lodash",
            api="get",
            file=Path("src/util.js"),
            line=5,
        ),
    )

    result = run_selector(
        selector=FakeVulnerableApiSelector(),
        vulnerability=vulnerability,
        usages=usages,
    )

    assert result.status is ApiMappingStatus.UNUSED
    assert result.target_apis == ()
    assert result.confidence is None