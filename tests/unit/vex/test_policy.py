"""Tests for the default VEX decision policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from reveal.exceptions import VexDecisionError
from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    Component,
    PocResult,
    ReachabilityStatus,
    ReproductionStatus,
    TaintPath,
    TaintResult,
    VexStatus,
    Vulnerability,
)
from reveal.vex import DefaultVexDecisionPolicy


def create_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=Component(
            name="minimist",
            version="0.0.8",
            ecosystem="npm",
            purl="pkg:npm/minimist@0.0.8",
        ),
        aliases=("CVE-2021-44906",),
        description="Prototype pollution in minimist.",
        fixed_versions=("1.2.6",),
    )


def create_mapping(
    *,
    status: ApiMappingStatus = ApiMappingStatus.MAPPED,
    target_apis: tuple[str, ...] = ("<module>",),
) -> ApiMappingResult:
    return ApiMappingResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        status=status,
        target_apis=target_apis,
        rationale="Test API mapping.",
        confidence=0.9 if status is ApiMappingStatus.MAPPED else None,
    )


def create_taint(
    *,
    target_api: str = "<module>",
    status: ReachabilityStatus,
) -> TaintResult:
    paths = ()

    if status is ReachabilityStatus.REACHABLE:
        paths = (
            TaintPath(
                source_file=Path("src/routes.js"),
                source_line=5,
                source="request.query",
                sink_file=Path("src/routes.js"),
                sink_line=10,
                sink="minimist(arguments)",
                sink_argument=0,
            ),
        )

    return TaintResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        target_api=target_api,
        status=status,
        paths=paths,
    )


def create_poc_result(
    *,
    status: ReproductionStatus,
    target_api: str = "<module>",
) -> PocResult:
    return PocResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        target_api=target_api,
        status=status,
        evidence=(
            "Candidate emitted REVEAL_REPRODUCED."
            if status is ReproductionStatus.REPRODUCED
            else ""
        ),
        reason="Test reproduction result.",
    )


def test_unused_package_is_not_affected() -> None:
    statement = DefaultVexDecisionPolicy().decide(
        vulnerability=create_vulnerability(),
        mapping=create_mapping(
            status=ApiMappingStatus.UNUSED,
            target_apis=(),
        ),
        taint_results=(),
        poc_results=(),
    )

    assert statement.status is VexStatus.NOT_AFFECTED
    assert (
        statement.justification
        == "vulnerable_code_not_in_execute_path"
    )


def test_unresolved_mapping_remains_under_investigation() -> None:
    statement = DefaultVexDecisionPolicy().decide(
        vulnerability=create_vulnerability(),
        mapping=create_mapping(
            status=ApiMappingStatus.UNRESOLVED,
            target_apis=(),
        ),
        taint_results=(),
        poc_results=(),
    )

    assert statement.status is VexStatus.UNDER_INVESTIGATION
    assert statement.impact_statement == "Test API mapping."


def test_all_targets_unreachable_are_not_affected() -> None:
    mapping = create_mapping(
        target_apis=("<module>", "parse"),
    )

    statement = DefaultVexDecisionPolicy().decide(
        vulnerability=create_vulnerability(),
        mapping=mapping,
        taint_results=(
            create_taint(
                target_api="<module>",
                status=ReachabilityStatus.UNREACHABLE,
            ),
            create_taint(
                target_api="parse",
                status=ReachabilityStatus.UNREACHABLE,
            ),
        ),
        poc_results=(),
    )

    assert statement.status is VexStatus.NOT_AFFECTED
    assert statement.justification == (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )


def test_partial_taint_analysis_remains_under_investigation() -> None:
    statement = DefaultVexDecisionPolicy().decide(
        vulnerability=create_vulnerability(),
        mapping=create_mapping(
            target_apis=("<module>", "parse"),
        ),
        taint_results=(
            create_taint(
                target_api="<module>",
                status=ReachabilityStatus.UNREACHABLE,
            ),
        ),
        poc_results=(),
    )

    assert statement.status is VexStatus.UNDER_INVESTIGATION


def test_reachable_api_without_reproduction_is_under_investigation() -> None:
    statement = DefaultVexDecisionPolicy().decide(
        vulnerability=create_vulnerability(),
        mapping=create_mapping(),
        taint_results=(
            create_taint(
                status=ReachabilityStatus.REACHABLE,
            ),
        ),
        poc_results=(),
    )

    assert statement.status is VexStatus.UNDER_INVESTIGATION
    assert "reproduction has not been confirmed" in (
        statement.impact_statement or ""
    )


def test_successful_poc_marks_product_as_affected() -> None:
    statement = DefaultVexDecisionPolicy().decide(
        vulnerability=create_vulnerability(),
        mapping=create_mapping(),
        taint_results=(
            create_taint(
                status=ReachabilityStatus.REACHABLE,
            ),
        ),
        poc_results=(
            create_poc_result(
                status=ReproductionStatus.REPRODUCED,
            ),
        ),
    )

    assert statement.status is VexStatus.AFFECTED
    assert statement.impact_statement == (
        "Candidate emitted REVEAL_REPRODUCED."
    )
    assert statement.action_statement == (
        "Update minimist to one of the reported fixed versions: 1.2.6."
    )


def test_failed_poc_does_not_mark_product_not_affected() -> None:
    statement = DefaultVexDecisionPolicy().decide(
        vulnerability=create_vulnerability(),
        mapping=create_mapping(),
        taint_results=(
            create_taint(
                status=ReachabilityStatus.REACHABLE,
            ),
        ),
        poc_results=(
            create_poc_result(
                status=ReproductionStatus.NOT_REPRODUCED,
            ),
        ),
    )

    assert statement.status is VexStatus.UNDER_INVESTIGATION
    assert "does not establish" in (
        statement.impact_statement or ""
    )


def test_inconclusive_poc_remains_under_investigation() -> None:
    statement = DefaultVexDecisionPolicy().decide(
        vulnerability=create_vulnerability(),
        mapping=create_mapping(),
        taint_results=(
            create_taint(
                status=ReachabilityStatus.REACHABLE,
            ),
        ),
        poc_results=(
            create_poc_result(
                status=ReproductionStatus.INCONCLUSIVE,
            ),
        ),
    )

    assert statement.status is VexStatus.UNDER_INVESTIGATION
    assert "inconclusive" in (
        statement.impact_statement or ""
    )


def test_policy_rejects_mismatched_vulnerability_id() -> None:
    mapping = ApiMappingResult(
        vulnerability_id="CVE-OTHER",
        status=ApiMappingStatus.UNRESOLVED,
    )

    with pytest.raises(
        VexDecisionError,
        match="API mapping vulnerability",
    ):
        DefaultVexDecisionPolicy().decide(
            vulnerability=create_vulnerability(),
            mapping=mapping,
            taint_results=(),
            poc_results=(),
        )


def test_policy_rejects_unmapped_taint_target() -> None:
    with pytest.raises(
        VexDecisionError,
        match="was not selected",
    ):
        DefaultVexDecisionPolicy().decide(
            vulnerability=create_vulnerability(),
            mapping=create_mapping(),
            taint_results=(
                create_taint(
                    target_api="other",
                    status=ReachabilityStatus.REACHABLE,
                ),
            ),
            poc_results=(),
        )