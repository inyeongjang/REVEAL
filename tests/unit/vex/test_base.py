"""Tests for the VEX decision policy abstraction."""

from __future__ import annotations

from collections.abc import Sequence

from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    Component,
    PocResult,
    TaintResult,
    VexStatement,
    VexStatus,
    Vulnerability,
)
from reveal.vex import VexDecisionPolicy


class FakeVexDecisionPolicy:
    """Minimal policy used to verify the shared interface."""

    def decide(
        self,
        vulnerability: Vulnerability,
        mapping: ApiMappingResult,
        taint_results: Sequence[TaintResult],
        poc_results: Sequence[PocResult],
    ) -> VexStatement:
        del mapping, taint_results, poc_results

        return VexStatement(
            vulnerability_id=vulnerability.id,
            products=(vulnerability.component.purl or "unknown",),
            status=VexStatus.UNDER_INVESTIGATION,
        )


def run_policy(
    policy: VexDecisionPolicy,
    vulnerability: Vulnerability,
    mapping: ApiMappingResult,
) -> VexStatement:
    """Execute any implementation satisfying the policy protocol."""

    return policy.decide(
        vulnerability=vulnerability,
        mapping=mapping,
        taint_results=(),
        poc_results=(),
    )


def test_policy_accepts_structural_implementation() -> None:
    vulnerability = Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=Component(
            name="minimist",
            version="0.0.8",
            ecosystem="npm",
            purl="pkg:npm/minimist@0.0.8",
        ),
    )
    mapping = ApiMappingResult(
        vulnerability_id=vulnerability.id,
        status=ApiMappingStatus.UNRESOLVED,
    )

    statement = run_policy(
        policy=FakeVexDecisionPolicy(),
        vulnerability=vulnerability,
        mapping=mapping,
    )

    assert statement.status is VexStatus.UNDER_INVESTIGATION
    assert statement.products == ("pkg:npm/minimist@0.0.8",)