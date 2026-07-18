"""Tests for shared REVEAL domain models."""

from pathlib import Path

import pytest

from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    Component,
    PocAttempt,
    PocCandidate,
    PocResult,
    ReachabilityStatus,
    ReproductionStatus,
    Sbom,
    ScanResult,
    TaintPath,
    TaintResult,
    VexStatement,
    VexStatus,
    Vulnerability,
)


def create_component() -> Component:
    return Component(
        name="minimist",
        version="0.0.8",
        ecosystem="npm",
        purl="pkg:npm/minimist@0.0.8",
    )


def test_scan_result_counts_vulnerabilities(tmp_path: Path) -> None:
    component = create_component()
    sbom = Sbom(
        format="cyclonedx-json",
        generator="syft",
        document_path=tmp_path / "sbom.json",
        components=(component,),
    )
    vulnerability = Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=component,
        aliases=("CVE-2021-44906",),
    )

    result = ScanResult(
        sbom=sbom,
        vulnerabilities=(vulnerability,),
    )

    assert result.finding_count == 1
    assert result.vulnerabilities[0].component == component


def test_api_mapping_reports_selected_targets() -> None:
    result = ApiMappingResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        status=ApiMappingStatus.MAPPED,
        target_apis=("minimist",),
        confidence=0.9,
    )

    assert result.has_targets is True


def test_api_mapping_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError):
        ApiMappingResult(
            vulnerability_id="GHSA-xvch-5gv4-984h",
            status=ApiMappingStatus.MAPPED,
            confidence=1.1,
        )


def test_taint_result_counts_paths() -> None:
    path = TaintPath(
        source_file=Path("src/routes/arguments.js"),
        source_line=13,
        source="req.body.argv",
        sink_file=Path("src/routes/arguments.js"),
        sink_line=13,
        sink="minimist(req.body.argv)",
        sink_argument=0,
    )
    result = TaintResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        target_api="minimist",
        status=ReachabilityStatus.REACHABLE,
        paths=(path,),
    )

    assert result.path_count == 1


def test_poc_result_counts_attempts() -> None:
    candidate = PocCandidate(
        language="javascript",
        code='console.log("POC_FAILED");',
        expected_signal="POC_SUCCESS",
    )
    attempt = PocAttempt(
        number=1,
        candidate=candidate,
        exit_code=0,
        stdout="POC_FAILED",
        reproduced=False,
    )
    result = PocResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        target_api="minimist",
        status=ReproductionStatus.NOT_REPRODUCED,
        attempts=(attempt,),
    )

    assert result.attempt_count == 1
    assert result.status is ReproductionStatus.NOT_REPRODUCED


def test_vex_status_is_separate_from_reproduction_status() -> None:
    statement = VexStatement(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.UNDER_INVESTIGATION,
        impact_statement="Generated PoCs did not reproduce the vulnerability.",
    )

    assert statement.status is VexStatus.UNDER_INVESTIGATION
    assert statement.status.value != ReproductionStatus.NOT_REPRODUCED.value