"""Tests for the normalized JSON analysis artifact writer."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from reveal.artifacts import JsonAnalysisArtifactWriter
from reveal.exceptions import ArtifactWriteError
from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    ApiUsage,
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
from reveal.pipeline import VulnerabilityAnalysis


def create_analysis(
    tmp_path: Path,
) -> tuple[
    ScanResult,
    tuple[ApiUsage, ...],
    VulnerabilityAnalysis,
]:
    component = Component(
        name="minimist",
        version="0.0.8",
        ecosystem="npm",
        purl="pkg:npm/minimist@0.0.8",
    )
    vulnerability = Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=component,
        aliases=("CVE-2021-44906",),
        description="Prototype pollution in minimist.",
        severity="High",
        fixed_versions=("1.2.6",),
        urls=("https://example.com/advisory",),
    )
    scan = ScanResult(
        sbom=Sbom(
            format="cyclonedx-json",
            generator="syft",
            document_path=tmp_path / "sbom.cdx.json",
            components=(component,),
        ),
        vulnerabilities=(vulnerability,),
    )
    usage = ApiUsage(
        package="minimist",
        api="<module>",
        file=Path("src/routes.js"),
        line=10,
        column=5,
    )
    mapping = ApiMappingResult(
        vulnerability_id=vulnerability.id,
        status=ApiMappingStatus.MAPPED,
        target_apis=("<module>",),
        rationale="The exported parser is affected.",
        confidence=0.95,
    )
    taint = TaintResult(
        vulnerability_id=vulnerability.id,
        target_api="<module>",
        status=ReachabilityStatus.REACHABLE,
        paths=(
            TaintPath(
                source_file=Path("src/routes.js"),
                source_line=5,
                source="request.query",
                sink_file=Path("src/routes.js"),
                sink_line=10,
                sink="minimist(request.query)",
                sink_argument=0,
                steps=(
                    "request.query",
                    "arguments",
                    "minimist(arguments)",
                ),
            ),
        ),
        reason="Remote input reaches the parser.",
    )
    candidate = PocCandidate(
        language="javascript",
        code="console.log('REVEAL_REPRODUCED');",
        expected_signal="REVEAL_REPRODUCED",
        description="Reproduce prototype pollution.",
    )
    poc = PocResult(
        vulnerability_id=vulnerability.id,
        target_api="<module>",
        status=ReproductionStatus.REPRODUCED,
        attempts=(
            PocAttempt(
                number=1,
                candidate=candidate,
                exit_code=0,
                stdout="REVEAL_REPRODUCED\n",
                reproduced=True,
            ),
        ),
        evidence="The expected reproduction signal was emitted.",
    )
    vex = VexStatement(
        vulnerability_id=vulnerability.id,
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.AFFECTED,
        impact_statement="The vulnerability was reproduced.",
        action_statement="Update minimist to version 1.2.6.",
    )

    return (
        scan,
        (usage,),
        VulnerabilityAnalysis(
            vulnerability=vulnerability,
            mapping=mapping,
            taint_results=(taint,),
            poc_results=(poc,),
            vex_statement=vex,
        ),
    )


def test_write_serializes_complete_analysis(
    tmp_path: Path,
) -> None:
    scan, usages, analysis = create_analysis(tmp_path)
    output_path = tmp_path / "results" / "analysis.json"
    vex_path = tmp_path / "results" / "openvex.json"

    result = JsonAnalysisArtifactWriter().write(
        scan=scan,
        usages=usages,
        analyses=(analysis,),
        output_path=output_path,
        vex_path=vex_path,
        timestamp=datetime(
            2026,
            7,
            19,
            1,
            30,
            tzinfo=timezone.utc,
        ),
    )

    assert result == output_path

    document = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert document["schema_version"] == 1
    assert document["generated_at"] == "2026-07-19T01:30:00Z"
    assert document["tool"] == {"name": "REVEAL"}

    assert document["summary"] == {
        "component_count": 1,
        "vulnerability_count": 1,
        "observed_usage_count": 1,
        "mapped_vulnerability_count": 1,
        "reachable_target_count": 1,
        "reproduced_target_count": 1,
        "vex_status_counts": {
            "affected": 1,
            "not_affected": 0,
            "fixed": 0,
            "under_investigation": 0,
        },
    }

    serialized_analysis = document["analyses"][0]

    assert serialized_analysis["mapping"]["status"] == "mapped"
    assert serialized_analysis["mapping"]["target_apis"] == [
        "<module>"
    ]
    assert serialized_analysis["taint_results"][0]["status"] == (
        "reachable"
    )
    assert (
        serialized_analysis["taint_results"][0]["paths"][0][
            "sink_argument"
        ]
        == 0
    )
    assert serialized_analysis["poc_results"][0]["status"] == (
        "reproduced"
    )
    assert (
        serialized_analysis["poc_results"][0]["attempts"][0][
            "stdout"
        ]
        == "REVEAL_REPRODUCED\n"
    )
    assert serialized_analysis["vex_statement"]["status"] == (
        "affected"
    )
    assert document["outputs"]["openvex"] == str(vex_path)


def test_write_accepts_empty_analysis_result(
    tmp_path: Path,
) -> None:
    scan = ScanResult(
        sbom=Sbom(
            format="cyclonedx-json",
            generator="syft",
            document_path=tmp_path / "sbom.json",
            components=(),
        ),
        vulnerabilities=(),
    )
    output_path = tmp_path / "analysis.json"

    JsonAnalysisArtifactWriter().write(
        scan=scan,
        usages=(),
        analyses=(),
        output_path=output_path,
        timestamp=datetime.now(timezone.utc),
    )

    document = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert document["summary"]["vulnerability_count"] == 0
    assert document["analyses"] == []
    assert document["outputs"]["openvex"] is None


def test_write_converts_timestamp_to_utc(
    tmp_path: Path,
) -> None:
    scan = ScanResult(
        sbom=Sbom(
            format="cyclonedx-json",
            generator="fake",
            document_path=tmp_path / "sbom.json",
            components=(),
        ),
        vulnerabilities=(),
    )
    output_path = tmp_path / "analysis.json"

    JsonAnalysisArtifactWriter().write(
        scan=scan,
        usages=(),
        analyses=(),
        output_path=output_path,
        timestamp=datetime(
            2026,
            7,
            19,
            10,
            30,
            tzinfo=timezone(timedelta(hours=9)),
        ),
    )

    document = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert document["generated_at"] == "2026-07-19T01:30:00Z"


def test_write_rejects_naive_timestamp(
    tmp_path: Path,
) -> None:
    scan = ScanResult(
        sbom=Sbom(
            format="cyclonedx-json",
            generator="fake",
            document_path=tmp_path / "sbom.json",
            components=(),
        ),
        vulnerabilities=(),
    )

    with pytest.raises(
        ArtifactWriteError,
        match="timezone information",
    ):
        JsonAnalysisArtifactWriter().write(
            scan=scan,
            usages=(),
            analyses=(),
            output_path=tmp_path / "analysis.json",
            timestamp=datetime(2026, 7, 19, 1, 30),
        )
