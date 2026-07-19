"""Tests for end-to-end analysis pipeline orchestration."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

import pytest

from reveal.exceptions import PipelineError
from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    ApiUsage,
    Component,
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
from reveal.pipeline import AnalysisPipeline
from reveal.vex import DefaultVexDecisionPolicy


class FakeSbomGenerator:
    """Deterministic SBOM generator for pipeline tests."""

    def __init__(self, component: Component) -> None:
        self.component = component
        self.calls: list[tuple[Path, Path]] = []

    def generate(
        self,
        source: Path,
        output_path: Path,
    ) -> Sbom:
        self.calls.append((source, output_path))
        output_path.write_text("{}", encoding="utf-8")

        return Sbom(
            format="cyclonedx-json",
            generator="fake",
            document_path=output_path,
            components=(self.component,),
        )


class FakeVulnerabilityScanner:
    """Deterministic vulnerability scanner for pipeline tests."""

    def __init__(
        self,
        vulnerabilities: tuple[Vulnerability, ...],
    ) -> None:
        self.vulnerabilities = vulnerabilities
        self.calls: list[tuple[Sbom, Path]] = []

    def scan(
        self,
        sbom: Sbom,
        output_path: Path,
    ) -> ScanResult:
        self.calls.append((sbom, output_path))
        output_path.write_text("{}", encoding="utf-8")

        return ScanResult(
            sbom=sbom,
            vulnerabilities=self.vulnerabilities,
        )


class FakeUsageAnalyzer:
    """Deterministic package usage analyzer."""

    def __init__(
        self,
        usages: tuple[ApiUsage, ...],
    ) -> None:
        self.usages = usages
        self.calls: list[
            tuple[Path, tuple[str, ...], Path]
        ] = []

    def analyze(
        self,
        source: Path,
        packages: Sequence[str],
        work_dir: Path,
    ) -> tuple[ApiUsage, ...]:
        self.calls.append(
            (
                source,
                tuple(packages),
                work_dir,
            )
        )

        return self.usages


class FakeApiSelector:
    """Deterministic vulnerable API selector."""

    def __init__(
        self,
        mapping: ApiMappingResult,
    ) -> None:
        self.mapping = mapping
        self.calls: list[
            tuple[Vulnerability, tuple[ApiUsage, ...]]
        ] = []

    def select(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
    ) -> ApiMappingResult:
        self.calls.append(
            (
                vulnerability,
                tuple(usages),
            )
        )

        return self.mapping


class FakeTaintAnalyzer:
    """Deterministic taint analyzer."""

    def __init__(
        self,
        results: tuple[TaintResult, ...],
    ) -> None:
        self.results = results
        self.calls: list[
            tuple[
                Path,
                Vulnerability,
                tuple[ApiUsage, ...],
                Path,
            ]
        ] = []

    def analyze(
        self,
        source: Path,
        vulnerability: Vulnerability,
        targets: Sequence[ApiUsage],
        work_dir: Path,
    ) -> tuple[TaintResult, ...]:
        self.calls.append(
            (
                source,
                vulnerability,
                tuple(targets),
                work_dir,
            )
        )

        return self.results


class FakePocGenerator:
    """Deterministic PoC generator."""

    def __init__(
        self,
        candidates: tuple[PocCandidate, ...],
    ) -> None:
        self.candidates = candidates
        self.calls: list[
            tuple[
                Path,
                Vulnerability,
                TaintResult,
                int,
            ]
        ] = []

    def generate(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        self.calls.append(
            (
                source,
                vulnerability,
                taint,
                max_candidates,
            )
        )

        return self.candidates[:max_candidates]


class FakePocRunner:
    """Deterministic PoC runner."""

    def __init__(
        self,
        status: ReproductionStatus,
    ) -> None:
        self.status = status
        self.calls: list[
            tuple[
                Path,
                Vulnerability,
                str,
                tuple[PocCandidate, ...],
                Path,
            ]
        ] = []

    def run(
        self,
        source: Path,
        vulnerability: Vulnerability,
        target_api: str,
        candidates: Sequence[PocCandidate],
        work_dir: Path,
    ) -> PocResult:
        normalized_candidates = tuple(candidates)
        self.calls.append(
            (
                source,
                vulnerability,
                target_api,
                normalized_candidates,
                work_dir,
            )
        )

        return PocResult(
            vulnerability_id=vulnerability.id,
            target_api=target_api,
            status=self.status,
            evidence=(
                "PoC reproduced the vulnerable behavior."
                if self.status is ReproductionStatus.REPRODUCED
                else ""
            ),
            reason="Test PoC result.",
        )


class FakeVexWriter:
    """Deterministic VEX writer."""

    def __init__(self) -> None:
        self.calls: list[
            tuple[
                tuple[VexStatement, ...],
                Path,
                datetime | None,
            ]
        ] = []

    def write(
        self,
        statements: Sequence[VexStatement],
        output_path: Path,
        *,
        timestamp: datetime | None = None,
    ) -> Path:
        normalized_statements = tuple(statements)
        self.calls.append(
            (
                normalized_statements,
                output_path,
                timestamp,
            )
        )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        output_path.write_text(
            "fake vex",
            encoding="utf-8",
        )

        return output_path


def create_component() -> Component:
    return Component(
        name="minimist",
        version="0.0.8",
        ecosystem="npm",
        purl="pkg:npm/minimist@0.0.8",
    )


def create_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=create_component(),
        aliases=("CVE-2021-44906",),
        description="Prototype pollution in minimist.",
        fixed_versions=("1.2.6",),
    )


def create_usage() -> ApiUsage:
    return ApiUsage(
        package="minimist",
        api="<module>",
        file=Path("src/routes.js"),
        line=10,
        column=5,
    )


def create_reachable_taint() -> TaintResult:
    return TaintResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
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
            ),
        ),
    )


def create_candidate() -> PocCandidate:
    return PocCandidate(
        language="javascript",
        code="console.log('REVEAL_REPRODUCED');",
        expected_signal="REVEAL_REPRODUCED",
        description="Test PoC candidate.",
    )


def build_pipeline(
    *,
    vulnerabilities: tuple[Vulnerability, ...],
    usages: tuple[ApiUsage, ...],
    mapping: ApiMappingResult,
    taint_results: tuple[TaintResult, ...],
    poc_status: ReproductionStatus = ReproductionStatus.REPRODUCED,
) -> tuple[
    AnalysisPipeline,
    FakeUsageAnalyzer,
    FakeTaintAnalyzer,
    FakePocGenerator,
    FakePocRunner,
    FakeVexWriter,
]:
    component = create_component()
    usage_analyzer = FakeUsageAnalyzer(usages)
    taint_analyzer = FakeTaintAnalyzer(taint_results)
    poc_generator = FakePocGenerator((create_candidate(),))
    poc_runner = FakePocRunner(poc_status)
    vex_writer = FakeVexWriter()

    pipeline = AnalysisPipeline(
        sbom_generator=FakeSbomGenerator(component),
        vulnerability_scanner=FakeVulnerabilityScanner(
            vulnerabilities,
        ),
        usage_analyzer=usage_analyzer,
        api_selector=FakeApiSelector(mapping),
        taint_analyzer=taint_analyzer,
        poc_generator=poc_generator,
        poc_runner=poc_runner,
        vex_policy=DefaultVexDecisionPolicy(),
        vex_writer=vex_writer,
        max_poc_candidates=2,
    )

    return (
        pipeline,
        usage_analyzer,
        taint_analyzer,
        poc_generator,
        poc_runner,
        vex_writer,
    )


def test_pipeline_runs_all_stages_for_reachable_vulnerability(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    vulnerability = create_vulnerability()
    mapping = ApiMappingResult(
        vulnerability_id=vulnerability.id,
        status=ApiMappingStatus.MAPPED,
        target_apis=("<module>",),
        rationale="The module call exposes the vulnerable parser.",
        confidence=0.9,
    )

    (
        pipeline,
        usage_analyzer,
        taint_analyzer,
        poc_generator,
        poc_runner,
        vex_writer,
    ) = build_pipeline(
        vulnerabilities=(vulnerability,),
        usages=(create_usage(),),
        mapping=mapping,
        taint_results=(create_reachable_taint(),),
    )

    output_path = tmp_path / "results" / "openvex.json"

    result = pipeline.run(
        source=source,
        work_dir=tmp_path / "work",
        vex_output_path=output_path,
    )

    assert result.vulnerability_count == 1
    assert result.vex_path == output_path
    assert result.analyses[0].mapping.status is ApiMappingStatus.MAPPED
    assert result.analyses[0].taint_results[0].status is (
        ReachabilityStatus.REACHABLE
    )
    assert result.analyses[0].poc_results[0].status is (
        ReproductionStatus.REPRODUCED
    )
    assert result.analyses[0].vex_statement.status is VexStatus.AFFECTED

    shared_reachability_dir = tmp_path / "work" / "reachability"

    assert usage_analyzer.calls[0][1] == ("minimist",)
    assert usage_analyzer.calls[0][2] == shared_reachability_dir
    assert taint_analyzer.calls[0][2] == (create_usage(),)
    assert taint_analyzer.calls[0][3] == shared_reachability_dir
    assert poc_generator.calls[0][3] == 2
    assert poc_runner.calls[0][2] == "<module>"
    assert "vulnerabilities" in poc_runner.calls[0][4].parts
    assert "reproduction" in poc_runner.calls[0][4].parts
    assert len(vex_writer.calls) == 1
    assert vex_writer.calls[0][0][0].status is VexStatus.AFFECTED


def test_pipeline_skips_taint_and_poc_for_unused_package(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    vulnerability = create_vulnerability()
    mapping = ApiMappingResult(
        vulnerability_id=vulnerability.id,
        status=ApiMappingStatus.UNUSED,
        rationale="No package usage was observed.",
    )

    (
        pipeline,
        _,
        taint_analyzer,
        poc_generator,
        poc_runner,
        _,
    ) = build_pipeline(
        vulnerabilities=(vulnerability,),
        usages=(),
        mapping=mapping,
        taint_results=(),
    )

    result = pipeline.run(
        source=source,
        work_dir=tmp_path / "work",
        vex_output_path=tmp_path / "openvex.json",
    )

    analysis = result.analyses[0]

    assert analysis.taint_results == ()
    assert analysis.poc_results == ()
    assert analysis.vex_statement.status is VexStatus.NOT_AFFECTED
    assert taint_analyzer.calls == []
    assert poc_generator.calls == []
    assert poc_runner.calls == []


def test_pipeline_skips_poc_for_unreachable_api(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    vulnerability = create_vulnerability()
    mapping = ApiMappingResult(
        vulnerability_id=vulnerability.id,
        status=ApiMappingStatus.MAPPED,
        target_apis=("<module>",),
        confidence=0.9,
    )
    unreachable = TaintResult(
        vulnerability_id=vulnerability.id,
        target_api="<module>",
        status=ReachabilityStatus.UNREACHABLE,
    )

    (
        pipeline,
        _,
        taint_analyzer,
        poc_generator,
        poc_runner,
        _,
    ) = build_pipeline(
        vulnerabilities=(vulnerability,),
        usages=(create_usage(),),
        mapping=mapping,
        taint_results=(unreachable,),
    )

    result = pipeline.run(
        source=source,
        work_dir=tmp_path / "work",
        vex_output_path=tmp_path / "openvex.json",
    )

    assert len(taint_analyzer.calls) == 1
    assert poc_generator.calls == []
    assert poc_runner.calls == []
    assert result.analyses[0].vex_statement.status is (
        VexStatus.NOT_AFFECTED
    )


def test_pipeline_skips_downstream_stages_without_vulnerabilities(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    unresolved_mapping = ApiMappingResult(
        vulnerability_id="unused",
        status=ApiMappingStatus.UNRESOLVED,
    )

    (
        pipeline,
        usage_analyzer,
        taint_analyzer,
        poc_generator,
        poc_runner,
        vex_writer,
    ) = build_pipeline(
        vulnerabilities=(),
        usages=(),
        mapping=unresolved_mapping,
        taint_results=(),
    )

    result = pipeline.run(
        source=source,
        work_dir=tmp_path / "work",
        vex_output_path=tmp_path / "openvex.json",
    )

    assert result.scan.vulnerabilities == ()
    assert result.usages == ()
    assert result.analyses == ()
    assert result.vex_path is None

    assert usage_analyzer.calls == []
    assert taint_analyzer.calls == []
    assert poc_generator.calls == []
    assert poc_runner.calls == []
    assert vex_writer.calls == []


def test_pipeline_rejects_missing_source_directory(
    tmp_path: Path,
) -> None:
    pipeline, *_ = build_pipeline(
        vulnerabilities=(),
        usages=(),
        mapping=ApiMappingResult(
            vulnerability_id="unused",
            status=ApiMappingStatus.UNRESOLVED,
        ),
        taint_results=(),
    )

    with pytest.raises(
        PipelineError,
        match="Source directory does not exist",
    ):
        pipeline.run(
            source=tmp_path / "missing",
            work_dir=tmp_path / "work",
            vex_output_path=tmp_path / "openvex.json",
        )


def test_pipeline_rejects_non_positive_candidate_limit() -> None:
    component = create_component()

    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        AnalysisPipeline(
            sbom_generator=FakeSbomGenerator(component),
            vulnerability_scanner=FakeVulnerabilityScanner(()),
            usage_analyzer=FakeUsageAnalyzer(()),
            api_selector=FakeApiSelector(
                ApiMappingResult(
                    vulnerability_id="unused",
                    status=ApiMappingStatus.UNRESOLVED,
                )
            ),
            taint_analyzer=FakeTaintAnalyzer(()),
            poc_generator=FakePocGenerator(()),
            poc_runner=FakePocRunner(
                ReproductionStatus.NOT_REPRODUCED
            ),
            vex_policy=DefaultVexDecisionPolicy(),
            vex_writer=FakeVexWriter(),
            max_poc_candidates=0,
        )