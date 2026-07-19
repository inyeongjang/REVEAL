"""Tests for conservative pipeline error handling."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from reveal.exceptions import (
    CodeQLAnalysisError,
    LlmError,
    PocExecutionError,
    PocGenerationError,
    VexDecisionError,
)
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
from reveal.pipeline import AnalysisPipeline, PipelineResult
from reveal.reachability import VulnerableApiSelector
from reveal.vex import DefaultVexDecisionPolicy, VexDecisionPolicy


class FakeSbomGenerator:
    """Generate a deterministic SBOM."""

    def __init__(
        self,
        components: tuple[Component, ...],
    ) -> None:
        self.components = components

    def generate(
        self,
        source: Path,
        output_path: Path,
    ) -> Sbom:
        output_path.write_text("{}", encoding="utf-8")

        return Sbom(
            format="cyclonedx-json",
            generator="fake",
            document_path=output_path,
            components=self.components,
        )


class FakeVulnerabilityScanner:
    """Return deterministic vulnerabilities."""

    def __init__(
        self,
        vulnerabilities: tuple[Vulnerability, ...],
    ) -> None:
        self.vulnerabilities = vulnerabilities

    def scan(
        self,
        sbom: Sbom,
        output_path: Path,
    ) -> ScanResult:
        output_path.write_text("{}", encoding="utf-8")

        return ScanResult(
            sbom=sbom,
            vulnerabilities=self.vulnerabilities,
        )


class RecordingUsageAnalyzer:
    """Return usages or raise a configured error."""

    def __init__(
        self,
        usages: tuple[ApiUsage, ...],
        error: CodeQLAnalysisError | None = None,
    ) -> None:
        self.usages = usages
        self.error = error
        self.call_count = 0

    def analyze(
        self,
        source: Path,
        packages: Sequence[str],
        work_dir: Path,
    ) -> tuple[ApiUsage, ...]:
        del source, packages, work_dir
        self.call_count += 1

        if self.error is not None:
            raise self.error

        return self.usages


class RecordingApiSelector:
    """Return a mapping or raise a configured error."""

    def __init__(
        self,
        mapping: ApiMappingResult,
        error: LlmError | None = None,
    ) -> None:
        self.mapping = mapping
        self.error = error
        self.call_count = 0

    def select(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
    ) -> ApiMappingResult:
        del vulnerability, usages
        self.call_count += 1

        if self.error is not None:
            raise self.error

        return self.mapping


class RecordingTaintAnalyzer:
    """Return taint results or raise a configured error."""

    def __init__(
        self,
        results: tuple[TaintResult, ...],
        error: CodeQLAnalysisError | None = None,
    ) -> None:
        self.results = results
        self.error = error
        self.call_count = 0

    def analyze(
        self,
        source: Path,
        vulnerability: Vulnerability,
        targets: Sequence[ApiUsage],
        work_dir: Path,
    ) -> tuple[TaintResult, ...]:
        del source, vulnerability, targets, work_dir
        self.call_count += 1

        if self.error is not None:
            raise self.error

        return self.results


class RecordingPocGenerator:
    """Return candidates or raise a configured error."""

    def __init__(
        self,
        candidates: tuple[PocCandidate, ...],
        error: PocGenerationError | None = None,
    ) -> None:
        self.candidates = candidates
        self.error = error
        self.call_count = 0

    def generate(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        del source, vulnerability, taint
        self.call_count += 1

        if self.error is not None:
            raise self.error

        return self.candidates[:max_candidates]


class RecordingPocRunner:
    """Return a PoC result or raise a configured error."""

    def __init__(
        self,
        error: PocExecutionError | None = None,
    ) -> None:
        self.error = error
        self.call_count = 0

    def run(
        self,
        source: Path,
        vulnerability: Vulnerability,
        target_api: str,
        candidates: Sequence[PocCandidate],
        work_dir: Path,
    ) -> PocResult:
        del source, candidates, work_dir
        self.call_count += 1

        if self.error is not None:
            raise self.error

        return PocResult(
            vulnerability_id=vulnerability.id,
            target_api=target_api,
            status=ReproductionStatus.NOT_REPRODUCED,
            reason="Test reproduction did not succeed.",
        )


class FakeVexWriter:
    """Write deterministic VEX output."""

    def write(
        self,
        statements: Sequence[VexStatement],
        output_path: Path,
        *,
        timestamp: datetime | None = None,
    ) -> Path:
        del statements, timestamp

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        output_path.write_text(
            "{}",
            encoding="utf-8",
        )

        return output_path


class RaisingVexPolicy:
    """Raise a deterministic VEX decision error."""

    def decide(
        self,
        vulnerability: Vulnerability,
        mapping: ApiMappingResult,
        taint_results: Sequence[TaintResult],
        poc_results: Sequence[PocResult],
    ) -> VexStatement:
        del vulnerability, mapping, taint_results, poc_results

        raise VexDecisionError("inconsistent test evidence")


def create_component(
    *,
    name: str = "minimist",
) -> Component:
    return Component(
        name=name,
        version="0.0.8",
        ecosystem="npm",
        purl=f"pkg:npm/{name}@0.0.8",
    )


def create_vulnerability(
    *,
    vulnerability_id: str = "GHSA-xvch-5gv4-984h",
    component: Component | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=vulnerability_id,
        component=component or create_component(),
        description="Prototype pollution in a dependency.",
    )


def create_usage() -> ApiUsage:
    return ApiUsage(
        package="minimist",
        api="<module>",
        file=Path("src/app.js"),
        line=10,
        column=5,
    )


def create_mapping(
    vulnerability: Vulnerability,
) -> ApiMappingResult:
    return ApiMappingResult(
        vulnerability_id=vulnerability.id,
        status=ApiMappingStatus.MAPPED,
        target_apis=("<module>",),
        rationale="The exported function is affected.",
        confidence=0.9,
    )


def create_reachable_taint(
    vulnerability: Vulnerability,
) -> TaintResult:
    return TaintResult(
        vulnerability_id=vulnerability.id,
        target_api="<module>",
        status=ReachabilityStatus.REACHABLE,
        paths=(
            TaintPath(
                source_file=Path("src/app.js"),
                source_line=5,
                source="request.query",
                sink_file=Path("src/app.js"),
                sink_line=10,
                sink="minimist(request.query)",
                sink_argument=0,
            ),
        ),
    )


def create_candidate() -> PocCandidate:
    return PocCandidate(
        language="javascript",
        code="console.error('not reproduced');",
        expected_signal="REVEAL_REPRODUCED",
        description="Test PoC.",
    )


def build_pipeline(
    *,
    vulnerabilities: tuple[Vulnerability, ...],
    usage_analyzer: RecordingUsageAnalyzer,
    api_selector: VulnerableApiSelector,
    taint_analyzer: RecordingTaintAnalyzer,
    poc_generator: RecordingPocGenerator,
    poc_runner: RecordingPocRunner,
    vex_policy: VexDecisionPolicy | None = None,
) -> AnalysisPipeline:
    return AnalysisPipeline(
        sbom_generator=FakeSbomGenerator(
            tuple(
                vulnerability.component
                for vulnerability in vulnerabilities
            )
        ),
        vulnerability_scanner=FakeVulnerabilityScanner(
            vulnerabilities
        ),
        usage_analyzer=usage_analyzer,
        api_selector=api_selector,
        taint_analyzer=taint_analyzer,
        poc_generator=poc_generator,
        poc_runner=poc_runner,
        vex_policy=(
            vex_policy
            if vex_policy is not None
            else DefaultVexDecisionPolicy()
        ),
        vex_writer=FakeVexWriter(),
    )


def run_pipeline(
    pipeline: AnalysisPipeline,
    tmp_path: Path,
) -> PipelineResult:
    source = tmp_path / "project"
    source.mkdir()

    return pipeline.run(
        source=source,
        work_dir=tmp_path / "work",
        vex_output_path=tmp_path / "openvex.json",
    )


def test_usage_error_marks_mapping_as_error(
    tmp_path: Path,
) -> None:
    vulnerability = create_vulnerability()
    usage_analyzer = RecordingUsageAnalyzer(
        (),
        error=CodeQLAnalysisError("database creation failed"),
    )
    selector = RecordingApiSelector(
        create_mapping(vulnerability)
    )
    taint_analyzer = RecordingTaintAnalyzer(())
    poc_generator = RecordingPocGenerator(())
    poc_runner = RecordingPocRunner()

    pipeline = build_pipeline(
        vulnerabilities=(vulnerability,),
        usage_analyzer=usage_analyzer,
        api_selector=selector,
        taint_analyzer=taint_analyzer,
        poc_generator=poc_generator,
        poc_runner=poc_runner,
    )

    result = run_pipeline(pipeline, tmp_path)
    analysis = result.analyses[0]

    assert analysis.mapping.status is ApiMappingStatus.ERROR
    assert "Package usage analysis failed" in analysis.mapping.rationale
    assert analysis.vex_statement.status is (
        VexStatus.UNDER_INVESTIGATION
    )
    assert selector.call_count == 0
    assert taint_analyzer.call_count == 0
    assert poc_generator.call_count == 0
    assert poc_runner.call_count == 0


def test_selector_error_skips_downstream_analysis(
    tmp_path: Path,
) -> None:
    vulnerability = create_vulnerability()
    selector = RecordingApiSelector(
        create_mapping(vulnerability),
        error=LlmError("invalid model response"),
    )
    taint_analyzer = RecordingTaintAnalyzer(())
    poc_generator = RecordingPocGenerator(())
    poc_runner = RecordingPocRunner()

    pipeline = build_pipeline(
        vulnerabilities=(vulnerability,),
        usage_analyzer=RecordingUsageAnalyzer(
            (create_usage(),)
        ),
        api_selector=selector,
        taint_analyzer=taint_analyzer,
        poc_generator=poc_generator,
        poc_runner=poc_runner,
    )

    result = run_pipeline(pipeline, tmp_path)
    analysis = result.analyses[0]

    assert analysis.mapping.status is ApiMappingStatus.ERROR
    assert "Vulnerable API selection failed" in (
        analysis.mapping.rationale
    )
    assert analysis.taint_results == ()
    assert analysis.poc_results == ()
    assert analysis.vex_statement.status is (
        VexStatus.UNDER_INVESTIGATION
    )
    assert taint_analyzer.call_count == 0


def test_taint_error_becomes_error_result(
    tmp_path: Path,
) -> None:
    vulnerability = create_vulnerability()
    taint_analyzer = RecordingTaintAnalyzer(
        (),
        error=CodeQLAnalysisError("query compilation failed"),
    )
    poc_generator = RecordingPocGenerator(())
    poc_runner = RecordingPocRunner()

    pipeline = build_pipeline(
        vulnerabilities=(vulnerability,),
        usage_analyzer=RecordingUsageAnalyzer(
            (create_usage(),)
        ),
        api_selector=RecordingApiSelector(
            create_mapping(vulnerability)
        ),
        taint_analyzer=taint_analyzer,
        poc_generator=poc_generator,
        poc_runner=poc_runner,
    )

    result = run_pipeline(pipeline, tmp_path)
    analysis = result.analyses[0]

    assert len(analysis.taint_results) == 1
    assert analysis.taint_results[0].status is (
        ReachabilityStatus.ERROR
    )
    assert "Taint reachability analysis failed" in (
        analysis.taint_results[0].reason
    )
    assert analysis.poc_results == ()
    assert analysis.vex_statement.status is (
        VexStatus.UNDER_INVESTIGATION
    )
    assert poc_generator.call_count == 0
    assert poc_runner.call_count == 0


def test_poc_generation_error_becomes_error_result(
    tmp_path: Path,
) -> None:
    vulnerability = create_vulnerability()
    generator = RecordingPocGenerator(
        (),
        error=PocGenerationError("invalid generated JSON"),
    )
    runner = RecordingPocRunner()

    pipeline = build_pipeline(
        vulnerabilities=(vulnerability,),
        usage_analyzer=RecordingUsageAnalyzer(
            (create_usage(),)
        ),
        api_selector=RecordingApiSelector(
            create_mapping(vulnerability)
        ),
        taint_analyzer=RecordingTaintAnalyzer(
            (create_reachable_taint(vulnerability),)
        ),
        poc_generator=generator,
        poc_runner=runner,
    )

    result = run_pipeline(pipeline, tmp_path)
    analysis = result.analyses[0]

    assert len(analysis.poc_results) == 1
    assert analysis.poc_results[0].status is (
        ReproductionStatus.ERROR
    )
    assert "PoC generation failed" in (
        analysis.poc_results[0].reason
    )
    assert analysis.vex_statement.status is (
        VexStatus.UNDER_INVESTIGATION
    )
    assert runner.call_count == 0


def test_poc_execution_error_becomes_error_result(
    tmp_path: Path,
) -> None:
    vulnerability = create_vulnerability()
    runner = RecordingPocRunner(
        error=PocExecutionError("Docker is unavailable")
    )

    pipeline = build_pipeline(
        vulnerabilities=(vulnerability,),
        usage_analyzer=RecordingUsageAnalyzer(
            (create_usage(),)
        ),
        api_selector=RecordingApiSelector(
            create_mapping(vulnerability)
        ),
        taint_analyzer=RecordingTaintAnalyzer(
            (create_reachable_taint(vulnerability),)
        ),
        poc_generator=RecordingPocGenerator(
            (create_candidate(),)
        ),
        poc_runner=runner,
    )

    result = run_pipeline(pipeline, tmp_path)
    analysis = result.analyses[0]

    assert len(analysis.poc_results) == 1
    assert analysis.poc_results[0].status is (
        ReproductionStatus.ERROR
    )
    assert "PoC execution failed" in analysis.poc_results[0].reason
    assert analysis.vex_statement.status is (
        VexStatus.UNDER_INVESTIGATION
    )


def test_vex_policy_error_uses_fallback_statement(
    tmp_path: Path,
) -> None:
    vulnerability = create_vulnerability()

    pipeline = build_pipeline(
        vulnerabilities=(vulnerability,),
        usage_analyzer=RecordingUsageAnalyzer(
            (create_usage(),)
        ),
        api_selector=RecordingApiSelector(
            create_mapping(vulnerability)
        ),
        taint_analyzer=RecordingTaintAnalyzer(
            (create_reachable_taint(vulnerability),)
        ),
        poc_generator=RecordingPocGenerator(
            (create_candidate(),)
        ),
        poc_runner=RecordingPocRunner(),
        vex_policy=RaisingVexPolicy(),
    )

    result = run_pipeline(pipeline, tmp_path)
    statement = result.analyses[0].vex_statement

    assert statement.status is VexStatus.UNDER_INVESTIGATION
    assert statement.products == (
        "pkg:npm/minimist@0.0.8",
    )
    assert "VEX decision failed" in (
        statement.impact_statement or ""
    )
