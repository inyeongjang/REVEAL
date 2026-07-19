"""Tests for bounded PoC refinement in the analysis pipeline."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

import pytest

from reveal.exceptions import PocRefinementError
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
from reveal.pipeline import AnalysisPipeline, PipelineResult
from reveal.vex import DefaultVexDecisionPolicy


class FakeSbomGenerator:
    """Generate a deterministic test SBOM."""

    def __init__(self, component: Component) -> None:
        self.component = component

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
            components=(self.component,),
        )


class FakeVulnerabilityScanner:
    """Return one deterministic vulnerability."""

    def __init__(self, vulnerability: Vulnerability) -> None:
        self.vulnerability = vulnerability

    def scan(
        self,
        sbom: Sbom,
        output_path: Path,
    ) -> ScanResult:
        output_path.write_text("{}", encoding="utf-8")

        return ScanResult(
            sbom=sbom,
            vulnerabilities=(self.vulnerability,),
        )


class FakeUsageAnalyzer:
    """Return one deterministic API usage."""

    def analyze(
        self,
        source: Path,
        packages: Sequence[str],
        work_dir: Path,
    ) -> tuple[ApiUsage, ...]:
        del source, packages, work_dir

        return (
            ApiUsage(
                package="minimist",
                api="<module>",
                file=Path("src/app.js"),
                line=10,
                column=5,
            ),
        )


class FakeApiSelector:
    """Map the vulnerability to the module call."""

    def select(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
    ) -> ApiMappingResult:
        del usages

        return ApiMappingResult(
            vulnerability_id=vulnerability.id,
            status=ApiMappingStatus.MAPPED,
            target_apis=("<module>",),
            rationale="The module export is affected.",
            confidence=0.9,
        )


class FakeTaintAnalyzer:
    """Return one reachable taint result."""

    def analyze(
        self,
        source: Path,
        vulnerability: Vulnerability,
        targets: Sequence[ApiUsage],
        work_dir: Path,
    ) -> tuple[TaintResult, ...]:
        del source, targets, work_dir

        return (
            TaintResult(
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
            ),
        )


class FakePocGenerator:
    """Return one initial PoC candidate."""

    def __init__(self, candidate: PocCandidate) -> None:
        self.candidate = candidate

    def generate(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        del source, vulnerability, taint, max_candidates

        return (self.candidate,)


class FakePocRefiner:
    """Return configured candidate batches."""

    def __init__(
        self,
        batches: tuple[tuple[PocCandidate, ...], ...],
        *,
        error: PocRefinementError | None = None,
    ) -> None:
        self.batches = batches
        self.error = error
        self.calls: list[PocResult] = []

    def refine(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        previous_result: PocResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        del source, vulnerability, taint

        self.calls.append(previous_result)

        if self.error is not None:
            raise self.error

        index = len(self.calls) - 1

        if index >= len(self.batches):
            return ()

        return self.batches[index][:max_candidates]


class FakePocRunner:
    """Return configured execution statuses."""

    def __init__(
        self,
        statuses: tuple[ReproductionStatus, ...],
    ) -> None:
        self.statuses = statuses
        self.calls: list[
            tuple[tuple[PocCandidate, ...], Path]
        ] = []

    def run(
        self,
        source: Path,
        vulnerability: Vulnerability,
        target_api: str,
        candidates: Sequence[PocCandidate],
        work_dir: Path,
    ) -> PocResult:
        del source

        normalized_candidates = tuple(candidates)
        self.calls.append(
            (
                normalized_candidates,
                work_dir,
            )
        )

        status = self.statuses[len(self.calls) - 1]
        candidate = normalized_candidates[0]
        reproduced = status is ReproductionStatus.REPRODUCED

        attempt = PocAttempt(
            number=1,
            candidate=candidate,
            exit_code=0 if reproduced else 1,
            stdout=(
                f"{candidate.expected_signal}\n"
                if reproduced
                else ""
            ),
            stderr=(
                ""
                if reproduced
                else "Expected signal was not emitted."
            ),
            reproduced=reproduced,
        )

        return PocResult(
            vulnerability_id=vulnerability.id,
            target_api=target_api,
            status=status,
            attempts=(attempt,),
            evidence=(
                "The refined candidate reproduced the vulnerability."
                if reproduced
                else ""
            ),
            reason=(
                ""
                if reproduced
                else "The candidate did not reproduce the vulnerability."
            ),
        )


class FakeVexWriter:
    """Write a deterministic VEX output file."""

    def write(
        self,
        statements: Sequence[VexStatement],
        output_path: Path,
        *,
        timestamp: datetime | None = None,
    ) -> Path:
        del statements, timestamp

        output_path.write_text("{}", encoding="utf-8")

        return output_path


def create_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=Component(
            name="minimist",
            version="0.0.8",
            ecosystem="npm",
            purl="pkg:npm/minimist@0.0.8",
        ),
        description="Prototype pollution in minimist.",
    )


def create_candidate(code: str) -> PocCandidate:
    return PocCandidate(
        language="javascript",
        code=code,
        expected_signal="REVEAL_REPRODUCED",
        description="Test PoC candidate.",
    )


def build_pipeline(
    *,
    initial_candidate: PocCandidate,
    runner: FakePocRunner,
    refiner: FakePocRefiner | None,
    max_rounds: int = 2,
) -> AnalysisPipeline:
    vulnerability = create_vulnerability()

    return AnalysisPipeline(
        sbom_generator=FakeSbomGenerator(
            vulnerability.component
        ),
        vulnerability_scanner=FakeVulnerabilityScanner(
            vulnerability
        ),
        usage_analyzer=FakeUsageAnalyzer(),
        api_selector=FakeApiSelector(),
        taint_analyzer=FakeTaintAnalyzer(),
        poc_generator=FakePocGenerator(initial_candidate),
        poc_runner=runner,
        poc_refiner=refiner,
        vex_policy=DefaultVexDecisionPolicy(),
        vex_writer=FakeVexWriter(),
        max_poc_refinement_rounds=max_rounds,
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


def test_pipeline_reproduces_after_refinement(
    tmp_path: Path,
) -> None:
    initial = create_candidate("console.error('initial');")
    refined = create_candidate(
        "console.log('REVEAL_REPRODUCED');"
    )
    runner = FakePocRunner(
        (
            ReproductionStatus.NOT_REPRODUCED,
            ReproductionStatus.REPRODUCED,
        )
    )
    refiner = FakePocRefiner(((refined,),))

    result = run_pipeline(
        build_pipeline(
            initial_candidate=initial,
            runner=runner,
            refiner=refiner,
        ),
        tmp_path,
    )

    poc_result = result.analyses[0].poc_results[0]

    assert poc_result.status is ReproductionStatus.REPRODUCED
    assert poc_result.attempt_count == 2
    assert tuple(
        attempt.number
        for attempt in poc_result.attempts
    ) == (1, 2)
    assert tuple(
        attempt.candidate.code
        for attempt in poc_result.attempts
    ) == (
        initial.code,
        refined.code,
    )
    assert result.analyses[0].vex_statement.status is (
        VexStatus.AFFECTED
    )

    assert len(refiner.calls) == 1
    assert refiner.calls[0].attempt_count == 1
    assert runner.calls[0][1].name == "round-000"
    assert runner.calls[1][1].name == "round-001"


def test_pipeline_stops_at_refinement_limit(
    tmp_path: Path,
) -> None:
    initial = create_candidate("console.error('round zero');")
    first = create_candidate("console.error('round one');")
    second = create_candidate("console.error('round two');")

    runner = FakePocRunner(
        (
            ReproductionStatus.NOT_REPRODUCED,
            ReproductionStatus.NOT_REPRODUCED,
            ReproductionStatus.NOT_REPRODUCED,
        )
    )
    refiner = FakePocRefiner(
        (
            (first,),
            (second,),
        )
    )

    result = run_pipeline(
        build_pipeline(
            initial_candidate=initial,
            runner=runner,
            refiner=refiner,
            max_rounds=2,
        ),
        tmp_path,
    )

    poc_result = result.analyses[0].poc_results[0]

    assert poc_result.status is (
        ReproductionStatus.NOT_REPRODUCED
    )
    assert poc_result.attempt_count == 3
    assert len(runner.calls) == 3
    assert len(refiner.calls) == 2
    assert result.analyses[0].vex_statement.status is (
        VexStatus.UNDER_INVESTIGATION
    )


def test_pipeline_does_not_repeat_identical_candidate(
    tmp_path: Path,
) -> None:
    initial = create_candidate("console.error('same');")
    runner = FakePocRunner(
        (ReproductionStatus.NOT_REPRODUCED,)
    )
    refiner = FakePocRefiner(((initial,),))

    result = run_pipeline(
        build_pipeline(
            initial_candidate=initial,
            runner=runner,
            refiner=refiner,
        ),
        tmp_path,
    )

    poc_result = result.analyses[0].poc_results[0]

    assert poc_result.status is (
        ReproductionStatus.NOT_REPRODUCED
    )
    assert poc_result.attempt_count == 1
    assert len(runner.calls) == 1
    assert len(refiner.calls) == 1


def test_refinement_error_becomes_inconclusive(
    tmp_path: Path,
) -> None:
    initial = create_candidate("console.error('initial');")
    runner = FakePocRunner(
        (ReproductionStatus.NOT_REPRODUCED,)
    )
    refiner = FakePocRefiner(
        (),
        error=PocRefinementError(
            "The LLM returned invalid JSON."
        ),
    )

    result = run_pipeline(
        build_pipeline(
            initial_candidate=initial,
            runner=runner,
            refiner=refiner,
        ),
        tmp_path,
    )

    poc_result = result.analyses[0].poc_results[0]

    assert poc_result.status is ReproductionStatus.INCONCLUSIVE
    assert poc_result.attempt_count == 1
    assert "at least one" in poc_result.reason
    assert result.analyses[0].vex_statement.status is (
        VexStatus.UNDER_INVESTIGATION
    )


def test_pipeline_without_refiner_runs_only_once(
    tmp_path: Path,
) -> None:
    initial = create_candidate("console.error('initial');")
    runner = FakePocRunner(
        (ReproductionStatus.NOT_REPRODUCED,)
    )

    result = run_pipeline(
        build_pipeline(
            initial_candidate=initial,
            runner=runner,
            refiner=None,
        ),
        tmp_path,
    )

    assert len(runner.calls) == 1
    assert result.analyses[0].poc_results[0].status is (
        ReproductionStatus.NOT_REPRODUCED
    )


def test_pipeline_rejects_negative_refinement_limit() -> None:
    initial = create_candidate("console.error('initial');")

    with pytest.raises(
        ValueError,
        match="must not be negative",
    ):
        build_pipeline(
            initial_candidate=initial,
            runner=FakePocRunner(
                (ReproductionStatus.NOT_REPRODUCED,)
            ),
            refiner=None,
            max_rounds=-1,
        )