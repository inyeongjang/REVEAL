"""Tests for REVEAL runtime dependency bootstrap."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

import pytest

from reveal.bootstrap import (
    RuntimeComponents,
    RuntimeContext,
    bootstrap_runtime,
)
from reveal.config import AnalysisConfig, RuntimeConfig
from reveal.exceptions import BootstrapError
from reveal.models import (
    ApiMappingResult,
    ApiUsage,
    PocCandidate,
    PocResult,
    Sbom,
    ScanResult,
    TaintResult,
    VexStatement,
    Vulnerability,
)


class FakeSbomGenerator:
    """Minimal SBOM generator."""

    def generate(
        self,
        source: Path,
        output_path: Path,
    ) -> Sbom:
        del source

        return Sbom(
            format="cyclonedx-json",
            generator="fake",
            document_path=output_path,
            components=(),
        )


class FakeVulnerabilityScanner:
    """Minimal vulnerability scanner."""

    def scan(
        self,
        sbom: Sbom,
        output_path: Path,
    ) -> ScanResult:
        del output_path

        return ScanResult(
            sbom=sbom,
            vulnerabilities=(),
        )


class FakeUsageAnalyzer:
    """Minimal package usage analyzer."""

    def analyze(
        self,
        source: Path,
        packages: Sequence[str],
        work_dir: Path,
    ) -> tuple[ApiUsage, ...]:
        del source, packages, work_dir

        return ()


class FakeApiSelector:
    """Minimal vulnerable API selector."""

    def select(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
    ) -> ApiMappingResult:
        del vulnerability, usages

        raise AssertionError(
            "The selector must not run in this bootstrap test."
        )


class FakeTaintAnalyzer:
    """Minimal taint analyzer."""

    def analyze(
        self,
        source: Path,
        vulnerability: Vulnerability,
        targets: Sequence[ApiUsage],
        work_dir: Path,
    ) -> tuple[TaintResult, ...]:
        del source, vulnerability, targets, work_dir

        return ()


class FakePocGenerator:
    """Minimal PoC generator."""

    def generate(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        del source, vulnerability, taint, max_candidates

        return ()


class FakePocRefiner:
    """Minimal PoC refiner."""

    def refine(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        previous_result: PocResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        del (
            source,
            vulnerability,
            taint,
            previous_result,
            max_candidates,
        )

        return ()


class FakePocRunner:
    """Minimal PoC runner."""

    def run(
        self,
        source: Path,
        vulnerability: Vulnerability,
        target_api: str,
        candidates: Sequence[PocCandidate],
        work_dir: Path,
    ) -> PocResult:
        del (
            source,
            vulnerability,
            target_api,
            candidates,
            work_dir,
        )

        raise AssertionError(
            "The runner must not run in this bootstrap test."
        )


class FakeVexPolicy:
    """Minimal VEX decision policy."""

    def decide(
        self,
        vulnerability: Vulnerability,
        mapping: ApiMappingResult,
        taint_results: Sequence[TaintResult],
        poc_results: Sequence[PocResult],
    ) -> VexStatement:
        del (
            vulnerability,
            mapping,
            taint_results,
            poc_results,
        )

        raise AssertionError(
            "The policy must not run in this bootstrap test."
        )


class FakeVexWriter:
    """Minimal VEX writer."""

    def write(
        self,
        statements: Sequence[VexStatement],
        output_path: Path,
        *,
        timestamp: datetime | None = None,
    ) -> Path:
        del statements, timestamp

        return output_path


class RecordingComponentFactory:
    """Record bootstrap inputs and return configured components."""

    def __init__(
        self,
        components: RuntimeComponents,
    ) -> None:
        self.components = components
        self.calls: list[
            tuple[RuntimeConfig, str]
        ] = []

    def create(
        self,
        *,
        config: RuntimeConfig,
        document_id: str,
    ) -> RuntimeComponents:
        self.calls.append(
            (
                config,
                document_id,
            )
        )

        return self.components


def create_components(
    *,
    poc_refiner: FakePocRefiner | None = None,
) -> RuntimeComponents:
    return RuntimeComponents(
        sbom_generator=FakeSbomGenerator(),
        vulnerability_scanner=FakeVulnerabilityScanner(),
        usage_analyzer=FakeUsageAnalyzer(),
        api_selector=FakeApiSelector(),
        taint_analyzer=FakeTaintAnalyzer(),
        poc_generator=FakePocGenerator(),
        poc_runner=FakePocRunner(),
        poc_refiner=poc_refiner,
        vex_policy=FakeVexPolicy(),
        vex_writer=FakeVexWriter(),
        artifact_writer=None,
    )


def test_bootstrap_creates_configured_pipeline() -> None:
    config = RuntimeConfig(
        analysis=AnalysisConfig(
            max_poc_candidates=4,
            max_poc_refinement_rounds=3,
            enable_poc_refinement=True,
        )
    )
    components = create_components(
        poc_refiner=FakePocRefiner()
    )
    factory = RecordingComponentFactory(components)

    context = bootstrap_runtime(
        config=config,
        component_factory=factory,
        document_id="urn:uuid:test-document",
    )

    assert isinstance(context, RuntimeContext)
    assert context.config is config
    assert context.components is components

    assert factory.calls == [
        (
            config,
            "urn:uuid:test-document",
        )
    ]

    pipeline = context.pipeline

    assert pipeline.sbom_generator is components.sbom_generator
    assert (
        pipeline.vulnerability_scanner
        is components.vulnerability_scanner
    )
    assert pipeline.usage_analyzer is components.usage_analyzer
    assert pipeline.api_selector is components.api_selector
    assert pipeline.taint_analyzer is components.taint_analyzer
    assert pipeline.poc_generator is components.poc_generator
    assert pipeline.poc_runner is components.poc_runner
    assert pipeline.poc_refiner is components.poc_refiner
    assert pipeline.vex_policy is components.vex_policy
    assert pipeline.vex_writer is components.vex_writer
    assert pipeline.artifact_writer is components.artifact_writer

    assert pipeline.max_poc_candidates == 4
    assert pipeline.max_poc_refinement_rounds == 3


def test_bootstrap_disables_refinement_from_config() -> None:
    config = RuntimeConfig(
        analysis=AnalysisConfig(
            enable_poc_refinement=False,
            max_poc_refinement_rounds=5,
        )
    )
    components = create_components(
        poc_refiner=FakePocRefiner()
    )

    context = bootstrap_runtime(
        config=config,
        component_factory=RecordingComponentFactory(
            components
        ),
        document_id="urn:uuid:test-document",
    )

    assert context.pipeline.poc_refiner is None
    assert context.pipeline.max_poc_refinement_rounds == 0


def test_bootstrap_requires_refiner_when_enabled() -> None:
    config = RuntimeConfig(
        analysis=AnalysisConfig(
            enable_poc_refinement=True,
        )
    )

    with pytest.raises(
        BootstrapError,
        match="no PoC refiner",
    ):
        bootstrap_runtime(
            config=config,
            component_factory=RecordingComponentFactory(
                create_components(
                    poc_refiner=None,
                )
            ),
            document_id="urn:uuid:test-document",
        )


def test_bootstrap_trims_document_id() -> None:
    config = RuntimeConfig(
        analysis=AnalysisConfig(
            enable_poc_refinement=False,
        )
    )
    factory = RecordingComponentFactory(
        create_components()
    )

    bootstrap_runtime(
        config=config,
        component_factory=factory,
        document_id="  urn:uuid:test-document  ",
    )

    assert factory.calls[0][1] == "urn:uuid:test-document"


def test_bootstrap_rejects_empty_document_id() -> None:
    config = RuntimeConfig(
        analysis=AnalysisConfig(
            enable_poc_refinement=False,
        )
    )

    with pytest.raises(
        BootstrapError,
        match="document ID must not be empty",
    ):
        bootstrap_runtime(
            config=config,
            component_factory=RecordingComponentFactory(
                create_components()
            ),
            document_id=" ",
        )