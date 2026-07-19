"""Runtime dependency bootstrap for REVEAL."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from reveal.artifacts import AnalysisArtifactWriter
from reveal.config import RuntimeConfig
from reveal.exceptions import BootstrapError
from reveal.pipeline import AnalysisPipeline
from reveal.reachability import (
    TaintAnalyzer,
    UsageAnalyzer,
    VulnerableApiSelector,
)
from reveal.reproduction import (
    PocGenerator,
    PocRefiner,
    PocRunner,
)
from reveal.sbom import SbomGenerator
from reveal.vex import VexDecisionPolicy, VexWriter
from reveal.vulnerabilities import VulnerabilityScanner


@dataclass(frozen=True, slots=True)
class RuntimeComponents:
    """Concrete components required by the analysis pipeline."""

    sbom_generator: SbomGenerator
    vulnerability_scanner: VulnerabilityScanner
    usage_analyzer: UsageAnalyzer
    api_selector: VulnerableApiSelector
    taint_analyzer: TaintAnalyzer
    poc_generator: PocGenerator
    poc_runner: PocRunner
    vex_policy: VexDecisionPolicy
    vex_writer: VexWriter
    poc_refiner: PocRefiner | None = None
    artifact_writer: AnalysisArtifactWriter | None = None


class RuntimeComponentFactory(Protocol):
    """Factory responsible for constructing runtime components."""

    def create(
        self,
        *,
        config: RuntimeConfig,
        document_id: str,
    ) -> RuntimeComponents:
        """Create concrete components from runtime configuration."""
        ...


@dataclass(frozen=True, slots=True)
class RuntimeContext:
    """Fully bootstrapped REVEAL runtime."""

    config: RuntimeConfig
    components: RuntimeComponents
    pipeline: AnalysisPipeline


def bootstrap_runtime(
    *,
    config: RuntimeConfig,
    component_factory: RuntimeComponentFactory,
    document_id: str,
) -> RuntimeContext:
    """Create a configured analysis pipeline and its dependencies."""

    normalized_document_id = document_id.strip()

    if not normalized_document_id:
        raise BootstrapError(
            "OpenVEX document ID must not be empty."
        )

    components = component_factory.create(
        config=config,
        document_id=normalized_document_id,
    )

    poc_refiner = _resolve_poc_refiner(
        config=config,
        components=components,
    )
    max_refinement_rounds = (
        config.analysis.max_poc_refinement_rounds
        if poc_refiner is not None
        else 0
    )

    pipeline = AnalysisPipeline(
        sbom_generator=components.sbom_generator,
        vulnerability_scanner=components.vulnerability_scanner,
        usage_analyzer=components.usage_analyzer,
        api_selector=components.api_selector,
        taint_analyzer=components.taint_analyzer,
        poc_generator=components.poc_generator,
        poc_runner=components.poc_runner,
        poc_refiner=poc_refiner,
        vex_policy=components.vex_policy,
        vex_writer=components.vex_writer,
        artifact_writer=components.artifact_writer,
        max_poc_candidates=(
            config.analysis.max_poc_candidates
        ),
        max_poc_refinement_rounds=max_refinement_rounds,
    )

    return RuntimeContext(
        config=config,
        components=components,
        pipeline=pipeline,
    )


def _resolve_poc_refiner(
    *,
    config: RuntimeConfig,
    components: RuntimeComponents,
) -> PocRefiner | None:
    if not config.analysis.enable_poc_refinement:
        return None

    if components.poc_refiner is None:
        raise BootstrapError(
            "PoC refinement is enabled, but no PoC refiner "
            "was provided by the runtime component factory."
        )

    return components.poc_refiner