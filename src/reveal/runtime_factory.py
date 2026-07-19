"""Configured runtime component construction for REVEAL."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from reveal.artifacts import AnalysisArtifactWriter
from reveal.bootstrap import RuntimeComponents
from reveal.config import RuntimeConfig
from reveal.llm import LlmClient
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


class CodeQLClientPort(Protocol):
    """Operations required by the CodeQL reachability adapters."""

    def create_database(
        self,
        source: Path,
        database_path: Path,
    ) -> None:
        """Create a CodeQL database for the source project."""
        ...

    def run_query(
        self,
        database_path: Path,
        query_path: Path,
        output_path: Path,
    ) -> None:
        """Run one CodeQL query and write its BQRS output."""
        ...

    def decode_bqrs(
        self,
        bqrs_path: Path,
        output_path: Path,
    ) -> None:
        """Decode BQRS query output into a normalized file."""
        ...


@dataclass(frozen=True, slots=True)
class RuntimeAdapterBuilders:
    """Builders for concrete runtime adapters."""

    build_llm_client: Callable[
        [RuntimeConfig],
        LlmClient,
    ]
    build_codeql_client: Callable[
        [RuntimeConfig],
        CodeQLClientPort,
    ]
    build_sbom_generator: Callable[
        [RuntimeConfig],
        SbomGenerator,
    ]
    build_vulnerability_scanner: Callable[
        [RuntimeConfig],
        VulnerabilityScanner,
    ]
    build_usage_analyzer: Callable[
        [RuntimeConfig, CodeQLClientPort],
        UsageAnalyzer,
    ]
    build_api_selector: Callable[
        [RuntimeConfig, LlmClient],
        VulnerableApiSelector,
    ]
    build_taint_analyzer: Callable[
        [RuntimeConfig, CodeQLClientPort],
        TaintAnalyzer,
    ]
    build_poc_generator: Callable[
        [RuntimeConfig, LlmClient],
        PocGenerator,
    ]
    build_poc_refiner: Callable[
        [RuntimeConfig, LlmClient],
        PocRefiner,
    ]
    build_poc_runner: Callable[
        [RuntimeConfig],
        PocRunner,
    ]
    build_vex_policy: Callable[
        [RuntimeConfig],
        VexDecisionPolicy,
    ]
    build_vex_writer: Callable[
        [RuntimeConfig, str],
        VexWriter,
    ]
    build_artifact_writer: Callable[
        [RuntimeConfig],
        AnalysisArtifactWriter,
    ]


class ConfiguredRuntimeComponentFactory:
    """Create runtime components using configured adapter builders."""

    def __init__(
        self,
        builders: RuntimeAdapterBuilders,
    ) -> None:
        self.builders = builders

    def create(
        self,
        *,
        config: RuntimeConfig,
        document_id: str,
    ) -> RuntimeComponents:
        """Create all adapters required by the analysis pipeline."""

        llm_client = self.builders.build_llm_client(config)
        codeql_client = self.builders.build_codeql_client(config)

        poc_refiner: PocRefiner | None = None

        if config.analysis.enable_poc_refinement:
            poc_refiner = self.builders.build_poc_refiner(
                config,
                llm_client,
            )

        return RuntimeComponents(
            sbom_generator=(
                self.builders.build_sbom_generator(config)
            ),
            vulnerability_scanner=(
                self.builders.build_vulnerability_scanner(config)
            ),
            usage_analyzer=self.builders.build_usage_analyzer(
                config,
                codeql_client,
            ),
            api_selector=self.builders.build_api_selector(
                config,
                llm_client,
            ),
            taint_analyzer=self.builders.build_taint_analyzer(
                config,
                codeql_client,
            ),
            poc_generator=self.builders.build_poc_generator(
                config,
                llm_client,
            ),
            poc_runner=self.builders.build_poc_runner(config),
            poc_refiner=poc_refiner,
            vex_policy=self.builders.build_vex_policy(config),
            vex_writer=self.builders.build_vex_writer(
                config,
                document_id,
            ),
            artifact_writer=(
                self.builders.build_artifact_writer(config)
            ),
        )