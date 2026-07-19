"""Tests for configured runtime component construction."""

from __future__ import annotations

from typing import cast

from reveal.artifacts import AnalysisArtifactWriter
from reveal.config import AnalysisConfig, RuntimeConfig
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
from reveal.runtime_factory import (
    CodeQLClientPort,
    ConfiguredRuntimeComponentFactory,
    RuntimeAdapterBuilders,
)
from reveal.sbom import SbomGenerator
from reveal.vex import VexDecisionPolicy, VexWriter
from reveal.vulnerabilities import VulnerabilityScanner


class RuntimeSentinels:
    """Typed sentinel objects used to verify component wiring."""

    def __init__(self) -> None:
        self.llm_client = cast(
            LlmClient,
            object(),
        )
        self.codeql_client = cast(
            CodeQLClientPort,
            object(),
        )
        self.sbom_generator = cast(
            SbomGenerator,
            object(),
        )
        self.vulnerability_scanner = cast(
            VulnerabilityScanner,
            object(),
        )
        self.usage_analyzer = cast(
            UsageAnalyzer,
            object(),
        )
        self.api_selector = cast(
            VulnerableApiSelector,
            object(),
        )
        self.taint_analyzer = cast(
            TaintAnalyzer,
            object(),
        )
        self.poc_generator = cast(
            PocGenerator,
            object(),
        )
        self.poc_refiner = cast(
            PocRefiner,
            object(),
        )
        self.poc_runner = cast(
            PocRunner,
            object(),
        )
        self.vex_policy = cast(
            VexDecisionPolicy,
            object(),
        )
        self.vex_writer = cast(
            VexWriter,
            object(),
        )
        self.artifact_writer = cast(
            AnalysisArtifactWriter,
            object(),
        )


class RecordingBuilders:
    """Record adapter construction and shared-client wiring."""

    def __init__(
        self,
        sentinels: RuntimeSentinels,
    ) -> None:
        self.sentinels = sentinels
        self.calls: list[str] = []
        self.document_ids: list[str] = []

    def build_llm_client(
        self,
        config: RuntimeConfig,
    ) -> LlmClient:
        del config

        self.calls.append("llm_client")

        return self.sentinels.llm_client

    def build_codeql_client(
        self,
        config: RuntimeConfig,
    ) -> CodeQLClientPort:
        del config

        self.calls.append("codeql_client")

        return self.sentinels.codeql_client

    def build_sbom_generator(
        self,
        config: RuntimeConfig,
    ) -> SbomGenerator:
        del config

        self.calls.append("sbom_generator")

        return self.sentinels.sbom_generator

    def build_vulnerability_scanner(
        self,
        config: RuntimeConfig,
    ) -> VulnerabilityScanner:
        del config

        self.calls.append("vulnerability_scanner")

        return self.sentinels.vulnerability_scanner

    def build_usage_analyzer(
        self,
        config: RuntimeConfig,
        client: CodeQLClientPort,
    ) -> UsageAnalyzer:
        del config

        assert client is self.sentinels.codeql_client

        self.calls.append("usage_analyzer")

        return self.sentinels.usage_analyzer

    def build_api_selector(
        self,
        config: RuntimeConfig,
        client: LlmClient,
    ) -> VulnerableApiSelector:
        del config

        assert client is self.sentinels.llm_client

        self.calls.append("api_selector")

        return self.sentinels.api_selector

    def build_taint_analyzer(
        self,
        config: RuntimeConfig,
        client: CodeQLClientPort,
    ) -> TaintAnalyzer:
        del config

        assert client is self.sentinels.codeql_client

        self.calls.append("taint_analyzer")

        return self.sentinels.taint_analyzer

    def build_poc_generator(
        self,
        config: RuntimeConfig,
        client: LlmClient,
    ) -> PocGenerator:
        del config

        assert client is self.sentinels.llm_client

        self.calls.append("poc_generator")

        return self.sentinels.poc_generator

    def build_poc_refiner(
        self,
        config: RuntimeConfig,
        client: LlmClient,
    ) -> PocRefiner:
        del config

        assert client is self.sentinels.llm_client

        self.calls.append("poc_refiner")

        return self.sentinels.poc_refiner

    def build_poc_runner(
        self,
        config: RuntimeConfig,
    ) -> PocRunner:
        del config

        self.calls.append("poc_runner")

        return self.sentinels.poc_runner

    def build_vex_policy(
        self,
        config: RuntimeConfig,
    ) -> VexDecisionPolicy:
        del config

        self.calls.append("vex_policy")

        return self.sentinels.vex_policy

    def build_vex_writer(
        self,
        config: RuntimeConfig,
        document_id: str,
    ) -> VexWriter:
        del config

        self.calls.append("vex_writer")
        self.document_ids.append(document_id)

        return self.sentinels.vex_writer

    def build_artifact_writer(
        self,
        config: RuntimeConfig,
    ) -> AnalysisArtifactWriter:
        del config

        self.calls.append("artifact_writer")

        return self.sentinels.artifact_writer

    def as_bundle(self) -> RuntimeAdapterBuilders:
        """Return the recorded methods as one builder bundle."""

        return RuntimeAdapterBuilders(
            build_llm_client=self.build_llm_client,
            build_codeql_client=self.build_codeql_client,
            build_sbom_generator=self.build_sbom_generator,
            build_vulnerability_scanner=(
                self.build_vulnerability_scanner
            ),
            build_usage_analyzer=self.build_usage_analyzer,
            build_api_selector=self.build_api_selector,
            build_taint_analyzer=self.build_taint_analyzer,
            build_poc_generator=self.build_poc_generator,
            build_poc_refiner=self.build_poc_refiner,
            build_poc_runner=self.build_poc_runner,
            build_vex_policy=self.build_vex_policy,
            build_vex_writer=self.build_vex_writer,
            build_artifact_writer=self.build_artifact_writer,
        )


def test_factory_builds_all_runtime_components() -> None:
    config = RuntimeConfig()
    sentinels = RuntimeSentinels()
    recording = RecordingBuilders(sentinels)
    factory = ConfiguredRuntimeComponentFactory(
        recording.as_bundle()
    )

    components = factory.create(
        config=config,
        document_id="urn:uuid:test-document",
    )

    assert components.sbom_generator is (
        sentinels.sbom_generator
    )
    assert components.vulnerability_scanner is (
        sentinels.vulnerability_scanner
    )
    assert components.usage_analyzer is (
        sentinels.usage_analyzer
    )
    assert components.api_selector is sentinels.api_selector
    assert components.taint_analyzer is (
        sentinels.taint_analyzer
    )
    assert components.poc_generator is (
        sentinels.poc_generator
    )
    assert components.poc_refiner is sentinels.poc_refiner
    assert components.poc_runner is sentinels.poc_runner
    assert components.vex_policy is sentinels.vex_policy
    assert components.vex_writer is sentinels.vex_writer
    assert components.artifact_writer is (
        sentinels.artifact_writer
    )

    assert recording.document_ids == [
        "urn:uuid:test-document",
    ]

    assert recording.calls.count("llm_client") == 1
    assert recording.calls.count("codeql_client") == 1
    assert recording.calls.count("poc_refiner") == 1


def test_factory_reuses_shared_clients() -> None:
    config = RuntimeConfig()
    sentinels = RuntimeSentinels()
    recording = RecordingBuilders(sentinels)

    ConfiguredRuntimeComponentFactory(
        recording.as_bundle()
    ).create(
        config=config,
        document_id="urn:uuid:test-document",
    )

    assert recording.calls.index("llm_client") < (
        recording.calls.index("api_selector")
    )
    assert recording.calls.index("llm_client") < (
        recording.calls.index("poc_generator")
    )
    assert recording.calls.index("llm_client") < (
        recording.calls.index("poc_refiner")
    )

    assert recording.calls.index("codeql_client") < (
        recording.calls.index("usage_analyzer")
    )
    assert recording.calls.index("codeql_client") < (
        recording.calls.index("taint_analyzer")
    )


def test_factory_skips_refiner_when_disabled() -> None:
    config = RuntimeConfig(
        analysis=AnalysisConfig(
            enable_poc_refinement=False,
        )
    )
    sentinels = RuntimeSentinels()
    recording = RecordingBuilders(sentinels)

    components = ConfiguredRuntimeComponentFactory(
        recording.as_bundle()
    ).create(
        config=config,
        document_id="urn:uuid:test-document",
    )

    assert components.poc_refiner is None
    assert "poc_refiner" not in recording.calls