"""Default runtime adapter builders for REVEAL."""

from __future__ import annotations

from math import ceil

from reveal.artifacts import (
    AnalysisArtifactWriter,
    JsonAnalysisArtifactWriter,
)
from reveal.config import LlmProvider, RuntimeConfig
from reveal.exceptions import BootstrapError
from reveal.llm import LlmClient
from reveal.llm.ollama import OllamaLlmClient
from reveal.llm.openai import OpenAILlmClient
from reveal.reachability import (
    TaintAnalyzer,
    UsageAnalyzer,
    VulnerableApiSelector,
)
from reveal.reachability.closed_corpus import (
    ClosedCorpusEvidenceRetriever,
)
from reveal.reachability.codeql.client import CodeQLClient
from reveal.reachability.codeql.taint_analyzer import (
    CodeQLTaintAnalyzer,
)
from reveal.reachability.codeql.usage_analyzer import (
    CodeQLUsageAnalyzer,
)
from reveal.reachability.llm_selector import (
    LlmVulnerableApiSelector,
)
from reveal.reproduction import (
    PocGenerator,
    PocRefiner,
    PocRunner,
)
from reveal.reproduction.docker_runner import DockerPocRunner
from reveal.reproduction.llm_generator import LlmPocGenerator
from reveal.reproduction.llm_refiner import LlmPocRefiner
from reveal.runtime_factory import (
    CodeQLClientPort,
    ConfiguredRuntimeComponentFactory,
    RuntimeAdapterBuilders,
)
from reveal.sbom import SbomGenerator
from reveal.sbom.syft import SyftSbomGenerator
from reveal.vex import VexDecisionPolicy, VexWriter
from reveal.vex.openvex import OpenVexWriter
from reveal.vex.policy import DefaultVexDecisionPolicy
from reveal.vulnerabilities import VulnerabilityScanner
from reveal.vulnerabilities.grype import (
    GrypeVulnerabilityScanner,
)


def create_default_runtime_component_factory(
) -> ConfiguredRuntimeComponentFactory:
    """Create the standard REVEAL runtime component factory."""

    return ConfiguredRuntimeComponentFactory(
        create_default_adapter_builders()
    )


def create_default_adapter_builders() -> RuntimeAdapterBuilders:
    """Create builders for the standard REVEAL adapters."""

    return RuntimeAdapterBuilders(
        build_llm_client=_build_llm_client,
        build_codeql_client=_build_codeql_client,
        build_sbom_generator=_build_sbom_generator,
        build_vulnerability_scanner=(
            _build_vulnerability_scanner
        ),
        build_usage_analyzer=_build_usage_analyzer,
        build_api_selector=_build_api_selector,
        build_taint_analyzer=_build_taint_analyzer,
        build_poc_generator=_build_poc_generator,
        build_poc_refiner=_build_poc_refiner,
        build_poc_runner=_build_poc_runner,
        build_vex_policy=_build_vex_policy,
        build_vex_writer=_build_vex_writer,
        build_artifact_writer=_build_artifact_writer,
    )


def _build_llm_client(
    config: RuntimeConfig,
) -> LlmClient:
    if config.llm.provider is LlmProvider.OPENAI:
        return OpenAILlmClient(
            model=config.llm.model,
            api_key=config.llm.openai_api_key,
            timeout_seconds=config.llm.timeout_seconds,
        )

    if config.llm.provider is LlmProvider.OLLAMA:
        return OllamaLlmClient(
            model=config.llm.model,
            endpoint=_ollama_generate_endpoint(config),
            timeout_seconds=config.llm.timeout_seconds,
        )

    raise BootstrapError(
        f"Unsupported LLM provider: {config.llm.provider}"
    )


def _build_codeql_client(
    config: RuntimeConfig,
) -> CodeQLClientPort:
    return CodeQLClient(
        executable=config.tools.codeql_executable,
        timeout_seconds=_command_timeout_seconds(config),
    )


def _build_sbom_generator(
    config: RuntimeConfig,
) -> SbomGenerator:
    return SyftSbomGenerator(
        executable=config.tools.syft_executable,
        timeout_seconds=_command_timeout_seconds(config),
    )


def _build_vulnerability_scanner(
    config: RuntimeConfig,
) -> VulnerabilityScanner:
    return GrypeVulnerabilityScanner(
        executable=config.tools.grype_executable,
        timeout_seconds=_command_timeout_seconds(config),
    )


def _build_usage_analyzer(
    config: RuntimeConfig,
    client: CodeQLClientPort,
) -> UsageAnalyzer:
    del config

    return CodeQLUsageAnalyzer(
        client=_require_default_codeql_client(client)
    )


def _build_api_selector(
    config: RuntimeConfig,
    client: LlmClient,
) -> VulnerableApiSelector:
    retriever = None

    if config.analysis.corpus_path is not None:
        retriever = ClosedCorpusEvidenceRetriever(
            corpus_path=config.analysis.corpus_path
        )

    return LlmVulnerableApiSelector(
        client=client,
        retriever=retriever,
        evidence_limit=config.analysis.retrieval_top_k,
    )


def _build_taint_analyzer(
    config: RuntimeConfig,
    client: CodeQLClientPort,
) -> TaintAnalyzer:
    del config

    return CodeQLTaintAnalyzer(
        client=_require_default_codeql_client(client)
    )


def _build_poc_generator(
    config: RuntimeConfig,
    client: LlmClient,
) -> PocGenerator:
    del config

    return LlmPocGenerator(client=client)


def _build_poc_refiner(
    config: RuntimeConfig,
    client: LlmClient,
) -> PocRefiner:
    del config

    return LlmPocRefiner(client=client)


def _build_poc_runner(
    config: RuntimeConfig,
) -> PocRunner:
    return DockerPocRunner(
        executable=config.tools.docker_executable,
        timeout_seconds=config.tools.poc_timeout_seconds,
    )


def _build_vex_policy(
    config: RuntimeConfig,
) -> VexDecisionPolicy:
    del config

    return DefaultVexDecisionPolicy()


def _build_vex_writer(
    config: RuntimeConfig,
    document_id: str,
) -> VexWriter:
    return OpenVexWriter(
        author=config.vex.author,
        document_id=document_id,
        role=config.vex.role,
        tooling=config.vex.tooling,
    )


def _build_artifact_writer(
    config: RuntimeConfig,
) -> AnalysisArtifactWriter:
    del config

    return JsonAnalysisArtifactWriter()


def _require_default_codeql_client(
    client: CodeQLClientPort,
) -> CodeQLClient:
    if not isinstance(client, CodeQLClient):
        raise BootstrapError(
            "Default CodeQL analyzers require a CodeQLClient instance."
        )

    return client


def _command_timeout_seconds(
    config: RuntimeConfig,
) -> int:
    return ceil(config.tools.command_timeout_seconds)


def _ollama_generate_endpoint(
    config: RuntimeConfig,
) -> str:
    return (
        f"{config.llm.ollama_base_url}"
        "/api/generate"
    )