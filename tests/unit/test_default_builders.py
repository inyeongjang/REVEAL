"""Tests for the default runtime adapter builders."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

import reveal.default_builders as default_builders
from reveal.config import (
    AnalysisConfig,
    LlmConfig,
    LlmProvider,
    RuntimeConfig,
    ToolConfig,
    VexConfig,
)
from reveal.exceptions import BootstrapError
from reveal.llm import LlmClient
from reveal.runtime_factory import (
    CodeQLClientPort,
    ConfiguredRuntimeComponentFactory,
)


def test_openai_builder_uses_runtime_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: dict[str, object] = {}

    class FakeOpenAiClient:
        def __init__(
            self,
            *,
            model: str,
            api_key: str | None,
            timeout_seconds: float,
        ) -> None:
            received.update(
                {
                    "model": model,
                    "api_key": api_key,
                    "timeout_seconds": timeout_seconds,
                }
            )

    monkeypatch.setattr(
        default_builders,
        "OpenAILlmClient",
        FakeOpenAiClient,
    )

    config = RuntimeConfig(
        llm=LlmConfig(
            provider=LlmProvider.OPENAI,
            model="test-openai-model",
            openai_api_key="test-api-key",
            timeout_seconds=42.5,
        )
    )

    client = (
        default_builders
        .create_default_adapter_builders()
        .build_llm_client(config)
    )

    assert isinstance(client, FakeOpenAiClient)
    assert received == {
        "model": "test-openai-model",
        "api_key": "test-api-key",
        "timeout_seconds": 42.5,
    }


def test_ollama_builder_appends_generate_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: dict[str, object] = {}

    class FakeOllamaClient:
        def __init__(
            self,
            *,
            model: str,
            endpoint: str,
            timeout_seconds: float,
        ) -> None:
            received.update(
                {
                    "model": model,
                    "endpoint": endpoint,
                    "timeout_seconds": timeout_seconds,
                }
            )

    monkeypatch.setattr(
        default_builders,
        "OllamaLlmClient",
        FakeOllamaClient,
    )

    config = RuntimeConfig(
        llm=LlmConfig(
            provider=LlmProvider.OLLAMA,
            model="qwen-test",
            ollama_base_url="http://127.0.0.1:11434",
            timeout_seconds=90.0,
        )
    )

    client = (
        default_builders
        .create_default_adapter_builders()
        .build_llm_client(config)
    )

    assert isinstance(client, FakeOllamaClient)
    assert received == {
        "model": "qwen-test",
        "endpoint": (
            "http://127.0.0.1:11434/api/generate"
        ),
        "timeout_seconds": 90.0,
    }


def test_command_builders_use_configured_executables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: dict[str, tuple[object, ...]] = {}

    class FakeSyft:
        def __init__(
            self,
            executable: str,
            timeout_seconds: int,
        ) -> None:
            received["syft"] = (
                executable,
                timeout_seconds,
            )

    class FakeGrype:
        def __init__(
            self,
            executable: str,
            timeout_seconds: int,
        ) -> None:
            received["grype"] = (
                executable,
                timeout_seconds,
            )

    class FakeCodeQL:
        def __init__(
            self,
            executable: str,
            timeout_seconds: int,
        ) -> None:
            received["codeql"] = (
                executable,
                timeout_seconds,
            )

    class FakeDocker:
        def __init__(
            self,
            *,
            executable: str,
            timeout_seconds: float,
        ) -> None:
            received["docker"] = (
                executable,
                timeout_seconds,
            )

    monkeypatch.setattr(
        default_builders,
        "SyftSbomGenerator",
        FakeSyft,
    )
    monkeypatch.setattr(
        default_builders,
        "GrypeVulnerabilityScanner",
        FakeGrype,
    )
    monkeypatch.setattr(
        default_builders,
        "CodeQLClient",
        FakeCodeQL,
    )
    monkeypatch.setattr(
        default_builders,
        "DockerPocRunner",
        FakeDocker,
    )

    config = RuntimeConfig(
        tools=ToolConfig(
            syft_executable="/tools/syft",
            grype_executable="/tools/grype",
            codeql_executable="/tools/codeql",
            docker_executable="/tools/docker",
            command_timeout_seconds=12.2,
            poc_timeout_seconds=45.0,
        )
    )
    builders = (
        default_builders.create_default_adapter_builders()
    )

    builders.build_sbom_generator(config)
    builders.build_vulnerability_scanner(config)
    builders.build_codeql_client(config)
    builders.build_poc_runner(config)

    assert received == {
        "syft": (
            "/tools/syft",
            13,
        ),
        "grype": (
            "/tools/grype",
            13,
        ),
        "codeql": (
            "/tools/codeql",
            13,
        ),
        "docker": (
            "/tools/docker",
            45.0,
        ),
    }


def test_codeql_analyzers_share_default_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: dict[str, object] = {}

    class FakeCodeQL:
        def __init__(
            self,
            executable: str,
            timeout_seconds: int,
        ) -> None:
            self.executable = executable
            self.timeout_seconds = timeout_seconds

    class FakeUsageAnalyzer:
        def __init__(
            self,
            client: FakeCodeQL | None = None,
        ) -> None:
            received["usage_client"] = client

    class FakeTaintAnalyzer:
        def __init__(
            self,
            client: FakeCodeQL,
        ) -> None:
            received["taint_client"] = client

    monkeypatch.setattr(
        default_builders,
        "CodeQLClient",
        FakeCodeQL,
    )
    monkeypatch.setattr(
        default_builders,
        "CodeQLUsageAnalyzer",
        FakeUsageAnalyzer,
    )
    monkeypatch.setattr(
        default_builders,
        "CodeQLTaintAnalyzer",
        FakeTaintAnalyzer,
    )

    config = RuntimeConfig()
    builders = (
        default_builders.create_default_adapter_builders()
    )
    client = builders.build_codeql_client(config)

    builders.build_usage_analyzer(
        config,
        client,
    )
    builders.build_taint_analyzer(
        config,
        client,
    )

    assert received["usage_client"] is client
    assert received["taint_client"] is client


def test_api_selector_uses_optional_closed_corpus(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    received: dict[str, object] = {}

    class FakeRetriever:
        def __init__(
            self,
            corpus_path: Path,
        ) -> None:
            received["corpus_path"] = corpus_path

    class FakeSelector:
        def __init__(
            self,
            client: LlmClient,
            retriever: object | None = None,
            evidence_limit: int = 5,
        ) -> None:
            received["client"] = client
            received["retriever"] = retriever
            received["evidence_limit"] = evidence_limit

    monkeypatch.setattr(
        default_builders,
        "ClosedCorpusEvidenceRetriever",
        FakeRetriever,
    )
    monkeypatch.setattr(
        default_builders,
        "LlmVulnerableApiSelector",
        FakeSelector,
    )

    config = RuntimeConfig(
        analysis=AnalysisConfig(
            corpus_path=corpus_path,
            retrieval_top_k=8,
        )
    )
    llm_client = cast(
        LlmClient,
        object(),
    )

    selector = (
        default_builders
        .create_default_adapter_builders()
        .build_api_selector(
            config,
            llm_client,
        )
    )

    assert isinstance(selector, FakeSelector)
    assert received["client"] is llm_client
    assert received["corpus_path"] == corpus_path
    assert received["evidence_limit"] == 8
    assert isinstance(
        received["retriever"],
        FakeRetriever,
    )


def test_vex_writer_uses_runtime_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: dict[str, object] = {}

    class FakeVexWriter:
        def __init__(
            self,
            *,
            author: str,
            document_id: str,
            role: str | None,
            tooling: str | None,
        ) -> None:
            received.update(
                {
                    "author": author,
                    "document_id": document_id,
                    "role": role,
                    "tooling": tooling,
                }
            )

    monkeypatch.setattr(
        default_builders,
        "OpenVexWriter",
        FakeVexWriter,
    )

    config = RuntimeConfig(
        vex=VexConfig(
            author="Example Security Team",
            role="Security Analyst",
            tooling="REVEAL test",
        )
    )

    writer = (
        default_builders
        .create_default_adapter_builders()
        .build_vex_writer(
            config,
            "urn:uuid:test-document",
        )
    )

    assert isinstance(writer, FakeVexWriter)
    assert received == {
        "author": "Example Security Team",
        "document_id": "urn:uuid:test-document",
        "role": "Security Analyst",
        "tooling": "REVEAL test",
    }


def test_default_factory_is_configured_factory() -> None:
    factory = (
        default_builders
        .create_default_runtime_component_factory()
    )

    assert isinstance(
        factory,
        ConfiguredRuntimeComponentFactory,
    )


def test_default_codeql_analyzers_reject_other_client() -> None:
    class OtherCodeQLClient:
        def create_database(
            self,
            source: Path,
            database_path: Path,
        ) -> None:
            del source, database_path

        def run_query(
            self,
            database_path: Path,
            query_path: Path,
            output_path: Path,
        ) -> None:
            del database_path, query_path, output_path

        def decode_bqrs(
            self,
            bqrs_path: Path,
            output_path: Path,
        ) -> None:
            del bqrs_path, output_path

    client = cast(
        CodeQLClientPort,
        OtherCodeQLClient(),
    )
    builders = (
        default_builders.create_default_adapter_builders()
    )

    with pytest.raises(
        BootstrapError,
        match="require a CodeQLClient",
    ):
        builders.build_usage_analyzer(
            RuntimeConfig(),
            client,
        )