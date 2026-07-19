"""Tests for REVEAL runtime configuration."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from reveal.config import (
    AnalysisConfig,
    LlmConfig,
    LlmProvider,
    RuntimeConfig,
    ToolConfig,
    VexConfig,
)
from reveal.exceptions import ConfigurationError


def test_runtime_config_uses_defaults() -> None:
    config = RuntimeConfig.from_env({})

    assert config.llm.provider is LlmProvider.OPENAI
    assert config.llm.model == "gpt-5.6"
    assert config.llm.openai_api_key is None
    assert config.llm.ollama_base_url == (
        "http://localhost:11434"
    )
    assert config.llm.timeout_seconds == 300.0
    assert config.llm.max_retries == 2

    assert config.tools.syft_executable == "syft"
    assert config.tools.grype_executable == "grype"
    assert config.tools.codeql_executable == "codeql"
    assert config.tools.docker_executable == "docker"
    assert config.tools.command_timeout_seconds == 300.0
    assert config.tools.poc_timeout_seconds == 30.0

    assert config.analysis.api_mapping_min_confidence == 0.75
    assert config.analysis.retrieval_top_k == 5
    assert config.analysis.corpus_path is None
    assert config.analysis.max_poc_candidates == 3
    assert config.analysis.max_poc_refinement_rounds == 2
    assert config.analysis.enable_poc_refinement is True

    assert config.vex.author == "REVEAL Security Research"
    assert config.vex.role == "Document Creator"
    assert config.vex.tooling == "REVEAL"


def test_ollama_provider_uses_ollama_default_model() -> None:
    config = RuntimeConfig.from_env(
        {
            "REVEAL_LLM_PROVIDER": "ollama",
        }
    )

    assert config.llm.provider is LlmProvider.OLLAMA
    assert config.llm.model == "qwen2.5-coder:7b"


def test_runtime_config_reads_environment_values(
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"

    config = RuntimeConfig.from_env(
        {
            "REVEAL_LLM_PROVIDER": "ollama",
            "REVEAL_LLM_MODEL": "deepseek-r1:14b",
            "REVEAL_OLLAMA_BASE_URL": (
                "http://127.0.0.1:11434/"
            ),
            "REVEAL_LLM_TIMEOUT": "120",
            "REVEAL_LLM_MAX_RETRIES": "4",
            "REVEAL_SYFT_PATH": "/tools/syft",
            "REVEAL_GRYPE_PATH": "/tools/grype",
            "REVEAL_CODEQL_PATH": "/tools/codeql",
            "REVEAL_DOCKER_PATH": "/tools/docker",
            "REVEAL_COMMAND_TIMEOUT": "600",
            "REVEAL_POC_TIMEOUT": "45",
            "REVEAL_API_MIN_CONFIDENCE": "0.8",
            "REVEAL_RETRIEVAL_TOP_K": "7",
            "REVEAL_CORPUS_PATH": str(corpus_path),
            "REVEAL_MAX_POC_CANDIDATES": "4",
            "REVEAL_MAX_POC_REFINEMENT_ROUNDS": "3",
            "REVEAL_ENABLE_POC_REFINEMENT": "false",
            "REVEAL_VEX_AUTHOR": "Example Security Team",
            "REVEAL_VEX_ROLE": "Security Analyst",
            "REVEAL_VEX_TOOLING": "REVEAL test build",
        }
    )

    assert config.llm.provider is LlmProvider.OLLAMA
    assert config.llm.model == "deepseek-r1:14b"
    assert config.llm.ollama_base_url == (
        "http://127.0.0.1:11434"
    )
    assert config.llm.timeout_seconds == 120.0
    assert config.llm.max_retries == 4

    assert config.tools.syft_executable == "/tools/syft"
    assert config.tools.grype_executable == "/tools/grype"
    assert config.tools.codeql_executable == "/tools/codeql"
    assert config.tools.docker_executable == "/tools/docker"
    assert config.tools.command_timeout_seconds == 600.0
    assert config.tools.poc_timeout_seconds == 45.0

    assert config.analysis.api_mapping_min_confidence == 0.8
    assert config.analysis.retrieval_top_k == 7
    assert config.analysis.corpus_path == corpus_path
    assert config.analysis.max_poc_candidates == 4
    assert config.analysis.max_poc_refinement_rounds == 3
    assert config.analysis.enable_poc_refinement is False

    assert config.vex.author == "Example Security Team"
    assert config.vex.role == "Security Analyst"
    assert config.vex.tooling == "REVEAL test build"


def test_reveal_openai_key_overrides_standard_key() -> None:
    config = RuntimeConfig.from_env(
        {
            "OPENAI_API_KEY": "standard-key",
            "REVEAL_OPENAI_API_KEY": "reveal-key",
        }
    )

    assert config.llm.openai_api_key == "reveal-key"


def test_openai_key_is_hidden_from_repr() -> None:
    config = LlmConfig(
        openai_api_key="super-secret-key",
    )

    assert "super-secret-key" not in repr(config)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", True),
        ("true", True),
        ("YES", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("NO", False),
        ("off", False),
    ],
)
def test_boolean_environment_values(
    value: str,
    expected: bool,
) -> None:
    config = RuntimeConfig.from_env(
        {
            "REVEAL_ENABLE_POC_REFINEMENT": value,
        }
    )

    assert config.analysis.enable_poc_refinement is expected


def test_empty_optional_vex_fields_become_none() -> None:
    config = RuntimeConfig.from_env(
        {
            "REVEAL_VEX_ROLE": "",
            "REVEAL_VEX_TOOLING": " ",
        }
    )

    assert config.vex.role is None
    assert config.vex.tooling is None


def test_corpus_path_expands_user_directory() -> None:
    config = RuntimeConfig.from_env(
        {
            "REVEAL_CORPUS_PATH": "~/reveal-corpus.json",
        }
    )

    assert config.analysis.corpus_path == Path(
        "~/reveal-corpus.json"
    ).expanduser()


def test_invalid_provider_is_rejected() -> None:
    with pytest.raises(
        ConfigurationError,
        match="Unsupported LLM provider",
    ):
        RuntimeConfig.from_env(
            {
                "REVEAL_LLM_PROVIDER": "unknown",
            }
        )


def test_invalid_boolean_is_rejected() -> None:
    with pytest.raises(
        ConfigurationError,
        match="must be a boolean",
    ):
        RuntimeConfig.from_env(
            {
                "REVEAL_ENABLE_POC_REFINEMENT": "sometimes",
            }
        )


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        (
            "REVEAL_MAX_POC_CANDIDATES",
            "zero",
            "must be an integer",
        ),
        (
            "REVEAL_LLM_TIMEOUT",
            "slow",
            "must be a number",
        ),
    ],
)
def test_invalid_numeric_environment_value_is_rejected(
    key: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(
        ConfigurationError,
        match=message,
    ):
        RuntimeConfig.from_env(
            {
                key: value,
            }
        )


@pytest.mark.parametrize(
    "config_factory",
    [
        lambda: AnalysisConfig(
            api_mapping_min_confidence=1.1
        ),
        lambda: AnalysisConfig(
            retrieval_top_k=0
        ),
        lambda: AnalysisConfig(
            max_poc_candidates=0
        ),
        lambda: AnalysisConfig(
            max_poc_refinement_rounds=-1
        ),
        lambda: ToolConfig(
            command_timeout_seconds=0
        ),
        lambda: ToolConfig(
            poc_timeout_seconds=0
        ),
        lambda: LlmConfig(
            timeout_seconds=0
        ),
        lambda: LlmConfig(
            max_retries=-1
        ),
        lambda: LlmConfig(
            ollama_base_url="localhost:11434"
        ),
        lambda: VexConfig(
            author=""
        ),
    ],
)
def test_invalid_direct_configuration_is_rejected(
    config_factory: Callable[[], object],
) -> None:
    with pytest.raises(ConfigurationError):
        config_factory()