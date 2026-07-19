"""Runtime configuration for REVEAL."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from reveal.exceptions import ConfigurationError


class LlmProvider(str, Enum):
    """Supported LLM service providers."""

    OPENAI = "openai"
    OLLAMA = "ollama"


_DEFAULT_MODELS = {
    LlmProvider.OPENAI: "gpt-5.6",
    LlmProvider.OLLAMA: "qwen2.5-coder:7b",
}


@dataclass(frozen=True, slots=True)
class LlmConfig:
    """Configuration for LLM requests."""

    provider: LlmProvider = LlmProvider.OPENAI
    model: str = "gpt-5.6"
    openai_api_key: str | None = field(
        default=None,
        repr=False,
    )
    ollama_base_url: str = "http://localhost:11434"
    timeout_seconds: float = 300.0
    max_retries: int = 2

    def __post_init__(self) -> None:
        model = _normalize_required_text(
            self.model,
            field_name="LLM model",
        )
        base_url = self.ollama_base_url.strip().rstrip("/")

        if not _is_http_url(base_url):
            raise ConfigurationError(
                "Ollama base URL must be an absolute HTTP or HTTPS URL."
            )

        if self.timeout_seconds <= 0:
            raise ConfigurationError(
                "LLM timeout must be greater than zero."
            )

        if self.max_retries < 0:
            raise ConfigurationError(
                "LLM max retries must not be negative."
            )

        api_key = self.openai_api_key

        if api_key is not None:
            api_key = api_key.strip() or None

        object.__setattr__(self, "model", model)
        object.__setattr__(
            self,
            "ollama_base_url",
            base_url,
        )
        object.__setattr__(
            self,
            "openai_api_key",
            api_key,
        )


@dataclass(frozen=True, slots=True)
class ToolConfig:
    """Configuration for external command-line tools."""

    syft_executable: str = "syft"
    grype_executable: str = "grype"
    codeql_executable: str = "codeql"
    docker_executable: str = "docker"
    command_timeout_seconds: float = 300.0
    poc_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        syft_executable = _normalize_required_text(
            self.syft_executable,
            field_name="Syft executable",
        )
        grype_executable = _normalize_required_text(
            self.grype_executable,
            field_name="Grype executable",
        )
        codeql_executable = _normalize_required_text(
            self.codeql_executable,
            field_name="CodeQL executable",
        )
        docker_executable = _normalize_required_text(
            self.docker_executable,
            field_name="Docker executable",
        )

        if self.command_timeout_seconds <= 0:
            raise ConfigurationError(
                "Command timeout must be greater than zero."
            )

        if self.poc_timeout_seconds <= 0:
            raise ConfigurationError(
                "PoC timeout must be greater than zero."
            )

        object.__setattr__(
            self,
            "syft_executable",
            syft_executable,
        )
        object.__setattr__(
            self,
            "grype_executable",
            grype_executable,
        )
        object.__setattr__(
            self,
            "codeql_executable",
            codeql_executable,
        )
        object.__setattr__(
            self,
            "docker_executable",
            docker_executable,
        )


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    """Configuration for analysis and reproduction behavior."""

    api_mapping_min_confidence: float = 0.75
    retrieval_top_k: int = 5
    corpus_path: Path | None = None
    max_poc_candidates: int = 3
    max_poc_refinement_rounds: int = 2
    enable_poc_refinement: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.api_mapping_min_confidence <= 1.0:
            raise ConfigurationError(
                "API mapping minimum confidence must be between zero "
                "and one."
            )

        if self.retrieval_top_k < 1:
            raise ConfigurationError(
                "Retrieval top-k must be at least one."
            )

        if self.max_poc_candidates < 1:
            raise ConfigurationError(
                "Maximum PoC candidates must be at least one."
            )

        if self.max_poc_refinement_rounds < 0:
            raise ConfigurationError(
                "Maximum PoC refinement rounds must not be negative."
            )

        if self.corpus_path is not None:
            object.__setattr__(
                self,
                "corpus_path",
                self.corpus_path.expanduser(),
            )


@dataclass(frozen=True, slots=True)
class VexConfig:
    """Configuration for generated OpenVEX documents."""

    author: str = "REVEAL Security Research"
    role: str | None = "Document Creator"
    tooling: str | None = "REVEAL"

    def __post_init__(self) -> None:
        author = _normalize_required_text(
            self.author,
            field_name="VEX author",
        )

        object.__setattr__(self, "author", author)
        object.__setattr__(
            self,
            "role",
            _normalize_optional_text(self.role),
        )
        object.__setattr__(
            self,
            "tooling",
            _normalize_optional_text(self.tooling),
        )


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """Complete runtime configuration for one REVEAL process."""

    llm: LlmConfig = field(default_factory=LlmConfig)
    tools: ToolConfig = field(default_factory=ToolConfig)
    analysis: AnalysisConfig = field(
        default_factory=AnalysisConfig
    )
    vex: VexConfig = field(default_factory=VexConfig)

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> RuntimeConfig:
        """Load configuration from environment variables."""

        source = os.environ if environ is None else environ

        provider = _parse_provider(
            _read_text(
                source,
                "REVEAL_LLM_PROVIDER",
                default=LlmProvider.OPENAI.value,
            )
        )
        model = _read_text(
            source,
            "REVEAL_LLM_MODEL",
            default=_DEFAULT_MODELS[provider],
        )

        llm = LlmConfig(
            provider=provider,
            model=model,
            openai_api_key=_first_optional_text(
                source,
                "REVEAL_OPENAI_API_KEY",
                "OPENAI_API_KEY",
            ),
            ollama_base_url=_read_text(
                source,
                "REVEAL_OLLAMA_BASE_URL",
                default="http://localhost:11434",
            ),
            timeout_seconds=_read_float(
                source,
                "REVEAL_LLM_TIMEOUT",
                default=300.0,
            ),
            max_retries=_read_int(
                source,
                "REVEAL_LLM_MAX_RETRIES",
                default=2,
            ),
        )

        tools = ToolConfig(
            syft_executable=_read_text(
                source,
                "REVEAL_SYFT_PATH",
                default="syft",
            ),
            grype_executable=_read_text(
                source,
                "REVEAL_GRYPE_PATH",
                default="grype",
            ),
            codeql_executable=_read_text(
                source,
                "REVEAL_CODEQL_PATH",
                default="codeql",
            ),
            docker_executable=_read_text(
                source,
                "REVEAL_DOCKER_PATH",
                default="docker",
            ),
            command_timeout_seconds=_read_float(
                source,
                "REVEAL_COMMAND_TIMEOUT",
                default=300.0,
            ),
            poc_timeout_seconds=_read_float(
                source,
                "REVEAL_POC_TIMEOUT",
                default=30.0,
            ),
        )

        corpus_value = _read_optional_text(
            source,
            "REVEAL_CORPUS_PATH",
        )
        corpus_path = (
            Path(corpus_value).expanduser()
            if corpus_value is not None
            else None
        )

        analysis = AnalysisConfig(
            api_mapping_min_confidence=_read_float(
                source,
                "REVEAL_API_MIN_CONFIDENCE",
                default=0.75,
            ),
            retrieval_top_k=_read_int(
                source,
                "REVEAL_RETRIEVAL_TOP_K",
                default=5,
            ),
            corpus_path=corpus_path,
            max_poc_candidates=_read_int(
                source,
                "REVEAL_MAX_POC_CANDIDATES",
                default=3,
            ),
            max_poc_refinement_rounds=_read_int(
                source,
                "REVEAL_MAX_POC_REFINEMENT_ROUNDS",
                default=2,
            ),
            enable_poc_refinement=_read_bool(
                source,
                "REVEAL_ENABLE_POC_REFINEMENT",
                default=True,
            ),
        )

        vex = VexConfig(
            author=_read_text(
                source,
                "REVEAL_VEX_AUTHOR",
                default="REVEAL Security Research",
            ),
            role=_read_optional_text_with_default(
                source,
                "REVEAL_VEX_ROLE",
                default="Document Creator",
            ),
            tooling=_read_optional_text_with_default(
                source,
                "REVEAL_VEX_TOOLING",
                default="REVEAL",
            ),
        )

        return cls(
            llm=llm,
            tools=tools,
            analysis=analysis,
            vex=vex,
        )


def _parse_provider(value: str) -> LlmProvider:
    try:
        return LlmProvider(value.strip().casefold())
    except ValueError as error:
        allowed = ", ".join(
            provider.value
            for provider in LlmProvider
        )
        raise ConfigurationError(
            f"Unsupported LLM provider {value!r}. "
            f"Expected one of: {allowed}."
        ) from error


def _read_text(
    environ: Mapping[str, str],
    key: str,
    *,
    default: str,
) -> str:
    value = environ.get(key)

    if value is None:
        return default

    normalized = value.strip()

    if not normalized:
        raise ConfigurationError(
            f"Environment variable {key} must not be empty."
        )

    return normalized


def _read_optional_text(
    environ: Mapping[str, str],
    key: str,
) -> str | None:
    value = environ.get(key)

    if value is None:
        return None

    return value.strip() or None


def _read_optional_text_with_default(
    environ: Mapping[str, str],
    key: str,
    *,
    default: str | None,
) -> str | None:
    if key not in environ:
        return default

    return _read_optional_text(environ, key)


def _first_optional_text(
    environ: Mapping[str, str],
    *keys: str,
) -> str | None:
    for key in keys:
        value = _read_optional_text(environ, key)

        if value is not None:
            return value

    return None


def _read_int(
    environ: Mapping[str, str],
    key: str,
    *,
    default: int,
) -> int:
    value = environ.get(key)

    if value is None:
        return default

    try:
        return int(value.strip())
    except ValueError as error:
        raise ConfigurationError(
            f"Environment variable {key} must be an integer."
        ) from error


def _read_float(
    environ: Mapping[str, str],
    key: str,
    *,
    default: float,
) -> float:
    value = environ.get(key)

    if value is None:
        return default

    try:
        return float(value.strip())
    except ValueError as error:
        raise ConfigurationError(
            f"Environment variable {key} must be a number."
        ) from error


def _read_bool(
    environ: Mapping[str, str],
    key: str,
    *,
    default: bool,
) -> bool:
    value = environ.get(key)

    if value is None:
        return default

    normalized = value.strip().casefold()

    if normalized in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return True

    if normalized in {
        "0",
        "false",
        "no",
        "off",
    }:
        return False

    raise ConfigurationError(
        f"Environment variable {key} must be a boolean."
    )


def _normalize_required_text(
    value: str,
    *,
    field_name: str,
) -> str:
    normalized = value.strip()

    if not normalized:
        raise ConfigurationError(
            f"{field_name} must not be empty."
        )

    return normalized


def _normalize_optional_text(
    value: str | None,
) -> str | None:
    if value is None:
        return None

    return value.strip() or None


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)

    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.netloc)
    )