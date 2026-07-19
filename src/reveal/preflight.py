"""Runtime environment preflight checks for REVEAL."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from reveal.config import LlmProvider, RuntimeConfig
from reveal.exceptions import PreflightError


@dataclass(frozen=True, slots=True)
class DependencyStatus:
    """Resolved external executable dependency."""

    name: str
    configured_value: str
    resolved_path: Path


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Successful runtime preflight result."""

    dependencies: tuple[DependencyStatus, ...]

    @property
    def dependency_count(self) -> int:
        """Return the number of resolved external dependencies."""

        return len(self.dependencies)

    @property
    def dependency_names(self) -> tuple[str, ...]:
        """Return resolved dependency names."""

        return tuple(
            dependency.name
            for dependency in self.dependencies
        )


def run_preflight(
    config: RuntimeConfig,
) -> PreflightReport:
    """Validate runtime settings and resolve external tools."""

    problems: list[str] = []

    _validate_llm_configuration(
        config=config,
        problems=problems,
    )
    _validate_corpus(
        config=config,
        problems=problems,
    )

    dependencies: list[DependencyStatus] = []

    for name, configured_value in (
        (
            "Syft",
            config.tools.syft_executable,
        ),
        (
            "Grype",
            config.tools.grype_executable,
        ),
        (
            "CodeQL",
            config.tools.codeql_executable,
        ),
        (
            "Docker",
            config.tools.docker_executable,
        ),
    ):
        try:
            dependency = _resolve_dependency(
                name=name,
                configured_value=configured_value,
            )
        except PreflightError as error:
            problems.append(str(error))
        else:
            dependencies.append(dependency)

    if problems:
        formatted = "\n".join(
            f"- {problem}"
            for problem in problems
        )

        raise PreflightError(
            "Runtime preflight failed:\n"
            f"{formatted}"
        )

    return PreflightReport(
        dependencies=tuple(dependencies),
    )


def _validate_llm_configuration(
    *,
    config: RuntimeConfig,
    problems: list[str],
) -> None:
    if (
        config.llm.provider is LlmProvider.OPENAI
        and config.llm.openai_api_key is None
    ):
        problems.append(
            "OpenAI provider requires OPENAI_API_KEY or "
            "REVEAL_OPENAI_API_KEY."
        )


def _validate_corpus(
    *,
    config: RuntimeConfig,
    problems: list[str],
) -> None:
    corpus_path = config.analysis.corpus_path

    if corpus_path is None:
        return

    if not corpus_path.exists():
        problems.append(
            "Closed-corpus evidence file does not exist: "
            f"{corpus_path}"
        )

        return

    if not corpus_path.is_file():
        problems.append(
            "Closed-corpus evidence path is not a file: "
            f"{corpus_path}"
        )


def _resolve_dependency(
    *,
    name: str,
    configured_value: str,
) -> DependencyStatus:
    if _looks_like_path(configured_value):
        resolved_path = (
            Path(configured_value)
            .expanduser()
            .resolve()
        )

        if not resolved_path.exists():
            raise PreflightError(
                f"{name} executable does not exist: "
                f"{resolved_path}"
            )

        if not resolved_path.is_file():
            raise PreflightError(
                f"{name} executable path is not a file: "
                f"{resolved_path}"
            )

        if not os.access(resolved_path, os.X_OK):
            raise PreflightError(
                f"{name} executable is not executable: "
                f"{resolved_path}"
            )

        return DependencyStatus(
            name=name,
            configured_value=configured_value,
            resolved_path=resolved_path,
        )

    located = shutil.which(configured_value)

    if located is None:
        raise PreflightError(
            f"{name} executable was not found on PATH: "
            f"{configured_value}"
        )

    return DependencyStatus(
        name=name,
        configured_value=configured_value,
        resolved_path=Path(located).resolve(),
    )


def _looks_like_path(value: str) -> bool:
    path = Path(value)

    return (
        path.is_absolute()
        or path.parent != Path(".")
        or "/" in value
        or "\\" in value
    )