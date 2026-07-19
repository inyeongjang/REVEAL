"""Tests for REVEAL runtime preflight checks."""

from __future__ import annotations

from pathlib import Path

import pytest

import reveal.preflight as preflight
from reveal.config import (
    AnalysisConfig,
    LlmConfig,
    LlmProvider,
    RuntimeConfig,
    ToolConfig,
)
from reveal.exceptions import PreflightError


def create_ollama_config(
    *,
    tools: ToolConfig | None = None,
    analysis: AnalysisConfig | None = None,
) -> RuntimeConfig:
    return RuntimeConfig(
        llm=LlmConfig(
            provider=LlmProvider.OLLAMA,
            model="qwen-test",
        ),
        tools=tools or ToolConfig(),
        analysis=analysis or AnalysisConfig(),
    )


def test_preflight_resolves_required_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    resolved = {
        "syft": tmp_path / "syft",
        "grype": tmp_path / "grype",
        "codeql": tmp_path / "codeql",
        "docker": tmp_path / "docker",
    }

    def fake_which(value: str) -> str | None:
        path = resolved.get(value)

        return str(path) if path is not None else None

    monkeypatch.setattr(
        preflight.shutil,
        "which",
        fake_which,
    )

    report = preflight.run_preflight(
        create_ollama_config()
    )

    assert report.dependency_count == 4
    assert report.dependency_names == (
        "Syft",
        "Grype",
        "CodeQL",
        "Docker",
    )
    assert tuple(
        dependency.resolved_path
        for dependency in report.dependencies
    ) == tuple(
        path.resolve()
        for path in resolved.values()
    )


def test_preflight_reports_all_missing_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        preflight.shutil,
        "which",
        lambda value: None,
    )

    with pytest.raises(
        PreflightError,
        match="Runtime preflight failed",
    ) as captured:
        preflight.run_preflight(
            create_ollama_config()
        )

    message = str(captured.value)

    assert "Syft executable was not found" in message
    assert "Grype executable was not found" in message
    assert "CodeQL executable was not found" in message
    assert "Docker executable was not found" in message


def test_preflight_requires_openai_api_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        preflight.shutil,
        "which",
        lambda value: str(tmp_path / value),
    )

    config = RuntimeConfig(
        llm=LlmConfig(
            provider=LlmProvider.OPENAI,
            model="test-model",
            openai_api_key=None,
        )
    )

    with pytest.raises(
        PreflightError,
        match="requires OPENAI_API_KEY",
    ):
        preflight.run_preflight(config)


def test_preflight_accepts_openai_api_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        preflight.shutil,
        "which",
        lambda value: str(tmp_path / value),
    )

    config = RuntimeConfig(
        llm=LlmConfig(
            provider=LlmProvider.OPENAI,
            model="test-model",
            openai_api_key="test-key",
        )
    )

    report = preflight.run_preflight(config)

    assert report.dependency_count == 4


def test_preflight_rejects_missing_corpus(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        preflight.shutil,
        "which",
        lambda value: str(tmp_path / value),
    )

    config = create_ollama_config(
        analysis=AnalysisConfig(
            corpus_path=tmp_path / "missing.json",
        )
    )

    with pytest.raises(
        PreflightError,
        match="evidence file does not exist",
    ):
        preflight.run_preflight(config)


def test_preflight_accepts_existing_corpus(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text(
        "[]",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        preflight.shutil,
        "which",
        lambda value: str(tmp_path / value),
    )

    config = create_ollama_config(
        analysis=AnalysisConfig(
            corpus_path=corpus_path,
        )
    )

    report = preflight.run_preflight(config)

    assert report.dependency_count == 4


def test_preflight_accepts_explicit_executable_paths(
    tmp_path: Path,
) -> None:
    executables: list[Path] = []

    for name in (
        "syft",
        "grype",
        "codeql",
        "docker",
    ):
        executable = tmp_path / name
        executable.write_text(
            "#!/bin/sh\nexit 0\n",
            encoding="utf-8",
        )
        executable.chmod(0o755)
        executables.append(executable)

    config = create_ollama_config(
        tools=ToolConfig(
            syft_executable=str(executables[0]),
            grype_executable=str(executables[1]),
            codeql_executable=str(executables[2]),
            docker_executable=str(executables[3]),
        )
    )

    report = preflight.run_preflight(config)

    assert tuple(
        dependency.resolved_path
        for dependency in report.dependencies
    ) == tuple(
        executable.resolve()
        for executable in executables
    )


def test_preflight_rejects_non_executable_file(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "not-executable"
    executable.write_text(
        "not executable",
        encoding="utf-8",
    )
    executable.chmod(0o644)

    config = create_ollama_config(
        tools=ToolConfig(
            syft_executable=str(executable),
            grype_executable=str(executable),
            codeql_executable=str(executable),
            docker_executable=str(executable),
        )
    )

    with pytest.raises(
        PreflightError,
        match="is not executable",
    ):
        preflight.run_preflight(config)