"""Tests for the REVEAL command-line interface."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

import reveal.cli as cli
from reveal.bootstrap import RuntimeContext
from reveal.config import RuntimeConfig
from reveal.exceptions import (
    BootstrapError,
    ConfigurationError,
    PreflightError,
)
from reveal.preflight import PreflightReport


@dataclass(frozen=True, slots=True)
class FakePipelineResult:
    """Minimal pipeline result for CLI tests."""

    vulnerability_count: int
    vex_path: Path | None
    artifact_path: Path | None


class FakePipeline:
    """Record CLI pipeline execution."""

    def __init__(
        self,
        result: FakePipelineResult,
    ) -> None:
        self.result = result
        self.calls: list[
            tuple[
                Path,
                Path,
                Path,
                Path | None,
            ]
        ] = []

    def run(
        self,
        *,
        source: Path,
        work_dir: Path,
        vex_output_path: Path,
        analysis_output_path: Path | None = None,
    ) -> FakePipelineResult:
        self.calls.append(
            (
                source,
                work_dir,
                vex_output_path,
                analysis_output_path,
            )
        )

        return self.result


@dataclass(frozen=True, slots=True)
class FakeRuntimeContext:
    """Minimal runtime context for CLI tests."""

    pipeline: FakePipeline


def install_fake_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pipeline: FakePipeline,
    document_ids: list[str] | None = None,
) -> None:
    monkeypatch.setattr(
        cli,
        "_load_runtime_config",
        lambda: RuntimeConfig(),
    )
    monkeypatch.setattr(
        cli,
        "_run_preflight",
        lambda config: PreflightReport(
            dependencies=()
        ),
    )

    def create_runtime(
        *,
        config: RuntimeConfig,
        document_id: str,
    ) -> RuntimeContext:
        assert isinstance(config, RuntimeConfig)

        if document_ids is not None:
            document_ids.append(document_id)

        return cast(
            RuntimeContext,
            FakeRuntimeContext(pipeline),
        )

    monkeypatch.setattr(
        cli,
        "_create_runtime",
        create_runtime,
    )


def test_main_without_command_prints_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main([])

    captured = capsys.readouterr()

    assert exit_code == cli.ExitCode.SUCCESS
    assert "usage: reveal" in captured.out
    assert "analyze" in captured.out


def test_help_option_prints_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["--help"])

    captured = capsys.readouterr()

    assert error.value.code == cli.ExitCode.SUCCESS
    assert "usage: reveal" in captured.out
    assert "analyze" in captured.out


def test_version_option_prints_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        cli.main(["--version"])

    captured = capsys.readouterr()

    assert error.value.code == cli.ExitCode.SUCCESS
    assert captured.out.startswith("reveal ")


def test_analyze_runs_pipeline_with_default_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    work_dir = tmp_path / "work"
    vex_path = work_dir / "openvex.json"
    artifact_path = work_dir / "analysis.json"

    pipeline = FakePipeline(
        FakePipelineResult(
            vulnerability_count=2,
            vex_path=vex_path,
            artifact_path=artifact_path,
        )
    )
    document_ids: list[str] = []

    install_fake_runtime(
        monkeypatch,
        pipeline=pipeline,
        document_ids=document_ids,
    )

    exit_code = cli.main(
        [
            "analyze",
            str(source),
            "--work-dir",
            str(work_dir),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == cli.ExitCode.SUCCESS
    assert pipeline.calls == [
        (
            source.resolve(),
            work_dir.resolve(),
            vex_path.resolve(),
            artifact_path.resolve(),
        )
    ]
    assert len(document_ids) == 1
    assert document_ids[0].startswith("urn:uuid:")

    assert "[1/3] Loading configuration..." in captured.out
    assert "[2/3] Checking runtime dependencies..." in (
        captured.out
    )
    assert "[3/3] Running analysis pipeline..." in (
        captured.out
    )
    assert "REVEAL analysis completed." in captured.out
    assert "Vulnerabilities analyzed: 2" in captured.out
    assert f"OpenVEX: {vex_path}" in captured.out
    assert f"Analysis evidence: {artifact_path}" in (
        captured.out
    )


def test_analyze_accepts_explicit_outputs_and_document_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    work_dir = tmp_path / "work"
    vex_path = tmp_path / "results" / "vex.json"
    artifact_path = (
        tmp_path
        / "results"
        / "analysis.json"
    )
    document_ids: list[str] = []

    pipeline = FakePipeline(
        FakePipelineResult(
            vulnerability_count=1,
            vex_path=vex_path.resolve(),
            artifact_path=artifact_path.resolve(),
        )
    )

    install_fake_runtime(
        monkeypatch,
        pipeline=pipeline,
        document_ids=document_ids,
    )

    exit_code = cli.main(
        [
            "analyze",
            str(source),
            "--work-dir",
            str(work_dir),
            "--vex-output",
            str(vex_path),
            "--analysis-output",
            str(artifact_path),
            "--document-id",
            "urn:uuid:explicit-document",
        ]
    )

    assert exit_code == cli.ExitCode.SUCCESS
    assert document_ids == [
        "urn:uuid:explicit-document",
    ]
    assert pipeline.calls == [
        (
            source.resolve(),
            work_dir.resolve(),
            vex_path.resolve(),
            artifact_path.resolve(),
        )
    ]


def test_analyze_reports_no_vex_for_empty_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    artifact_path = (
        tmp_path
        / "work"
        / "analysis.json"
    )
    pipeline = FakePipeline(
        FakePipelineResult(
            vulnerability_count=0,
            vex_path=None,
            artifact_path=artifact_path,
        )
    )

    install_fake_runtime(
        monkeypatch,
        pipeline=pipeline,
    )

    exit_code = cli.main(
        [
            "analyze",
            str(source),
            "--work-dir",
            str(tmp_path / "work"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == cli.ExitCode.SUCCESS
    assert "Vulnerabilities analyzed: 0" in captured.out
    assert "OpenVEX: not generated" in captured.out


def test_analyze_returns_analysis_error_for_missing_source(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(
        [
            "analyze",
            str(tmp_path / "missing"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == cli.ExitCode.ANALYSIS_ERROR
    assert "analysis error" in captured.err
    assert "Source directory does not exist" in (
        captured.err
    )


def test_configuration_error_has_distinct_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    def raise_configuration_error() -> RuntimeConfig:
        raise ConfigurationError(
            "Invalid LLM provider."
        )

    monkeypatch.setattr(
        cli,
        "_load_runtime_config",
        raise_configuration_error,
    )

    exit_code = cli.main(
        [
            "analyze",
            str(source),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == cli.ExitCode.CONFIGURATION_ERROR
    assert "configuration error" in captured.err
    assert "Invalid LLM provider" in captured.err


def test_preflight_error_has_distinct_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    monkeypatch.setattr(
        cli,
        "_load_runtime_config",
        lambda: RuntimeConfig(),
    )

    def raise_preflight_error(
        config: RuntimeConfig,
    ) -> PreflightReport:
        del config

        raise PreflightError(
            "Docker executable was not found."
        )

    monkeypatch.setattr(
        cli,
        "_run_preflight",
        raise_preflight_error,
    )

    exit_code = cli.main(
        [
            "analyze",
            str(source),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == cli.ExitCode.DEPENDENCY_ERROR
    assert "dependency error" in captured.err
    assert "Docker executable was not found" in (
        captured.err
    )


def test_bootstrap_error_has_analysis_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    monkeypatch.setattr(
        cli,
        "_load_runtime_config",
        lambda: RuntimeConfig(),
    )
    monkeypatch.setattr(
        cli,
        "_run_preflight",
        lambda config: PreflightReport(
            dependencies=()
        ),
    )

    def raise_bootstrap_error(
        *,
        config: RuntimeConfig,
        document_id: str,
    ) -> RuntimeContext:
        del config, document_id

        raise BootstrapError(
            "Runtime assembly failed."
        )

    monkeypatch.setattr(
        cli,
        "_create_runtime",
        raise_bootstrap_error,
    )

    exit_code = cli.main(
        [
            "analyze",
            str(source),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == cli.ExitCode.ANALYSIS_ERROR
    assert "bootstrap error" in captured.err
    assert "Runtime assembly failed" in captured.err