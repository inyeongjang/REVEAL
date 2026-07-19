"""Tests for the low-level CodeQL client."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from reveal.exceptions import CodeQLAnalysisError
from reveal.reachability.codeql.client import CodeQLClient


def test_create_database_builds_expected_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "project"
    database = tmp_path / "work" / "database"
    source.mkdir()

    captured_command: list[str] = []

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        captured_command.extend(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "reveal.reachability.codeql.client.subprocess.run",
        fake_run,
    )

    client = CodeQLClient()
    client.create_database(source, database)

    assert captured_command == [
        "codeql",
        "database",
        "create",
        str(database),
        "--language=javascript-typescript",
        f"--source-root={source}",
        "--build-mode=none",
        "--overwrite",
    ]

def test_install_pack_dependencies_builds_expected_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack_dir = tmp_path / "query"
    pack_dir.mkdir()
    (pack_dir / "qlpack.yml").write_text(
        "\n".join(
            [
                "name: reveal/test-pack",
                "version: 0.0.1",
                "dependencies:",
                '  codeql/javascript-all: "*"',
            ]
        ),
        encoding="utf-8",
    )

    captured_command: list[str] = []

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        captured_command.extend(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "reveal.reachability.codeql.client.subprocess.run",
        fake_run,
    )

    client = CodeQLClient()
    client.install_pack_dependencies(pack_dir)

    assert captured_command == [
        "codeql",
        "pack",
        "install",
        "--",
        str(pack_dir),
    ]

def test_install_pack_dependencies_rejects_missing_manifest(
    tmp_path: Path,
) -> None:
    pack_dir = tmp_path / "query"
    pack_dir.mkdir()

    client = CodeQLClient()

    with pytest.raises(
        CodeQLAnalysisError,
        match="manifest does not exist",
    ):
        client.install_pack_dependencies(pack_dir)

def test_install_pack_dependencies_rejects_missing_directory(
    tmp_path: Path,
) -> None:
    client = CodeQLClient()

    with pytest.raises(
        CodeQLAnalysisError,
        match="pack directory does not exist",
    ):
        client.install_pack_dependencies(
            tmp_path / "missing-query-pack"
        )
        
def test_client_reports_missing_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(
        "reveal.reachability.codeql.client.subprocess.run",
        fake_run,
    )

    client = CodeQLClient(executable="missing-codeql")

    with pytest.raises(
        CodeQLAnalysisError,
        match="not found",
    ):
        client.create_database(
            source,
            tmp_path / "database",
        )


def test_client_reports_command_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="database creation failed",
        )

    monkeypatch.setattr(
        "reveal.reachability.codeql.client.subprocess.run",
        fake_run,
    )

    client = CodeQLClient()

    with pytest.raises(
        CodeQLAnalysisError,
        match="database creation failed",
    ):
        client.create_database(
            source,
            tmp_path / "database",
        )


def test_client_rejects_invalid_timeout() -> None:
    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        CodeQLClient(timeout_seconds=0)