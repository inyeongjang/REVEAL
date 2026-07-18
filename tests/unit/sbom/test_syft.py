"""Tests for the Syft SBOM generator."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from reveal.exceptions import SbomGenerationError
from reveal.sbom.syft import SyftSbomGenerator


def test_generate_runs_syft_and_normalizes_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "project"
    output_path = tmp_path / "output" / "sbom.json"
    source.mkdir()

    captured_command: list[str] = []

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        captured_command.extend(command)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [
                        {
                            "type": "library",
                            "name": "minimist",
                            "version": "0.0.8",
                            "purl": "pkg:npm/minimist@0.0.8",
                        },
                        {
                            "type": "library",
                            "name": "lodash",
                            "version": "4.17.20",
                            "purl": "pkg:npm/lodash@4.17.20",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "reveal.sbom.syft.subprocess.run",
        fake_run,
    )

    generator = SyftSbomGenerator()
    result = generator.generate(source, output_path)

    assert captured_command == [
        "syft",
        "scan",
        str(source),
        "--quiet",
        "--output",
        f"cyclonedx-json={output_path}",
    ]
    assert result.generator == "syft"
    assert result.format == "cyclonedx-json"
    assert result.document_path == output_path
    assert len(result.components) == 2

    minimist = result.components[0]

    assert minimist.name == "minimist"
    assert minimist.version == "0.0.8"
    assert minimist.ecosystem == "npm"
    assert minimist.purl == "pkg:npm/minimist@0.0.8"


def test_generate_rejects_missing_source(tmp_path: Path) -> None:
    generator = SyftSbomGenerator()

    with pytest.raises(SbomGenerationError, match="does not exist"):
        generator.generate(
            tmp_path / "missing",
            tmp_path / "sbom.json",
        )


def test_generate_reports_missing_executable(
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
        "reveal.sbom.syft.subprocess.run",
        fake_run,
    )

    generator = SyftSbomGenerator(executable="missing-syft")

    with pytest.raises(SbomGenerationError, match="not found"):
        generator.generate(
            source,
            tmp_path / "sbom.json",
        )


def test_generate_reports_syft_failure(
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
            stderr="cataloging failed",
        )

    monkeypatch.setattr(
        "reveal.sbom.syft.subprocess.run",
        fake_run,
    )

    generator = SyftSbomGenerator()

    with pytest.raises(SbomGenerationError, match="cataloging failed"):
        generator.generate(
            source,
            tmp_path / "sbom.json",
        )


def test_generate_rejects_invalid_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "project"
    output_path = tmp_path / "sbom.json"
    source.mkdir()

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        output_path.write_text("not valid JSON", encoding="utf-8")

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "reveal.sbom.syft.subprocess.run",
        fake_run,
    )

    generator = SyftSbomGenerator()

    with pytest.raises(SbomGenerationError, match="invalid JSON"):
        generator.generate(source, output_path)


def test_parser_skips_components_without_names(tmp_path: Path) -> None:
    document_path = tmp_path / "sbom.json"
    document_path.write_text(
        json.dumps(
            {
                "components": [
                    {
                        "version": "1.0.0",
                        "purl": "pkg:npm/unknown@1.0.0",
                    },
                    {
                        "name": "valid-package",
                        "version": "2.0.0",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    result = SyftSbomGenerator._parse(document_path)

    assert len(result.components) == 1
    assert result.components[0].name == "valid-package"
    assert result.components[0].ecosystem == "unknown"