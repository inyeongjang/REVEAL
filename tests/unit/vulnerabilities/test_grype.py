"""Tests for the Grype vulnerability scanner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from reveal.exceptions import VulnerabilityScanError
from reveal.models import Component, Sbom
from reveal.vulnerabilities.grype import GrypeVulnerabilityScanner


def create_sbom(tmp_path: Path) -> Sbom:
    document_path = tmp_path / "sbom.json"
    document_path.write_text("{}", encoding="utf-8")

    component = Component(
        name="minimist",
        version="0.0.8",
        ecosystem="npm",
        purl="pkg:npm/minimist@0.0.8",
    )

    return Sbom(
        format="cyclonedx-json",
        generator="syft",
        document_path=document_path,
        components=(component,),
    )


def test_scan_runs_grype_and_normalizes_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sbom = create_sbom(tmp_path)
    output_path = tmp_path / "output" / "grype.json"
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
                    "matches": [
                        {
                            "vulnerability": {
                                "id": "GHSA-xvch-5gv4-984h",
                                "dataSource": (
                                    "https://github.com/advisories/"
                                    "GHSA-xvch-5gv4-984h"
                                ),
                                "severity": "High",
                                "description": (
                                    "Prototype pollution in minimist"
                                ),
                                "urls": [
                                    "https://nvd.nist.gov/vuln/"
                                    "detail/CVE-2021-44906"
                                ],
                                "fix": {
                                    "versions": ["1.2.6"],
                                    "state": "fixed",
                                },
                            },
                            "relatedVulnerabilities": [
                                {
                                    "id": "CVE-2021-44906",
                                }
                            ],
                            "artifact": {
                                "name": "minimist",
                                "version": "0.0.8",
                                "type": "npm",
                                "purl": "pkg:npm/minimist@0.0.8",
                            },
                        }
                    ]
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
        "reveal.vulnerabilities.grype.subprocess.run",
        fake_run,
    )

    scanner = GrypeVulnerabilityScanner()
    result = scanner.scan(sbom, output_path)

    assert captured_command == [
        "grype",
        f"sbom:{sbom.document_path}",
        "--quiet",
        "--output",
        "json",
        "--file",
        str(output_path),
    ]

    assert result.sbom == sbom
    assert result.finding_count == 1

    vulnerability = result.vulnerabilities[0]

    assert vulnerability.id == "GHSA-xvch-5gv4-984h"
    assert vulnerability.aliases == ("CVE-2021-44906",)
    assert vulnerability.component == sbom.components[0]
    assert vulnerability.severity == "High"
    assert vulnerability.fixed_versions == ("1.2.6",)
    assert len(vulnerability.urls) == 2


def test_scan_rejects_missing_sbom_document(tmp_path: Path) -> None:
    sbom = Sbom(
        format="cyclonedx-json",
        generator="syft",
        document_path=tmp_path / "missing.json",
        components=(),
    )

    scanner = GrypeVulnerabilityScanner()

    with pytest.raises(
        VulnerabilityScanError,
        match="does not exist",
    ):
        scanner.scan(sbom, tmp_path / "grype.json")


def test_scan_reports_missing_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sbom = create_sbom(tmp_path)

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(
        "reveal.vulnerabilities.grype.subprocess.run",
        fake_run,
    )

    scanner = GrypeVulnerabilityScanner(
        executable="missing-grype"
    )

    with pytest.raises(
        VulnerabilityScanError,
        match="not found",
    ):
        scanner.scan(sbom, tmp_path / "grype.json")


def test_scan_reports_grype_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sbom = create_sbom(tmp_path)

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="database update failed",
        )

    monkeypatch.setattr(
        "reveal.vulnerabilities.grype.subprocess.run",
        fake_run,
    )

    scanner = GrypeVulnerabilityScanner()

    with pytest.raises(
        VulnerabilityScanError,
        match="database update failed",
    ):
        scanner.scan(sbom, tmp_path / "grype.json")


def test_scan_rejects_invalid_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sbom = create_sbom(tmp_path)
    output_path = tmp_path / "grype.json"

    def fake_run(
        command: list[str],
        **_: object,
    ) -> subprocess.CompletedProcess[str]:
        output_path.write_text(
            "not valid JSON",
            encoding="utf-8",
        )

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "reveal.vulnerabilities.grype.subprocess.run",
        fake_run,
    )

    scanner = GrypeVulnerabilityScanner()

    with pytest.raises(
        VulnerabilityScanError,
        match="invalid JSON",
    ):
        scanner.scan(sbom, output_path)