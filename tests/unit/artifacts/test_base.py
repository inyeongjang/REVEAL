"""Tests for the analysis artifact writer abstraction."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from reveal.artifacts import (
    AnalysisArtifactWriter,
    VulnerabilityAnalysisView,
)
from reveal.models import ApiUsage, Sbom, ScanResult


class FakeAnalysisArtifactWriter:
    """Minimal artifact writer satisfying the shared protocol."""

    def write(
        self,
        *,
        scan: ScanResult,
        usages: Sequence[ApiUsage],
        analyses: Sequence[VulnerabilityAnalysisView],
        output_path: Path,
        vex_path: Path | None = None,
        timestamp: datetime | None = None,
    ) -> Path:
        del timestamp

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        output_path.write_text(
            json.dumps(
                {
                    "vulnerability_count": len(
                        scan.vulnerabilities
                    ),
                    "usage_count": len(usages),
                    "analysis_count": len(analyses),
                    "vex_path": (
                        str(vex_path)
                        if vex_path is not None
                        else None
                    ),
                }
            ),
            encoding="utf-8",
        )

        return output_path


def run_writer(
    writer: AnalysisArtifactWriter,
    scan: ScanResult,
    output_path: Path,
) -> Path:
    """Execute any implementation satisfying the writer protocol."""

    return writer.write(
        scan=scan,
        usages=(),
        analyses=(),
        output_path=output_path,
    )


def test_writer_accepts_structural_implementation(
    tmp_path: Path,
) -> None:
    sbom_path = tmp_path / "sbom.json"
    scan = ScanResult(
        sbom=Sbom(
            format="cyclonedx-json",
            generator="fake",
            document_path=sbom_path,
            components=(),
        ),
        vulnerabilities=(),
    )
    output_path = tmp_path / "analysis.json"

    result = run_writer(
        writer=FakeAnalysisArtifactWriter(),
        scan=scan,
        output_path=output_path,
    )

    assert result == output_path
    assert json.loads(
        output_path.read_text(encoding="utf-8")
    ) == {
        "vulnerability_count": 0,
        "usage_count": 0,
        "analysis_count": 0,
        "vex_path": None,
    }
