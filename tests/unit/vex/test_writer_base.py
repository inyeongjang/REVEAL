"""Tests for the VEX writer abstraction."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from reveal.models import VexStatement, VexStatus
from reveal.vex import VexWriter


class FakeVexWriter:
    """Minimal writer used to verify the shared interface."""

    def write(
        self,
        statements: Sequence[VexStatement],
        output_path: Path,
        *,
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
                    "statement_count": len(statements),
                }
            ),
            encoding="utf-8",
        )

        return output_path


def run_writer(
    writer: VexWriter,
    statements: Sequence[VexStatement],
    output_path: Path,
) -> Path:
    """Execute any implementation satisfying the writer protocol."""

    return writer.write(
        statements=statements,
        output_path=output_path,
    )


def test_writer_accepts_structural_implementation(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "results" / "vex.json"
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.UNDER_INVESTIGATION,
    )

    result = run_writer(
        writer=FakeVexWriter(),
        statements=(statement,),
        output_path=output_path,
    )

    assert result == output_path
    assert json.loads(
        output_path.read_text(encoding="utf-8")
    ) == {
        "statement_count": 1,
    }