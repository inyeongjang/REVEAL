"""Tests for the OpenVEX document writer."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from reveal.exceptions import VexWriteError
from reveal.models import VexStatement, VexStatus
from reveal.vex import OpenVexWriter


def create_writer() -> OpenVexWriter:
    return OpenVexWriter(
        author="REVEAL Security Research",
        document_id="https://example.com/vex/reveal-analysis-001",
        role="VEX Document Creator",
        version=1,
        tooling="REVEAL",
    )


def test_write_creates_openvex_document(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "results" / "openvex.json"
    timestamp = datetime(
        2026,
        7,
        18,
        6,
        30,
        tzinfo=timezone.utc,
    )
    statement = VexStatement(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.AFFECTED,
        impact_statement=(
            "A proof of concept reproduced prototype pollution."
        ),
        action_statement="Update minimist to version 1.2.6 or later.",
    )

    result = create_writer().write(
        statements=(statement,),
        output_path=output_path,
        timestamp=timestamp,
    )

    assert result == output_path

    document = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert document == {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.com/vex/reveal-analysis-001",
        "author": "REVEAL Security Research",
        "timestamp": "2026-07-18T06:30:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "name": "GHSA-xvch-5gv4-984h",
                },
                "products": [
                    {
                        "@id": "pkg:npm/minimist@0.0.8",
                    }
                ],
                "status": "affected",
                "impact_statement": (
                    "A proof of concept reproduced prototype pollution."
                ),
                "action_statement": (
                    "Update minimist to version 1.2.6 or later."
                ),
            }
        ],
        "role": "VEX Document Creator",
        "tooling": "REVEAL",
    }


def test_write_serializes_not_affected_justification(
    tmp_path: Path,
) -> None:
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.NOT_AFFECTED,
        justification="vulnerable_code_not_in_execute_path",
        impact_statement=(
            "The vulnerable package API is not used by the application."
        ),
    )
    output_path = tmp_path / "openvex.json"

    create_writer().write(
        statements=(statement,),
        output_path=output_path,
        timestamp=datetime.now(timezone.utc),
    )

    document = json.loads(
        output_path.read_text(encoding="utf-8")
    )
    serialized_statement = document["statements"][0]

    assert serialized_statement["status"] == "not_affected"
    assert serialized_statement["justification"] == (
        "vulnerable_code_not_in_execute_path"
    )


def test_write_converts_timestamp_to_utc(
    tmp_path: Path,
) -> None:
    timestamp = datetime(
        2026,
        7,
        18,
        15,
        30,
        tzinfo=timezone(timedelta(hours=9)),
    )
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.UNDER_INVESTIGATION,
    )
    output_path = tmp_path / "openvex.json"

    create_writer().write(
        statements=(statement,),
        output_path=output_path,
        timestamp=timestamp,
    )

    document = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert document["timestamp"] == "2026-07-18T06:30:00Z"


def test_write_removes_exact_duplicate_statements(
    tmp_path: Path,
) -> None:
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.UNDER_INVESTIGATION,
    )
    output_path = tmp_path / "openvex.json"

    create_writer().write(
        statements=(statement, statement),
        output_path=output_path,
        timestamp=datetime.now(timezone.utc),
    )

    document = json.loads(
        output_path.read_text(encoding="utf-8")
    )

    assert len(document["statements"]) == 1


def test_write_rejects_empty_statement_sequence(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        VexWriteError,
        match="at least one statement",
    ):
        create_writer().write(
            statements=(),
            output_path=tmp_path / "openvex.json",
        )


def test_write_rejects_not_affected_without_explanation(
    tmp_path: Path,
) -> None:
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.NOT_AFFECTED,
    )

    with pytest.raises(
        VexWriteError,
        match="requires a justification or impact_statement",
    ):
        create_writer().write(
            statements=(statement,),
            output_path=tmp_path / "openvex.json",
        )


def test_write_rejects_affected_without_action(
    tmp_path: Path,
) -> None:
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.AFFECTED,
    )

    with pytest.raises(
        VexWriteError,
        match="requires an action_statement",
    ):
        create_writer().write(
            statements=(statement,),
            output_path=tmp_path / "openvex.json",
        )


def test_write_rejects_invalid_justification(
    tmp_path: Path,
) -> None:
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.NOT_AFFECTED,
        justification="not_reachable",
    )

    with pytest.raises(
        VexWriteError,
        match="Invalid OpenVEX justification",
    ):
        create_writer().write(
            statements=(statement,),
            output_path=tmp_path / "openvex.json",
        )


def test_write_rejects_product_without_iri_scheme(
    tmp_path: Path,
) -> None:
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("minimist@0.0.8",),
        status=VexStatus.UNDER_INVESTIGATION,
    )

    with pytest.raises(
        VexWriteError,
        match="absolute IRI",
    ):
        create_writer().write(
            statements=(statement,),
            output_path=tmp_path / "openvex.json",
        )


def test_write_rejects_naive_timestamp(
    tmp_path: Path,
) -> None:
    statement = VexStatement(
        vulnerability_id="CVE-2021-44906",
        products=("pkg:npm/minimist@0.0.8",),
        status=VexStatus.UNDER_INVESTIGATION,
    )

    with pytest.raises(
        VexWriteError,
        match="timezone information",
    ):
        create_writer().write(
            statements=(statement,),
            output_path=tmp_path / "openvex.json",
            timestamp=datetime(2026, 7, 18, 6, 30),
        )


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (
            {
                "author": "",
                "document_id": "https://example.com/vex/test",
            },
            "author",
        ),
        (
            {
                "author": "REVEAL",
                "document_id": "not-an-iri",
            },
            "document_id",
        ),
        (
            {
                "author": "REVEAL",
                "document_id": "https://example.com/vex/test",
                "version": 0,
            },
            "version",
        ),
    ],
)
def test_writer_rejects_invalid_configuration(
    arguments: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        OpenVexWriter(**arguments)  # type: ignore[arg-type]