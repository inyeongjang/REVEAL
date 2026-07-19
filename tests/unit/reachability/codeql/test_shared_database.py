"""Tests for shared CodeQL database reuse."""

from __future__ import annotations

from pathlib import Path

from reveal.models import ApiUsage, Component, Vulnerability
from reveal.reachability.codeql import (
    CodeQLTaintAnalyzer,
    CodeQLUsageAnalyzer,
)


class FakeCodeQLClient:
    """CodeQL client recording database and query operations."""

    def __init__(self) -> None:
        self.install_calls: list[Path] = []
        self.create_calls: list[tuple[Path, Path]] = []
        self.query_calls: list[
            tuple[Path, Path, Path]
        ] = []
        self.decode_calls: list[
            tuple[Path, Path]
        ] = []

    def install_pack_dependencies(
        self,
        pack_dir: Path,
    ) -> None:
        self.install_calls.append(pack_dir)

    def create_database(
        self,
        source: Path,
        database_path: Path,
    ) -> None:
        self.create_calls.append((source, database_path))
        database_path.mkdir(parents=True, exist_ok=True)

    def run_query(
        self,
        database_path: Path,
        query_path: Path,
        output_path: Path,
    ) -> None:
        self.query_calls.append(
            (
                database_path,
                query_path,
                output_path,
            )
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"fake bqrs")

    def decode_bqrs(
        self,
        bqrs_path: Path,
        output_path: Path,
    ) -> None:
        self.decode_calls.append((bqrs_path, output_path))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("", encoding="utf-8")


def create_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=Component(
            name="minimist",
            version="0.0.8",
            ecosystem="npm",
            purl="pkg:npm/minimist@0.0.8",
        ),
        aliases=("CVE-2021-44906",),
        description="Prototype pollution in minimist.",
    )


def test_usage_and_taint_analyzers_share_database(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "reachability"
    source.mkdir()

    client = FakeCodeQLClient()
    usage_analyzer = CodeQLUsageAnalyzer(client)
    taint_analyzer = CodeQLTaintAnalyzer(client)

    usage_analyzer.analyze(
        source=source,
        packages=("minimist",),
        work_dir=work_dir,
    )

    taint_analyzer.analyze(
        source=source,
        vulnerability=create_vulnerability(),
        targets=(
            ApiUsage(
                package="minimist",
                api="<module>",
                file=Path("src/app.js"),
                line=10,
                column=5,
            ),
        ),
        work_dir=work_dir,
    )

    assert client.install_calls == [
        work_dir / "usage" / "query",
        (
            work_dir
            / "taint"
            / "GHSA-xvch-5gv4-984h-minimist-0.0.8"
            / "query"
        ),
    ]

    assert client.create_calls == [
        (
            source,
            work_dir / "database",
        )
    ]

    assert len(client.query_calls) == 2
    assert all(
        database_path == work_dir / "database"
        for database_path, _, _ in client.query_calls
    )

    assert client.query_calls[0][1] == (
        work_dir / "usage" / "query" / "usage.ql"
    )
    assert client.query_calls[1][1] == (
        work_dir
        / "taint"
        / "GHSA-xvch-5gv4-984h-minimist-0.0.8"
        / "query"
        / "taint.ql"
    )