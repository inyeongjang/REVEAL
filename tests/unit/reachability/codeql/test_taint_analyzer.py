"""Tests for the CodeQL taint reachability analyzer."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from reveal.exceptions import CodeQLAnalysisError
from reveal.models import (
    ApiUsage,
    Component,
    ReachabilityStatus,
    Vulnerability,
)
from reveal.reachability.codeql.taint_analyzer import (
    CodeQLTaintAnalyzer,
)


class FakeCodeQLClient:
    """Deterministic CodeQL client for taint analyzer tests."""

    def __init__(
        self,
        rows: tuple[tuple[str, ...], ...] = (),
    ) -> None:
        self.rows = rows
        self.create_calls: list[tuple[Path, Path]] = []
        self.query_calls: list[tuple[Path, Path, Path]] = []
        self.decode_calls: list[tuple[Path, Path]] = []

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
        output_path.write_bytes(b"fake bqrs")

    def decode_bqrs(
        self,
        bqrs_path: Path,
        output_path: Path,
    ) -> None:
        self.decode_calls.append((bqrs_path, output_path))

        with output_path.open(
            mode="w",
            encoding="utf-8",
            newline="",
        ) as file:
            writer = csv.writer(file)
            writer.writerows(self.rows)


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


def create_targets() -> tuple[ApiUsage, ...]:
    return (
        ApiUsage(
            package="minimist",
            api="<module>",
            file=Path("src/routes/arguments.js"),
            line=13,
            column=12,
        ),
        ApiUsage(
            package="minimist",
            api="parse",
            file=Path("src/services/parser.js"),
            line=21,
            column=8,
        ),
    )


def test_analyze_returns_reachable_and_unreachable_results(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    client = FakeCodeQLClient(
        rows=(
            (
                "<module>",
                "src/routes/arguments.js",
                "7",
                "request.query",
                "src/routes/arguments.js",
                "13",
                "minimist(request.query)",
                "0",
            ),
        )
    )
    analyzer = CodeQLTaintAnalyzer(client)

    results = analyzer.analyze(
        source=source,
        vulnerability=create_vulnerability(),
        targets=create_targets(),
        work_dir=work_dir,
    )

    assert len(results) == 2

    reachable = results[0]

    assert reachable.target_api == "<module>"
    assert reachable.status is ReachabilityStatus.REACHABLE
    assert reachable.path_count == 1
    assert reachable.paths[0].source_file == Path(
        "src/routes/arguments.js"
    )
    assert reachable.paths[0].source_line == 7
    assert reachable.paths[0].source == "request.query"
    assert reachable.paths[0].sink_line == 13
    assert reachable.paths[0].sink_argument == 0

    unreachable = results[1]

    assert unreachable.target_api == "parse"
    assert unreachable.status is ReachabilityStatus.UNREACHABLE
    assert unreachable.paths == ()

    assert client.create_calls == [
        (
            source,
            work_dir / "database",
        )
    ]
    assert len(client.query_calls) == 1
    assert len(client.decode_calls) == 1


def test_analyze_reuses_existing_database(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    database_path = work_dir / "database"

    source.mkdir()
    database_path.mkdir(parents=True)

    client = FakeCodeQLClient()
    analyzer = CodeQLTaintAnalyzer(client)

    analyzer.analyze(
        source=source,
        vulnerability=create_vulnerability(),
        targets=create_targets(),
        work_dir=work_dir,
    )

    assert client.create_calls == []
    assert client.query_calls[0][0] == database_path


def test_analyze_renders_target_locations_into_query(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    analyzer = CodeQLTaintAnalyzer(FakeCodeQLClient())

    analyzer.analyze(
        source=source,
        vulnerability=create_vulnerability(),
        targets=create_targets(),
        work_dir=work_dir,
    )

    query = (work_dir / "taint-query" / "taint.ql").read_text(
        encoding="utf-8"
    )

    assert 'targetApi = "<module>"' in query
    assert 'filePath = "src/routes/arguments.js"' in query
    assert "line = 13" in query
    assert "column = 12" in query

    assert 'targetApi = "parse"' in query
    assert 'filePath = "src/services/parser.js"' in query
    assert "line = 21" in query
    assert "column = 8" in query

    assert "{{TARGET_CLAUSES}}" not in query


def test_analyze_uses_zero_as_unknown_column(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    target = ApiUsage(
        package="minimist",
        api="<module>",
        file=Path("src/app.js"),
        line=10,
        column=None,
    )

    analyzer = CodeQLTaintAnalyzer(FakeCodeQLClient())

    analyzer.analyze(
        source=source,
        vulnerability=create_vulnerability(),
        targets=(target,),
        work_dir=work_dir,
    )

    query = (work_dir / "taint-query" / "taint.ql").read_text(
        encoding="utf-8"
    )

    assert "column = 0" in query


def test_analyze_removes_duplicate_targets(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    target = ApiUsage(
        package="minimist",
        api="<module>",
        file=Path("src/app.js"),
        line=10,
        column=4,
    )

    analyzer = CodeQLTaintAnalyzer(FakeCodeQLClient())

    results = analyzer.analyze(
        source=source,
        vulnerability=create_vulnerability(),
        targets=(target, target),
        work_dir=work_dir,
    )

    assert len(results) == 1
    assert results[0].target_api == "<module>"


def test_analyze_accepts_empty_targets_without_running_codeql(
    tmp_path: Path,
) -> None:
    client = FakeCodeQLClient()
    analyzer = CodeQLTaintAnalyzer(client)

    results = analyzer.analyze(
        source=tmp_path / "missing",
        vulnerability=create_vulnerability(),
        targets=(),
        work_dir=tmp_path / "analysis",
    )

    assert results == ()
    assert client.create_calls == []
    assert client.query_calls == []
    assert client.decode_calls == []


def test_analyze_rejects_missing_source_directory(
    tmp_path: Path,
) -> None:
    analyzer = CodeQLTaintAnalyzer(FakeCodeQLClient())

    with pytest.raises(
        CodeQLAnalysisError,
        match="Source directory does not exist",
    ):
        analyzer.analyze(
            source=tmp_path / "missing",
            vulnerability=create_vulnerability(),
            targets=create_targets(),
            work_dir=tmp_path / "analysis",
        )


def test_analyze_rejects_malformed_csv(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    client = FakeCodeQLClient(
        rows=(
            (
                "<module>",
                "src/app.js",
                "7",
            ),
        )
    )
    analyzer = CodeQLTaintAnalyzer(client)

    with pytest.raises(
        CodeQLAnalysisError,
        match="expected 8 columns",
    ):
        analyzer.analyze(
            source=source,
            vulnerability=create_vulnerability(),
            targets=create_targets(),
            work_dir=tmp_path / "analysis",
        )