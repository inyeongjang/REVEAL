"""Tests for the CodeQL package usage analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from reveal.exceptions import CodeQLAnalysisError
from reveal.reachability.codeql.client import CodeQLClient
from reveal.reachability.codeql.usage_analyzer import (
    CodeQLUsageAnalyzer,
)


class FakeCodeQLClient(CodeQLClient):
    """CodeQL client that creates deterministic test artifacts."""

    def __init__(self) -> None:
        super().__init__()
        self.created_database: Path | None = None
        self.executed_query: Path | None = None

    def create_database(
        self,
        source: Path,
        database_path: Path,
    ) -> None:
        self.created_database = database_path
        database_path.mkdir(parents=True, exist_ok=True)

    def run_query(
        self,
        database_path: Path,
        query_path: Path,
        output_path: Path,
    ) -> None:
        self.executed_query = query_path
        output_path.write_bytes(b"test-bqrs")

    def decode_bqrs(
        self,
        bqrs_path: Path,
        output_path: Path,
    ) -> None:
        output_path.write_text(
            "\n".join(
                [
                    "minimist,<module>,src/app.js,10,5",
                    "minimist,parse,src/app.js,12,3",
                    "minimist,parse,src/app.js,12,3",
                    "lodash,get,src/util.js,7,8",
                ]
            ),
            encoding="utf-8",
        )


def test_analyze_returns_normalized_api_usages(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    client = FakeCodeQLClient()
    analyzer = CodeQLUsageAnalyzer(client)

    results = analyzer.analyze(
        source=source,
        packages=("minimist", "lodash"),
        work_dir=work_dir,
    )

    assert len(results) == 3

    assert results[0].package == "lodash"
    assert results[0].api == "get"
    assert results[0].file == Path("src/util.js")
    assert results[0].line == 7
    assert results[0].column == 8

    assert results[1].package == "minimist"
    assert results[1].api == "<module>"

    assert results[2].package == "minimist"
    assert results[2].api == "parse"

    assert client.created_database == work_dir / "database"
    assert client.executed_query == work_dir / "usage-query" / "usage.ql"


def test_analyze_renders_requested_packages_into_query(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    analyzer = CodeQLUsageAnalyzer(FakeCodeQLClient())

    analyzer.analyze(
        source=source,
        packages=("minimist", "@scope/example"),
        work_dir=work_dir,
    )

    query = (
        work_dir
        / "usage-query"
        / "usage.ql"
    ).read_text(encoding="utf-8")

    assert 'API::moduleImport("minimist")' in query
    assert 'API::moduleImport("@scope/example")' in query
    assert "{{PACKAGE_CLAUSES}}" not in query

    qlpack_path = work_dir / "usage-query" / "qlpack.yml"

    assert qlpack_path.is_file()


def test_analyze_removes_duplicate_and_empty_packages(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    analyzer = CodeQLUsageAnalyzer(FakeCodeQLClient())

    analyzer.analyze(
        source=source,
        packages=("minimist", "", " minimist "),
        work_dir=work_dir,
    )

    query = (
        work_dir
        / "usage-query"
        / "usage.ql"
    ).read_text(encoding="utf-8")

    assert query.count('packageName = "minimist"') == 1


def test_analyze_skips_codeql_for_empty_package_list(
    tmp_path: Path,
) -> None:
    client = FakeCodeQLClient()
    analyzer = CodeQLUsageAnalyzer(client)

    results = analyzer.analyze(
        source=tmp_path / "missing",
        packages=(),
        work_dir=tmp_path / "analysis",
    )

    assert results == ()
    assert client.created_database is None
    assert client.executed_query is None


def test_analyze_rejects_missing_source(
    tmp_path: Path,
) -> None:
    analyzer = CodeQLUsageAnalyzer(FakeCodeQLClient())

    with pytest.raises(
        CodeQLAnalysisError,
        match="does not exist",
    ):
        analyzer.analyze(
            source=tmp_path / "missing",
            packages=("minimist",),
            work_dir=tmp_path / "analysis",
        )