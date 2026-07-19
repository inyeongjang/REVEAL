"""CodeQL-based package usage analyzer."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from importlib.resources import files
from pathlib import Path

from reveal.exceptions import CodeQLAnalysisError
from reveal.models import ApiUsage
from reveal.reachability.codeql.client import CodeQLClient


class CodeQLUsageAnalyzer:
    """Find calls to selected JavaScript dependency APIs using CodeQL."""

    def __init__(self, client: CodeQLClient | None = None) -> None:
        self.client = client or CodeQLClient()

    def analyze(
        self,
        source: Path,
        packages: Sequence[str],
        work_dir: Path,
    ) -> tuple[ApiUsage, ...]:
        """Find direct and member calls involving selected packages."""

        normalized_packages = _normalize_packages(packages)

        if not normalized_packages:
            return ()

        if not source.exists():
            raise CodeQLAnalysisError(
                f"Analysis source does not exist: {source}"
            )

        if not source.is_dir():
            raise CodeQLAnalysisError(
                f"Analysis source is not a directory: {source}"
            )

        work_dir.mkdir(parents=True, exist_ok=True)

        database_path = work_dir / "database"
        analysis_dir = work_dir / "usage"
        query_dir = analysis_dir / "query"
        query_path = query_dir / "usage.ql"
        bqrs_path = analysis_dir / "usage.bqrs"
        csv_path = analysis_dir / "usage.csv"

        _prepare_query_pack(
            query_dir=query_dir,
            query_path=query_path,
            packages=normalized_packages,
        )

        if not database_path.is_dir():
            self.client.create_database(
                source=source,
                database_path=database_path,
            )

        self.client.run_query(
            database_path=database_path,
            query_path=query_path,
            output_path=bqrs_path,
        )
        self.client.decode_bqrs(
            bqrs_path=bqrs_path,
            output_path=csv_path,
        )

        return _parse_usage_csv(csv_path)


def _prepare_query_pack(
    query_dir: Path,
    query_path: Path,
    packages: tuple[str, ...],
) -> None:
    query_dir.mkdir(parents=True, exist_ok=True)

    resource_root = files("reveal").joinpath(
        "resources/codeql/javascript/usage"
    )

    qlpack_content = resource_root.joinpath(
        "qlpack.yml"
    ).read_text(encoding="utf-8")

    template = resource_root.joinpath(
        "usage.ql.tmpl"
    ).read_text(encoding="utf-8")

    clauses = "\n  or\n".join(
        _build_package_clause(package)
        for package in packages
    )

    query = template.replace(
        "{{PACKAGE_CLAUSES}}",
        clauses,
    )

    (query_dir / "qlpack.yml").write_text(
        qlpack_content,
        encoding="utf-8",
    )
    query_path.write_text(query, encoding="utf-8")


def _build_package_clause(package: str) -> str:
    escaped = _escape_ql_string(package)

    return f"""(
    packageName = "{escaped}" and
    (
      (
        call = API::moduleImport("{escaped}").getACall() and
        apiName = "<module>"
      )
      or
      exists(string member |
        call = API::moduleImport("{escaped}").getMember(member).getACall() and
        apiName = member
      )
    )
  )"""


def _escape_ql_string(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def _normalize_packages(
    packages: Sequence[str],
) -> tuple[str, ...]:
    normalized: list[str] = []

    for package in packages:
        value = package.strip()

        if value and value not in normalized:
            normalized.append(value)

    return tuple(normalized)


def _parse_usage_csv(path: Path) -> tuple[ApiUsage, ...]:
    usages: list[ApiUsage] = []

    try:
        with path.open(
            mode="r",
            encoding="utf-8",
            newline="",
        ) as stream:
            reader = csv.reader(stream)

            for row_number, row in enumerate(reader, start=1):
                usages.append(
                    _parse_usage_row(
                        row=row,
                        row_number=row_number,
                    )
                )
    except OSError as error:
        raise CodeQLAnalysisError(
            f"Failed to read CodeQL usage result: {path}"
        ) from error

    unique: dict[
        tuple[str, str, Path, int, int | None],
        ApiUsage,
    ] = {}

    for usage in usages:
        key = (
            usage.package,
            usage.api,
            usage.file,
            usage.line,
            usage.column,
        )
        unique[key] = usage

    return tuple(
        sorted(
            unique.values(),
            key=lambda usage: (
                usage.package,
                str(usage.file),
                usage.line,
                usage.column or 0,
                usage.api,
            ),
        )
    )


def _parse_usage_row(
    row: list[str],
    row_number: int,
) -> ApiUsage:
    if len(row) != 5:
        raise CodeQLAnalysisError(
            f"Invalid CodeQL usage row {row_number}: "
            f"expected 5 columns, found {len(row)}"
        )

    package, api, file_name, raw_line, raw_column = row

    try:
        line = int(raw_line)
        column = int(raw_column) if raw_column else None
    except ValueError as error:
        raise CodeQLAnalysisError(
            f"Invalid source location in CodeQL usage row {row_number}"
        ) from error

    return ApiUsage(
        package=package,
        api=api,
        file=Path(file_name),
        line=line,
        column=column,
    )