"""CodeQL-based remote-input taint reachability analysis."""

from __future__ import annotations

import csv
import re
from collections.abc import Sequence
from importlib.resources import files
from pathlib import Path

from reveal.exceptions import CodeQLAnalysisError
from reveal.models import (
    ApiUsage,
    ReachabilityStatus,
    TaintPath,
    TaintResult,
    Vulnerability,
)
from reveal.reachability.codeql.client import CodeQLClient


class CodeQLTaintAnalyzer:
    """Analyze remote-input flows to selected API call arguments."""

    def __init__(self, client: CodeQLClient) -> None:
        self.client = client

    def analyze(
        self,
        source: Path,
        vulnerability: Vulnerability,
        targets: Sequence[ApiUsage],
        work_dir: Path,
    ) -> tuple[TaintResult, ...]:
        """Run CodeQL taint analysis for the selected API usages."""

        normalized_targets = _unique_targets(targets)

        if not normalized_targets:
            return ()

        if not source.is_dir():
            raise CodeQLAnalysisError(
                f"Source directory does not exist: {source}"
            )

        work_dir.mkdir(parents=True, exist_ok=True)

        database_path = work_dir / "database"
        analysis_key = (
            f"{vulnerability.id}-"
            f"{vulnerability.component.name}-"
            f"{vulnerability.component.version}"
        )
        analysis_dir = (
            work_dir
            / "taint"
            / _safe_path_segment(analysis_key)
        )
        query_dir = analysis_dir / "query"
        query_path = query_dir / "taint.ql"
        bqrs_path = analysis_dir / "taint.bqrs"
        csv_path = analysis_dir / "taint.csv"

        _prepare_query_pack(
            query_dir=query_dir,
            query_path=query_path,
            targets=normalized_targets,
        )

        self.client.install_pack_dependencies(query_dir)

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

        paths_by_api = _parse_taint_csv(csv_path)

        return tuple(
            _create_result(
                vulnerability=vulnerability,
                target_api=target_api,
                paths=paths_by_api.get(target_api, ()),
            )
            for target_api in _unique_target_apis(normalized_targets)
        )


def _prepare_query_pack(
    query_dir: Path,
    query_path: Path,
    targets: Sequence[ApiUsage],
) -> None:
    query_dir.mkdir(parents=True, exist_ok=True)

    resource_root = files("reveal").joinpath(
        "resources/codeql/javascript/taint"
    )

    try:
        qlpack = resource_root.joinpath("qlpack.yml").read_text(
            encoding="utf-8"
        )
        template = resource_root.joinpath("taint.ql.tmpl").read_text(
            encoding="utf-8"
        )
    except OSError as error:
        raise CodeQLAnalysisError(
            "Failed to load the CodeQL taint query resources."
        ) from error

    query = template.replace(
        "{{TARGET_CLAUSES}}",
        _render_target_clauses(targets),
    )

    try:
        (query_dir / "qlpack.yml").write_text(
            qlpack,
            encoding="utf-8",
        )
        query_path.write_text(
            query,
            encoding="utf-8",
        )
    except OSError as error:
        raise CodeQLAnalysisError(
            f"Failed to prepare the CodeQL taint query: {query_path}"
        ) from error


def _render_target_clauses(
    targets: Sequence[ApiUsage],
) -> str:
    clauses: list[str] = []

    for target in targets:
        column = target.column if target.column is not None else 0

        clauses.append(
            "\n".join(
                (
                    "(",
                    f"    targetApi = {_ql_string(target.api)} and",
                    f"    filePath = {_ql_string(target.file.as_posix())} and",
                    f"    line = {target.line} and",
                    f"    column = {column}",
                    "  )",
                )
            )
        )

    return " or\n  ".join(clauses)


def _ql_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )

    return f'"{escaped}"'


def _parse_taint_csv(
    csv_path: Path,
) -> dict[str, tuple[TaintPath, ...]]:
    if not csv_path.is_file():
        raise CodeQLAnalysisError(
            f"CodeQL taint result does not exist: {csv_path}"
        )

    paths_by_api: dict[str, list[TaintPath]] = {}
    seen: set[
        tuple[
            str,
            Path,
            int,
            str,
            Path,
            int,
            str,
            int | None,
        ]
    ] = set()

    try:
        with csv_path.open(
            mode="r",
            encoding="utf-8",
            newline="",
        ) as file:
            reader = csv.reader(file)

            for row_number, row in enumerate(reader, start=1):
                if len(row) != 8:
                    raise CodeQLAnalysisError(
                        "Invalid CodeQL taint CSV row "
                        f"{row_number}: expected 8 columns, got {len(row)}"
                    )

                target_api = row[0].strip()

                if not target_api:
                    raise CodeQLAnalysisError(
                        "Invalid CodeQL taint CSV row "
                        f"{row_number}: target API is empty"
                    )

                source_file = Path(row[1])
                source_line = _parse_positive_int(
                    row[2],
                    row_number=row_number,
                    field="source line",
                )
                source_label = row[3]
                sink_file = Path(row[4])
                sink_line = _parse_positive_int(
                    row[5],
                    row_number=row_number,
                    field="sink line",
                )
                sink_label = row[6]
                sink_argument = _parse_optional_nonnegative_int(
                    row[7],
                    row_number=row_number,
                    field="sink argument",
                )

                key = (
                    target_api,
                    source_file,
                    source_line,
                    source_label,
                    sink_file,
                    sink_line,
                    sink_label,
                    sink_argument,
                )

                if key in seen:
                    continue

                seen.add(key)
                paths_by_api.setdefault(target_api, []).append(
                    TaintPath(
                        source_file=source_file,
                        source_line=source_line,
                        source=source_label,
                        sink_file=sink_file,
                        sink_line=sink_line,
                        sink=sink_label,
                        sink_argument=sink_argument,
                    )
                )
    except OSError as error:
        raise CodeQLAnalysisError(
            f"Failed to read CodeQL taint result: {csv_path}"
        ) from error

    return {
        target_api: tuple(
            sorted(
                paths,
                key=lambda path: (
                    path.source_file.as_posix(),
                    path.source_line,
                    path.sink_file.as_posix(),
                    path.sink_line,
                    path.sink_argument
                    if path.sink_argument is not None
                    else -1,
                ),
            )
        )
        for target_api, paths in paths_by_api.items()
    }


def _parse_positive_int(
    value: str,
    *,
    row_number: int,
    field: str,
) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise CodeQLAnalysisError(
            f"Invalid CodeQL taint CSV row {row_number}: "
            f"{field} must be an integer"
        ) from error

    if parsed < 1:
        raise CodeQLAnalysisError(
            f"Invalid CodeQL taint CSV row {row_number}: "
            f"{field} must be positive"
        )

    return parsed


def _parse_optional_nonnegative_int(
    value: str,
    *,
    row_number: int,
    field: str,
) -> int | None:
    if not value.strip():
        return None

    try:
        parsed = int(value)
    except ValueError as error:
        raise CodeQLAnalysisError(
            f"Invalid CodeQL taint CSV row {row_number}: "
            f"{field} must be an integer"
        ) from error

    if parsed < 0:
        raise CodeQLAnalysisError(
            f"Invalid CodeQL taint CSV row {row_number}: "
            f"{field} must not be negative"
        )

    return parsed


def _create_result(
    vulnerability: Vulnerability,
    target_api: str,
    paths: tuple[TaintPath, ...],
) -> TaintResult:
    if paths:
        return TaintResult(
            vulnerability_id=vulnerability.id,
            target_api=target_api,
            status=ReachabilityStatus.REACHABLE,
            paths=paths,
            reason=(
                "CodeQL found at least one remote-input taint flow "
                "to the selected API."
            ),
        )

    return TaintResult(
        vulnerability_id=vulnerability.id,
        target_api=target_api,
        status=ReachabilityStatus.UNREACHABLE,
        reason=(
            "CodeQL found no remote-input taint flow "
            "to the selected API."
        ),
    )


def _unique_targets(
    targets: Sequence[ApiUsage],
) -> tuple[ApiUsage, ...]:
    unique: list[ApiUsage] = []
    seen: set[tuple[str, str, str, int, int | None]] = set()

    for target in targets:
        key = (
            target.package,
            target.api,
            target.file.as_posix(),
            target.line,
            target.column,
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(target)

    return tuple(unique)


def _unique_target_apis(
    targets: Sequence[ApiUsage],
) -> tuple[str, ...]:
    unique: list[str] = []

    for target in targets:
        if target.api not in unique:
            unique.append(target.api)

    return tuple(unique)

def _safe_path_segment(value: str) -> str:
    normalized = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        value,
    ).strip("-._")

    return (normalized or "vulnerability")[:120]