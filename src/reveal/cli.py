"""Command-line interface for REVEAL."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from importlib.metadata import (
    PackageNotFoundError,
    version,
)
from pathlib import Path
from uuid import uuid4

from reveal.bootstrap import (
    RuntimeContext,
    bootstrap_runtime,
)
from reveal.config import RuntimeConfig
from reveal.default_builders import (
    create_default_runtime_component_factory,
)
from reveal.exceptions import (
    BootstrapError,
    ConfigurationError,
    PipelineError,
    PreflightError,
    RevealError,
)
from reveal.preflight import (
    PreflightReport,
    run_preflight,
)


class ExitCode(IntEnum):
    """Stable REVEAL process exit codes."""

    SUCCESS = 0
    GENERAL_ERROR = 1
    USAGE_ERROR = 2
    CONFIGURATION_ERROR = 3
    DEPENDENCY_ERROR = 4
    ANALYSIS_ERROR = 5


@dataclass(frozen=True, slots=True)
class AnalyzeArguments:
    """Normalized arguments for one analysis execution."""

    source: Path
    work_dir: Path
    vex_output: Path
    analysis_output: Path
    document_id: str


def build_parser() -> argparse.ArgumentParser:
    """Create the REVEAL command-line parser."""

    parser = argparse.ArgumentParser(
        prog="reveal",
        description=(
            "Assess the exploitability of vulnerabilities "
            "reported in software dependencies."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_package_version()}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="COMMAND",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze one source project.",
        description=(
            "Generate an SBOM, scan dependency vulnerabilities, "
            "analyze reachability, attempt local reproduction, "
            "and produce OpenVEX output."
        ),
    )
    analyze_parser.add_argument(
        "source",
        type=Path,
        metavar="SOURCE",
        help="Source project directory to analyze.",
    )
    analyze_parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path(".reveal"),
        metavar="PATH",
        help=(
            "Directory for intermediate analysis artifacts "
            "(default: .reveal)."
        ),
    )
    analyze_parser.add_argument(
        "--vex-output",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "OpenVEX output path "
            "(default: WORK_DIR/openvex.json)."
        ),
    )
    analyze_parser.add_argument(
        "--analysis-output",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Normalized evidence output path "
            "(default: WORK_DIR/analysis.json)."
        ),
    )
    analyze_parser.add_argument(
        "--document-id",
        default=None,
        metavar="IRI",
        help=(
            "OpenVEX document IRI. A UUID URN is generated "
            "when omitted."
        ),
    )

    return parser


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """Run the REVEAL command-line interface."""

    parser = build_parser()
    namespace = parser.parse_args(
        list(argv) if argv is not None else None
    )

    if namespace.command is None:
        parser.print_help()

        return int(ExitCode.SUCCESS)

    try:
        if namespace.command == "analyze":
            arguments = _normalize_analyze_arguments(
                namespace
            )

            return _run_analyze(arguments)

        parser.error(
            f"Unsupported command: {namespace.command}"
        )
    except ConfigurationError as error:
        _print_error(
            category="configuration",
            error=error,
        )

        return int(ExitCode.CONFIGURATION_ERROR)
    except PreflightError as error:
        _print_error(
            category="dependency",
            error=error,
        )

        return int(ExitCode.DEPENDENCY_ERROR)
    except BootstrapError as error:
        _print_error(
            category="bootstrap",
            error=error,
        )

        return int(ExitCode.ANALYSIS_ERROR)
    except RevealError as error:
        _print_error(
            category="analysis",
            error=error,
        )

        return int(ExitCode.ANALYSIS_ERROR)

    return int(ExitCode.GENERAL_ERROR)


def _normalize_analyze_arguments(
    namespace: argparse.Namespace,
) -> AnalyzeArguments:
    source = _absolute_path(namespace.source)
    work_dir = _absolute_path(namespace.work_dir)

    if not source.is_dir():
        raise PipelineError(
            f"Source directory does not exist: {source}"
        )

    vex_output_value: Path | None = namespace.vex_output
    analysis_output_value: Path | None = (
        namespace.analysis_output
    )
    document_id_value: str | None = namespace.document_id

    vex_output = (
        _absolute_path(vex_output_value)
        if vex_output_value is not None
        else work_dir / "openvex.json"
    )
    analysis_output = (
        _absolute_path(analysis_output_value)
        if analysis_output_value is not None
        else work_dir / "analysis.json"
    )
    document_id = (
        document_id_value.strip()
        if (
            document_id_value is not None
            and document_id_value.strip()
        )
        else _generate_document_id()
    )

    return AnalyzeArguments(
        source=source,
        work_dir=work_dir,
        vex_output=vex_output,
        analysis_output=analysis_output,
        document_id=document_id,
    )


def _run_analyze(
    arguments: AnalyzeArguments,
) -> int:
    print("[1/3] Loading configuration...")
    config = _load_runtime_config()

    print("[2/3] Checking runtime dependencies...")
    preflight = _run_preflight(config)
    _print_preflight_summary(preflight)

    print("[3/3] Running analysis pipeline...")
    runtime = _create_runtime(
        config=config,
        document_id=arguments.document_id,
    )

    result = runtime.pipeline.run(
        source=arguments.source,
        work_dir=arguments.work_dir,
        vex_output_path=arguments.vex_output,
        analysis_output_path=arguments.analysis_output,
    )

    print()
    print("REVEAL analysis completed.")
    print(
        "Vulnerabilities analyzed: "
        f"{result.vulnerability_count}"
    )

    if result.vex_path is not None:
        print(f"OpenVEX: {result.vex_path}")
    else:
        print(
            "OpenVEX: not generated "
            "(no vulnerabilities were reported)"
        )

    if result.artifact_path is not None:
        print(
            f"Analysis evidence: "
            f"{result.artifact_path}"
        )

    return int(ExitCode.SUCCESS)


def _load_runtime_config() -> RuntimeConfig:
    return RuntimeConfig.from_env()


def _run_preflight(
    config: RuntimeConfig,
) -> PreflightReport:
    return run_preflight(config)


def _create_runtime(
    *,
    config: RuntimeConfig,
    document_id: str,
) -> RuntimeContext:
    return bootstrap_runtime(
        config=config,
        component_factory=(
            create_default_runtime_component_factory()
        ),
        document_id=document_id,
    )


def _print_preflight_summary(
    report: PreflightReport,
) -> None:
    names = ", ".join(report.dependency_names)

    print(
        f"      Resolved {report.dependency_count} "
        f"dependencies: {names}"
    )


def _print_error(
    *,
    category: str,
    error: BaseException,
) -> None:
    print(
        f"reveal: {category} error: {error}",
        file=sys.stderr,
    )


def _generate_document_id() -> str:
    return f"urn:uuid:{uuid4()}"


def _absolute_path(path: Path) -> Path:
    return path.expanduser().resolve()


def _package_version() -> str:
    try:
        return version("reveal-sbom")
    except PackageNotFoundError:
        return "0.1.0"