"""Command-line interface for REVEAL."""

from __future__ import annotations

import argparse
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
from reveal.models import VexStatus
from reveal.pipeline import PipelineResult
from reveal.preflight import (
    PreflightReport,
    run_preflight,
)
from reveal.progress import ConsoleProgressReporter
from reveal.source import resolve_source
from reveal.ui import ConsoleUI


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

    source: str
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
        metavar="SOURCE",
        help=(
            "Local source directory or public GitHub repository "
            "URL to analyze."
        ),
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

    output_group = analyze_parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress normal progress and result output.",
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed configuration and analysis progress.",
    )
    analyze_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output.",
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

    ui = _create_console_ui(namespace)

    try:
        if namespace.command == "analyze":
            arguments = _normalize_analyze_arguments(namespace)

            return _run_analyze(arguments, ui=ui)

        parser.error(
            f"Unsupported command: {namespace.command}"
        )
    except ConfigurationError as error:
        _print_error(
            ui=ui,
            category="configuration",
            error=error,
        )

        return int(ExitCode.CONFIGURATION_ERROR)
    except PreflightError as error:
        _print_error(
            ui=ui,
            category="dependency",
            error=error,
        )

        return int(ExitCode.DEPENDENCY_ERROR)
    except BootstrapError as error:
        _print_error(
            ui=ui,
            category="bootstrap",
            error=error,
        )

        return int(ExitCode.ANALYSIS_ERROR)
    except RevealError as error:
        _print_error(
            ui=ui,
            category="analysis",
            error=error,
        )

        return int(ExitCode.ANALYSIS_ERROR)

    return int(ExitCode.GENERAL_ERROR)


def _normalize_analyze_arguments(
    namespace: argparse.Namespace,
) -> AnalyzeArguments:
    source = str(namespace.source).strip()
    work_dir = _absolute_path(namespace.work_dir)

    if not source:
        raise PipelineError("Source must not be empty.")

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
    *,
    ui: ConsoleUI,
) -> int:
    ui.banner()

    ui.stage(1, 3, "Loading configuration")
    config = _load_runtime_config()
    ui.success(
        f"{config.llm.provider.value} / {config.llm.model}"
    )

    if ui.verbose:
        ui.debug("Source", str(arguments.source))
        ui.debug("Work directory", str(arguments.work_dir))

    ui.stage(2, 3, "Checking runtime dependencies")
    preflight = _run_preflight(config)
    _print_preflight_summary(preflight, ui=ui)

    ui.stage(3, 3, "Running analysis pipeline")
    runtime = _create_runtime(
        config=config,
        document_id=arguments.document_id,
    )

    with resolve_source(arguments.source) as source:
        if source.is_remote:
            ui.success(f"cloned {source.repository_url}")

        ui.debug("Resolved source", str(source.path))

        result = runtime.pipeline.run(
            source=source.path,
            work_dir=arguments.work_dir,
            vex_output_path=arguments.vex_output,
            analysis_output_path=arguments.analysis_output,
            progress=ConsoleProgressReporter(ui),
        )

    _print_analysis_summary(result, ui=ui)

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


def _create_console_ui(
    namespace: argparse.Namespace,
) -> ConsoleUI:
    return ConsoleUI(
        quiet=bool(getattr(namespace, "quiet", False)),
        verbose=bool(getattr(namespace, "verbose", False)),
        color=(
            False
            if bool(getattr(namespace, "no_color", False))
            else None
        ),
    )


def _print_preflight_summary(
    report: PreflightReport,
    *,
    ui: ConsoleUI,
) -> None:
    names = ", ".join(report.dependency_names)
    message = f"resolved {report.dependency_count} dependencies"

    if names:
        message = f"{message}: {names}"

    ui.success(message)

    for dependency in report.dependencies:
        ui.debug(
            dependency.name,
            str(dependency.resolved_path),
        )


def _print_analysis_summary(
    result: PipelineResult,
    *,
    ui: ConsoleUI,
) -> None:
    ui.section("Analysis complete")
    ui.field("Vulnerabilities", result.vulnerability_count)

    counts = _count_vex_statuses(result)

    if result.vulnerability_count:
        ui.field("Affected", counts[VexStatus.AFFECTED])
        ui.field(
            "Not affected",
            counts[VexStatus.NOT_AFFECTED],
        )
        ui.field("Fixed", counts[VexStatus.FIXED])
        ui.field(
            "Investigating",
            counts[VexStatus.UNDER_INVESTIGATION],
        )

    ui.section("Artifacts")

    if result.vex_path is not None:
        ui.field("OpenVEX", result.vex_path)
    else:
        ui.field(
            "OpenVEX",
            "not generated (no vulnerabilities)",
        )

    if result.artifact_path is not None:
        ui.field("Evidence", result.artifact_path)
    else:
        ui.field("Evidence", "not generated")


def _count_vex_statuses(
    result: PipelineResult,
) -> dict[VexStatus, int]:
    counts = {
        status: 0
        for status in VexStatus
    }

    for analysis in result.analyses:
        counts[analysis.vex_statement.status] += 1

    return counts


def _print_error(
    *,
    ui: ConsoleUI,
    category: str,
    error: BaseException,
) -> None:
    ui.error(
        category=category,
        message=str(error),
    )

    hint = _error_hint(category)

    if hint:
        ui.hint(hint)


def _error_hint(category: str) -> str | None:
    if category == "configuration":
        return (
            "Check the REVEAL_* environment variables and "
            "the selected LLM provider settings."
        )

    if category == "dependency":
        return (
            "Install the missing tool or configure its "
            "REVEAL_*_PATH environment variable."
        )

    if category == "bootstrap":
        return (
            "Verify that the configured adapters and optional "
            "features are available."
        )

    if category == "analysis":
        return (
            "Run the command again with --verbose and inspect "
            "the generated files under the work directory."
        )

    return None


def _generate_document_id() -> str:
    return f"urn:uuid:{uuid4()}"


def _absolute_path(path: Path) -> Path:
    return path.expanduser().resolve()


def _package_version() -> str:
    try:
        return version("reveal-sbom")
    except PackageNotFoundError:
        return "0.1.0"