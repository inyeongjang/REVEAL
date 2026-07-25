"""Progress reporting interfaces for the REVEAL analysis pipeline."""

from __future__ import annotations

from enum import Enum
from typing import Protocol

from reveal.models import (
    ApiMappingResult,
    PocResult,
    ReachabilityStatus,
    ReproductionStatus,
    TaintResult,
    VexStatement,
    Vulnerability,
)
from reveal.ui import ConsoleUI


class ProgressOutcome(str, Enum):
    """Outcome of one pipeline stage."""

    OK = "ok"
    WARNING = "warning"
    SKIPPED = "skipped"


class PipelineProgressReporter(Protocol):
    """Receive structured progress events from the analysis pipeline."""

    def stage_started(
        self,
        current: int,
        total: int,
        title: str,
    ) -> None:
        """Report that a top-level pipeline stage has started."""

    def stage_finished(
        self,
        current: int,
        total: int,
        title: str,
        outcome: ProgressOutcome,
        message: str,
    ) -> None:
        """Report that a top-level pipeline stage has finished."""

    def vulnerability_started(
        self,
        current: int,
        total: int,
        vulnerability: Vulnerability,
    ) -> None:
        """Report that analysis of one vulnerability has started."""

    def vulnerability_finished(
        self,
        current: int,
        total: int,
        mapping: ApiMappingResult,
        taint_results: tuple[TaintResult, ...],
        poc_results: tuple[PocResult, ...],
        vex_statement: VexStatement,
    ) -> None:
        """Report the completed analysis result for one vulnerability."""


class NullProgressReporter:
    """Discard all pipeline progress events."""

    def stage_started(
        self,
        current: int,
        total: int,
        title: str,
    ) -> None:
        del current, total, title

    def stage_finished(
        self,
        current: int,
        total: int,
        title: str,
        outcome: ProgressOutcome,
        message: str,
    ) -> None:
        del current, total, title, outcome, message

    def vulnerability_started(
        self,
        current: int,
        total: int,
        vulnerability: Vulnerability,
    ) -> None:
        del current, total, vulnerability

    def vulnerability_finished(
        self,
        current: int,
        total: int,
        mapping: ApiMappingResult,
        taint_results: tuple[TaintResult, ...],
        poc_results: tuple[PocResult, ...],
        vex_statement: VexStatement,
    ) -> None:
        del (
            current,
            total,
            mapping,
            taint_results,
            poc_results,
            vex_statement,
        )


class ConsoleProgressReporter:
    """Render pipeline progress through a :class:`ConsoleUI` instance."""

    def __init__(self, ui: ConsoleUI) -> None:
        self._ui = ui

    def stage_started(
        self,
        current: int,
        total: int,
        title: str,
    ) -> None:
        self._ui.stage(current, total, title)

    def stage_finished(
        self,
        current: int,
        total: int,
        title: str,
        outcome: ProgressOutcome,
        message: str,
    ) -> None:
        del current, total, title

        if outcome is ProgressOutcome.OK:
            self._ui.success(message)
            return

        if outcome is ProgressOutcome.WARNING:
            self._ui.warning(message)
            return

        self._ui.skipped(message)

    def vulnerability_started(
        self,
        current: int,
        total: int,
        vulnerability: Vulnerability,
    ) -> None:
        component = vulnerability.component
        package = component.name

        if component.version:
            package = f"{package}@{component.version}"

        label = f"{vulnerability.id} ({package})"
        self._ui.vulnerability(current, total, label)

    def vulnerability_finished(
        self,
        current: int,
        total: int,
        mapping: ApiMappingResult,
        taint_results: tuple[TaintResult, ...],
        poc_results: tuple[PocResult, ...],
        vex_statement: VexStatement,
    ) -> None:
        del current, total

        mapping_status = mapping.status.value.upper()
        reachability_status = _summarize_reachability(taint_results)
        reproduction_status = _summarize_reproduction(poc_results)
        vex_status = vex_statement.status.value.upper()

        if self._ui.verbose:
            self._render_verbose_mapping(mapping)
            self._render_verbose_taint(taint_results)
            self._render_verbose_poc(poc_results)
            self._ui.detail("VEX", vex_status)
            return

        self._ui.vulnerability_summary(
            (
                mapping_status,
                reachability_status,
                reproduction_status,
                vex_status,
            )
        )

    def _render_verbose_mapping(
        self,
        mapping: ApiMappingResult,
    ) -> None:
        description_parts: list[str] = []

        if mapping.target_apis:
            description_parts.append(", ".join(mapping.target_apis))

        if mapping.confidence is not None:
            description_parts.append(
                f"confidence={mapping.confidence:.2f}"
            )

        self._ui.detail(
            "API mapping",
            mapping.status.value.upper(),
            description="; ".join(description_parts),
        )

    def _render_verbose_taint(
        self,
        results: tuple[TaintResult, ...],
    ) -> None:
        path_count = sum(result.path_count for result in results)
        description = ""

        if results:
            description = (
                f"{len(results)} target(s), "
                f"{path_count} path(s)"
            )

        self._ui.detail(
            "Reachability",
            _summarize_reachability(results),
            description=description,
        )

    def _render_verbose_poc(
        self,
        results: tuple[PocResult, ...],
    ) -> None:
        attempt_count = sum(
            result.attempt_count
            for result in results
        )
        description = ""

        if results:
            description = (
                f"{len(results)} target(s), "
                f"{attempt_count} attempt(s)"
            )

        self._ui.detail(
            "PoC",
            _summarize_reproduction(results),
            description=description,
        )


def _summarize_reachability(
    results: tuple[TaintResult, ...],
) -> str:
    if not results:
        return "SKIPPED"

    statuses = {result.status for result in results}

    if ReachabilityStatus.ERROR in statuses:
        return ReachabilityStatus.ERROR.value.upper()

    if ReachabilityStatus.REACHABLE in statuses:
        return ReachabilityStatus.REACHABLE.value.upper()

    if ReachabilityStatus.UNKNOWN in statuses:
        return ReachabilityStatus.UNKNOWN.value.upper()

    return ReachabilityStatus.UNREACHABLE.value.upper()


def _summarize_reproduction(
    results: tuple[PocResult, ...],
) -> str:
    if not results:
        return ReproductionStatus.SKIPPED.value.upper()

    statuses = {result.status for result in results}

    if ReproductionStatus.REPRODUCED in statuses:
        return ReproductionStatus.REPRODUCED.value.upper()

    if ReproductionStatus.ERROR in statuses:
        return ReproductionStatus.ERROR.value.upper()

    if ReproductionStatus.INCONCLUSIVE in statuses:
        return ReproductionStatus.INCONCLUSIVE.value.upper()

    if ReproductionStatus.NOT_REPRODUCED in statuses:
        return ReproductionStatus.NOT_REPRODUCED.value.upper()

    return ReproductionStatus.SKIPPED.value.upper()