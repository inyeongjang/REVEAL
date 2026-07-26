"""Progress reporting for REVEAL analysis."""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Literal, Protocol, TextIO

from reveal.models import (
    ApiMappingResult,
    PocResult,
    TaintResult,
    VexStatement,
    Vulnerability,
)


class AnalysisStage(IntEnum):
    """Ordered REVEAL analysis stages."""

    RESOLVE_SOURCE = 1
    VALIDATE_RUNTIME = 2
    GENERATE_SBOM = 3
    SCAN_VULNERABILITIES = 4
    DETECT_USAGE = 5
    EVALUATE_VULNERABILITIES = 6
    WRITE_OPENVEX = 7
    WRITE_ANALYSIS = 8


STAGE_NAMES: dict[AnalysisStage, str] = {
    AnalysisStage.RESOLVE_SOURCE: "Resolving source",
    AnalysisStage.VALIDATE_RUNTIME: (
        "Validating configuration and dependencies"
    ),
    AnalysisStage.GENERATE_SBOM: "Generating SBOM",
    AnalysisStage.SCAN_VULNERABILITIES: (
        "Scanning dependency vulnerabilities"
    ),
    AnalysisStage.DETECT_USAGE: "Analyzing package usage",
    AnalysisStage.EVALUATE_VULNERABILITIES: (
        "Evaluating vulnerabilities"
    ),
    AnalysisStage.WRITE_OPENVEX: "Writing OpenVEX",
    AnalysisStage.WRITE_ANALYSIS: (
        "Writing analysis evidence"
    ),
}

TOTAL_STAGES = len(AnalysisStage)

ProgressStatus = Literal[
    "running",
    "completed",
    "warning",
    "skipped",
    "failed",
]


class ProgressOutcome(str, Enum):
    """Result of one completed pipeline stage."""

    OK = "ok"
    WARNING = "warning"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """One normalized progress event."""

    stage: int
    total_stages: int
    name: str
    status: ProgressStatus
    detail: str | None = None
    current: int | None = None
    total: int | None = None


class ProgressReporter(Protocol):
    """Common progress reporter interface."""

    def report(self, event: ProgressEvent) -> None:
        """Report one normalized event."""

    def close(self) -> None:
        """Release reporter resources."""


class PipelineProgressReporter(ProgressReporter, Protocol):
    """Progress interface expected by AnalysisPipeline."""

    def stage_started(
        self,
        stage: int,
        total_stages: int,
        name: str,
    ) -> None:
        """Report the start of one pipeline stage."""

    def stage_finished(
        self,
        stage: int,
        total_stages: int,
        name: str,
        outcome: ProgressOutcome,
        detail: str | None = None,
    ) -> None:
        """Report the completion of one pipeline stage."""

    def vulnerability_started(
        self,
        current: int,
        total: int,
        vulnerability: Vulnerability,
    ) -> None:
        """Report the start of one vulnerability analysis."""

    def vulnerability_finished(
        self,
        current: int,
        total: int,
        mapping: ApiMappingResult,
        taint_results: tuple[TaintResult, ...],
        poc_results: tuple[PocResult, ...],
        vex_statement: VexStatement,
    ) -> None:
        """Report the result of one vulnerability analysis."""


class BaseProgressReporter:
    """Translate pipeline callbacks into normalized events."""

    _PIPELINE_STAGE_OFFSET = 2
    _PIPELINE_TOTAL_STAGES = 8

    def report(self, event: ProgressEvent) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def stage_started(
        self,
        stage: int,
        total_stages: int,
        name: str,
    ) -> None:
        del total_stages

        self.report(
            ProgressEvent(
                stage=stage + self._PIPELINE_STAGE_OFFSET,
                total_stages=self._PIPELINE_TOTAL_STAGES,
                name=name,
                status="running",
            )
        )

    def stage_finished(
        self,
        stage: int,
        total_stages: int,
        name: str,
        outcome: ProgressOutcome,
        detail: str | None = None,
    ) -> None:
        del total_stages

        self.report(
            ProgressEvent(
                stage=stage + self._PIPELINE_STAGE_OFFSET,
                total_stages=self._PIPELINE_TOTAL_STAGES,
                name=name,
                status=_outcome_status(outcome),
                detail=detail,
            )
        )

    def vulnerability_started(
        self,
        current: int,
        total: int,
        vulnerability: Vulnerability,
    ) -> None:
        component = vulnerability.component

        self.report(
            ProgressEvent(
                stage=6,
                total_stages=self._PIPELINE_TOTAL_STAGES,
                name="Evaluating vulnerabilities",
                status="running",
                detail=(
                    f"{vulnerability.id} · "
                    f"{component.name}@{component.version}"
                ),
                current=current,
                total=total,
            )
        )

    def vulnerability_finished(
        self,
        current: int,
        total: int,
        mapping: ApiMappingResult,
        taint_results: tuple[TaintResult, ...],
        poc_results: tuple[PocResult, ...],
        vex_statement: VexStatement,
    ) -> None:
        mapping_status = _enum_value(mapping.status)
        taint_status = _summarize_statuses(
            result.status for result in taint_results
        )
        poc_status = _summarize_statuses(
            result.status for result in poc_results
        )
        vex_status = _enum_value(vex_statement.status)

        self.report(
            ProgressEvent(
                stage=6,
                total_stages=self._PIPELINE_TOTAL_STAGES,
                name="Evaluating vulnerabilities",
                status="completed",
                detail=(
                    f"{mapping_status} → "
                    f"{taint_status} → "
                    f"{poc_status} → "
                    f"{vex_status}"
                ),
                current=current,
                total=total,
            )
        )


class NullProgressReporter(BaseProgressReporter):
    """Ignore all progress events."""

    def report(self, event: ProgressEvent) -> None:
        del event


class ConsoleProgressReporter(BaseProgressReporter):
    """Display progress with a terminal spinner."""

    _SPINNER_FRAMES = (
        "⠋",
        "⠙",
        "⠹",
        "⠸",
        "⠼",
        "⠴",
        "⠦",
        "⠧",
        "⠇",
        "⠏",
    )

    _STATUS_ICONS: dict[ProgressStatus, str] = {
        "running": "•",
        "completed": "✓",
        "warning": "!",
        "skipped": "−",
        "failed": "✗",
    }

    def __init__(
        self,
        *,
        stream: TextIO = sys.stderr,
        interval_seconds: float = 0.1,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError(
                "interval_seconds must be positive."
            )

        self._stream = stream
        self._interval_seconds = interval_seconds
        self._interactive = stream.isatty()

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._spinner_thread: threading.Thread | None = None
        self._active_event: ProgressEvent | None = None

        self._frame_index = 0
        self._rendered_length = 0

    def report(self, event: ProgressEvent) -> None:
        if event.status == "running":
            self._start_spinner(event)
            return

        self._stop_spinner()
        self._write_final(event)

    def close(self) -> None:
        self._stop_spinner()

    def _start_spinner(
        self,
        event: ProgressEvent,
    ) -> None:
        self._stop_spinner()
        self._active_event = event

        if not self._interactive:
            self._stream.write(
                f"• {self._format_event(event)}\n"
            )
            self._stream.flush()
            return

        self._stop_event.clear()
        self._spinner_thread = threading.Thread(
            target=self._spin,
            name="reveal-progress-spinner",
            daemon=True,
        )
        self._spinner_thread.start()

    def _spin(self) -> None:
        while not self._stop_event.wait(
            self._interval_seconds
        ):
            event = self._active_event

            if event is None:
                return

            icon = self._SPINNER_FRAMES[
                self._frame_index
                % len(self._SPINNER_FRAMES)
            ]
            self._frame_index += 1

            self._write_current(
                f"{icon} {self._format_event(event)}"
            )

    def _stop_spinner(self) -> None:
        self._stop_event.set()

        thread = self._spinner_thread

        if (
            thread is not None
            and thread is not threading.current_thread()
        ):
            thread.join(timeout=1.0)

        self._spinner_thread = None
        self._active_event = None

        if (
            self._interactive
            and self._rendered_length > 0
        ):
            self._clear_current_line()

    def _write_final(
        self,
        event: ProgressEvent,
    ) -> None:
        icon = self._STATUS_ICONS[event.status]

        self._stream.write(
            f"{icon} {self._format_event(event)}\n"
        )
        self._stream.flush()

    def _write_current(
        self,
        text: str,
    ) -> None:
        with self._lock:
            padding = max(
                0,
                self._rendered_length - len(text),
            )

            self._stream.write(
                "\r" + text + (" " * padding)
            )
            self._stream.flush()

            self._rendered_length = len(text)

    def _clear_current_line(self) -> None:
        with self._lock:
            self._stream.write(
                "\r"
                + (" " * self._rendered_length)
                + "\r"
            )
            self._stream.flush()

            self._rendered_length = 0

    @staticmethod
    def _format_event(
        event: ProgressEvent,
    ) -> str:
        text = (
            f"[{event.stage}/{event.total_stages}] "
            f"{event.name}"
        )

        if (
            event.current is not None
            and event.total is not None
        ):
            text += (
                f" [{event.current}/{event.total}]"
            )

        if event.detail:
            text += f" · {event.detail}"

        return text


class JsonProgressReporter(BaseProgressReporter):
    """Write machine-readable progress events as JSON Lines."""

    def __init__(
        self,
        *,
        stream: TextIO = sys.stdout,
    ) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def report(
        self,
        event: ProgressEvent,
    ) -> None:
        payload = {
            "type": "progress",
            "stage": event.stage,
            "total_stages": event.total_stages,
            "name": event.name,
            "status": event.status,
            "detail": event.detail,
            "current": event.current,
            "total": event.total,
        }

        with self._lock:
            json.dump(
                payload,
                self._stream,
                ensure_ascii=False,
            )
            self._stream.write("\n")
            self._stream.flush()


def _outcome_status(
    outcome: ProgressOutcome,
) -> ProgressStatus:
    if outcome is ProgressOutcome.OK:
        return "completed"

    if outcome is ProgressOutcome.WARNING:
        return "warning"

    if outcome is ProgressOutcome.SKIPPED:
        return "skipped"

    return "failed"


def _enum_value(value: object) -> str:
    raw_value = getattr(value, "value", value)

    return str(raw_value).upper()


def _summarize_statuses(
    statuses: object,
) -> str:
    values = [
        _enum_value(status)
        for status in statuses
    ]

    if not values:
        return "SKIPPED"

    unique: list[str] = []

    for value in values:
        if value not in unique:
            unique.append(value)

    return ",".join(unique)