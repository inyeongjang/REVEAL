"""Interfaces for normalized analysis artifact generation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Protocol

from reveal.models import (
    ApiMappingResult,
    ApiUsage,
    PocResult,
    ScanResult,
    TaintResult,
    VexStatement,
    Vulnerability,
)


class VulnerabilityAnalysisView(Protocol):
    """Read-only view of one vulnerability analysis result."""

    @property
    def vulnerability(self) -> Vulnerability:
        """Return the analyzed vulnerability."""
        ...

    @property
    def mapping(self) -> ApiMappingResult:
        """Return the vulnerable API mapping result."""
        ...

    @property
    def taint_results(self) -> tuple[TaintResult, ...]:
        """Return taint reachability results."""
        ...

    @property
    def poc_results(self) -> tuple[PocResult, ...]:
        """Return PoC reproduction results."""
        ...

    @property
    def vex_statement(self) -> VexStatement:
        """Return the final VEX statement."""
        ...


class AnalysisArtifactWriter(Protocol):
    """Interface implemented by normalized artifact writers."""

    def write(
        self,
        *,
        scan: ScanResult,
        usages: Sequence[ApiUsage],
        analyses: Sequence[VulnerabilityAnalysisView],
        output_path: Path,
        vex_path: Path | None = None,
        timestamp: datetime | None = None,
    ) -> Path:
        """Write normalized analysis evidence and return its path."""
        ...