"""Interfaces for VEX decisions and document generation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Protocol

from reveal.models import (
    ApiMappingResult,
    PocResult,
    TaintResult,
    VexStatement,
    Vulnerability,
)


class VexDecisionPolicy(Protocol):
    """Interface implemented by VEX decision policies."""

    def decide(
        self,
        vulnerability: Vulnerability,
        mapping: ApiMappingResult,
        taint_results: Sequence[TaintResult],
        poc_results: Sequence[PocResult],
    ) -> VexStatement:
        """Convert analysis evidence into one VEX statement."""
        ...


class VexWriter(Protocol):
    """Interface implemented by VEX document writers."""

    def write(
        self,
        statements: Sequence[VexStatement],
        output_path: Path,
        *,
        timestamp: datetime | None = None,
    ) -> Path:
        """Write VEX statements to a document and return its path."""
        ...