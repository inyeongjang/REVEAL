"""Interfaces for vulnerability reproduction."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from reveal.models import (
    PocCandidate,
    PocResult,
    TaintResult,
    Vulnerability,
)


class PocGenerator(Protocol):
    """Interface implemented by proof-of-concept generators."""

    def generate(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        """Generate PoC candidates for a reachable vulnerability."""
        ...


class PocRefiner(Protocol):
    """Interface implemented by proof-of-concept refiners."""

    def refine(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        previous_result: PocResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        """Generate revised candidates from a previous execution result."""
        ...


class PocRunner(Protocol):
    """Interface implemented by isolated PoC execution environments."""

    def run(
        self,
        source: Path,
        vulnerability: Vulnerability,
        target_api: str,
        candidates: Sequence[PocCandidate],
        work_dir: Path,
    ) -> PocResult:
        """Execute PoC candidates and return normalized reproduction evidence."""
        ...