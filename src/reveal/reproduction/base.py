"""Interfaces for vulnerability reproduction."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from reveal.models import PocCandidate, TaintResult, Vulnerability


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