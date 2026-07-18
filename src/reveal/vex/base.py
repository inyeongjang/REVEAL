"""Interfaces for VEX decision policies."""

from __future__ import annotations

from collections.abc import Sequence
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