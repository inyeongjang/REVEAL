"""Interfaces for package usage and reachability analysis."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from reveal.models import ApiUsage, TaintResult, Vulnerability


class UsageAnalyzer(Protocol):
    """Interface implemented by package usage analysis tools."""

    def analyze(
        self,
        source: Path,
        packages: Sequence[str],
        work_dir: Path,
    ) -> tuple[ApiUsage, ...]:
        """Find observed API usages for the requested packages."""
        ...


class TaintAnalyzer(Protocol):
    """Interface implemented by input reachability analysis tools."""

    def analyze(
        self,
        source: Path,
        vulnerability: Vulnerability,
        targets: Sequence[ApiUsage],
        work_dir: Path,
    ) -> tuple[TaintResult, ...]:
        """Analyze attacker-controlled input flows to selected API usages."""
        ...