"""Interfaces for package usage and reachability analysis."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from reveal.models import ApiUsage


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