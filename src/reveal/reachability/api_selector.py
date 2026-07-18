"""Interfaces for selecting vulnerable APIs from observed usages."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from reveal.models import ApiMappingResult, ApiUsage, Vulnerability


class VulnerableApiSelector(Protocol):
    """Select APIs associated with a vulnerability from observed usages."""

    def select(
        self,
        vulnerability: Vulnerability,
        usages: Sequence[ApiUsage],
    ) -> ApiMappingResult:
        """Map a vulnerability to zero or more observed target APIs."""
        ...