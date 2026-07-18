"""Interfaces for SBOM generation."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from reveal.models import Sbom


class SbomGenerator(Protocol):
    """Interface implemented by SBOM generation tools."""

    def generate(self, source: Path, output_path: Path) -> Sbom:
        """Generate and normalize an SBOM for the given source."""
        ...