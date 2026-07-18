"""Interfaces for vulnerability scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from reveal.models import Sbom, ScanResult


class VulnerabilityScanner(Protocol):
    """Interface implemented by vulnerability scanning tools."""

    def scan(self, sbom: Sbom, output_path: Path) -> ScanResult:
        """Scan an SBOM and return normalized vulnerability findings."""
        ...