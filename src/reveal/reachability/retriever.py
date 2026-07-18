"""Interfaces for retrieving vulnerability evidence."""

from __future__ import annotations

from typing import Protocol

from reveal.models import Vulnerability, VulnerabilityEvidence


class VulnerabilityEvidenceRetriever(Protocol):
    """Retrieve supporting evidence for vulnerability-to-API mapping."""

    def retrieve(
        self,
        vulnerability: Vulnerability,
        *,
        limit: int = 5,
    ) -> tuple[VulnerabilityEvidence, ...]:
        """Return evidence relevant to the supplied vulnerability."""
        ...