"""Vulnerability scanning support."""

from reveal.vulnerabilities.base import VulnerabilityScanner
from reveal.vulnerabilities.grype import GrypeVulnerabilityScanner

__all__ = [
    "GrypeVulnerabilityScanner",
    "VulnerabilityScanner",
]