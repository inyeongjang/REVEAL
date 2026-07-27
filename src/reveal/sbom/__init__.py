"""SBOM generation support."""

from reveal.sbom.base import SbomGenerator
from reveal.sbom.syft import SyftSbomGenerator

__all__ = ["SbomGenerator", "SyftSbomGenerator"]