"""Shared exception hierarchy for REVEAL."""


class RevealError(Exception):
    """Base exception for expected REVEAL failures."""


class SbomGenerationError(RevealError):
    """Raised when SBOM generation or normalization fails."""


class VulnerabilityScanError(RevealError):
    """Raised when vulnerability scanning or normalization fails."""


class CodeQLAnalysisError(RevealError):
    """Raised when CodeQL database creation or query execution fails."""