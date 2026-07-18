"""Shared exception hierarchy for REVEAL."""


class RevealError(Exception):
    """Base exception for expected REVEAL failures."""


class SbomGenerationError(RevealError):
    """Raised when SBOM generation or normalization fails."""