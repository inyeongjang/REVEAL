"""Shared exception hierarchy for REVEAL."""


class RevealError(Exception):
    """Base exception for expected REVEAL failures."""


class SbomGenerationError(RevealError):
    """Raised when SBOM generation or normalization fails."""


class VulnerabilityScanError(RevealError):
    """Raised when vulnerability scanning or normalization fails."""


class CodeQLAnalysisError(RevealError):
    """Raised when CodeQL database creation or query execution fails."""


class LlmError(RevealError):
    """Raised when an LLM request or response processing fails."""


class EvidenceRetrievalError(RevealError):
    """Raised when vulnerability evidence retrieval fails."""


class PocGenerationError(RevealError):
    """Raised when PoC context collection or generation fails."""


class PocExecutionError(RevealError):
    """Raised when a PoC execution environment cannot be prepared."""


class VexDecisionError(RevealError):
    """Raised when inconsistent evidence prevents a VEX decision."""


class VexWriteError(RevealError):
    """Raised when an OpenVEX document cannot be created."""


class PipelineError(RevealError):
    """Raised when the analysis pipeline cannot be prepared."""