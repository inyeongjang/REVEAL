"""Shared domain models for the REVEAL analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ApiMappingStatus(str, Enum):
    """Outcome of mapping a vulnerability to observed API usage."""

    MAPPED = "mapped"
    UNUSED = "unused"
    UNRESOLVED = "unresolved"
    ERROR = "error"


class ReachabilityStatus(str, Enum):
    """Outcome of analyzing input reachability to a vulnerable API."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"
    ERROR = "error"


class ReproductionStatus(str, Enum):
    """Outcome of attempting to reproduce vulnerable behavior."""

    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"
    ERROR = "error"


class VexStatus(str, Enum):
    """Tool-independent VEX product status."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


@dataclass(frozen=True, slots=True)
class Component:
    """A software component reported in an SBOM."""

    name: str
    version: str
    ecosystem: str
    purl: str | None = None


@dataclass(frozen=True, slots=True)
class Sbom:
    """A normalized SBOM generated for a target repository."""

    format: str
    generator: str
    document_path: Path
    components: tuple[Component, ...]


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """A vulnerability associated with one software component."""

    id: str
    component: Component
    aliases: tuple[str, ...] = ()
    description: str = ""
    severity: str | None = None
    fixed_versions: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Result of scanning an SBOM for known vulnerabilities."""

    sbom: Sbom
    vulnerabilities: tuple[Vulnerability, ...]

    @property
    def finding_count(self) -> int:
        """Return the number of vulnerability findings."""

        return len(self.vulnerabilities)


@dataclass(frozen=True, slots=True)
class ApiUsage:
    """One observed use of a dependency API."""

    package: str
    api: str
    file: Path
    line: int
    column: int | None = None


@dataclass(frozen=True, slots=True)
class ApiMappingResult:
    """Result of mapping one vulnerability to observed APIs."""

    vulnerability_id: str
    status: ApiMappingStatus
    target_apis: tuple[str, ...] = ()
    rationale: str = ""
    confidence: float | None = None

    def __post_init__(self) -> None:
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("API mapping confidence must be between 0.0 and 1.0.")

    @property
    def has_targets(self) -> bool:
        """Return whether at least one target API was selected."""

        return bool(self.target_apis)


@dataclass(frozen=True, slots=True)
class TaintPath:
    """One attacker-controlled data flow reaching a target API."""

    source_file: Path
    source_line: int
    source: str
    sink_file: Path
    sink_line: int
    sink: str
    sink_argument: int | None = None
    steps: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TaintResult:
    """Reachability result for one selected target API."""

    vulnerability_id: str
    target_api: str
    status: ReachabilityStatus
    paths: tuple[TaintPath, ...] = ()
    reason: str = ""

    @property
    def path_count(self) -> int:
        """Return the number of discovered taint paths."""

        return len(self.paths)


@dataclass(frozen=True, slots=True)
class PocCandidate:
    """A generated candidate for reproducing vulnerable behavior."""

    language: str
    code: str
    expected_signal: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class PocAttempt:
    """One PoC generation and execution attempt."""

    number: int
    candidate: PocCandidate
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    reproduced: bool = False
    error: str | None = None


@dataclass(frozen=True, slots=True)
class PocResult:
    """Final reproduction result for one target API."""

    vulnerability_id: str
    target_api: str
    status: ReproductionStatus
    attempts: tuple[PocAttempt, ...] = ()
    evidence: str = ""
    reason: str = ""

    @property
    def attempt_count(self) -> int:
        """Return the number of attempted PoCs."""

        return len(self.attempts)


@dataclass(frozen=True, slots=True)
class VexStatement:
    """A format-independent exploitability statement."""

    vulnerability_id: str
    products: tuple[str, ...]
    status: VexStatus
    justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None