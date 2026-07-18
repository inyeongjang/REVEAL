"""Tests for the PoC generator abstraction."""

from __future__ import annotations

from pathlib import Path

from reveal.models import (
    Component,
    PocCandidate,
    ReachabilityStatus,
    TaintPath,
    TaintResult,
    Vulnerability,
)
from reveal.reproduction import PocGenerator


class FakePocGenerator:
    """Minimal generator used to verify the shared interface."""

    def generate(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        del source

        candidates = (
            PocCandidate(
                language="javascript",
                code=(
                    "const minimist = require('minimist');\n"
                    "minimist(['--__proto__.polluted', 'true']);\n"
                ),
                expected_signal="Object.prototype.polluted is set",
                description=(
                    f"Exercise {taint.target_api} for "
                    f"{vulnerability.id}."
                ),
            ),
            PocCandidate(
                language="javascript",
                code=(
                    "const minimist = require('minimist');\n"
                    "minimist(['--constructor.prototype.polluted', 'true']);\n"
                ),
                expected_signal="A prototype property is modified",
                description="Alternative crafted argument path.",
            ),
        )

        return candidates[:max_candidates]


def run_generator(
    generator: PocGenerator,
    source: Path,
    vulnerability: Vulnerability,
    taint: TaintResult,
    *,
    max_candidates: int = 3,
) -> tuple[PocCandidate, ...]:
    """Execute any implementation satisfying the generator protocol."""

    return generator.generate(
        source=source,
        vulnerability=vulnerability,
        taint=taint,
        max_candidates=max_candidates,
    )


def create_vulnerability() -> Vulnerability:
    return Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=Component(
            name="minimist",
            version="0.0.8",
            ecosystem="npm",
            purl="pkg:npm/minimist@0.0.8",
        ),
        aliases=("CVE-2021-44906",),
        description="Prototype pollution in minimist.",
    )


def create_taint_result() -> TaintResult:
    return TaintResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        target_api="<module>",
        status=ReachabilityStatus.REACHABLE,
        paths=(
            TaintPath(
                source_file=Path("src/routes/arguments.js"),
                source_line=7,
                source="request.query",
                sink_file=Path("src/routes/arguments.js"),
                sink_line=13,
                sink="minimist(request.query)",
                sink_argument=0,
            ),
        ),
        reason="Remote input reaches the selected API.",
    )


def test_generator_accepts_structural_implementation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    candidates = run_generator(
        generator=FakePocGenerator(),
        source=source,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
    )

    assert len(candidates) == 2
    assert candidates[0].language == "javascript"
    assert "minimist" in candidates[0].code
    assert candidates[0].expected_signal
    assert "GHSA-xvch-5gv4-984h" in candidates[0].description


def test_generator_respects_candidate_limit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    candidates = run_generator(
        generator=FakePocGenerator(),
        source=source,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        max_candidates=1,
    )

    assert len(candidates) == 1


def test_generator_can_return_no_candidates(
    tmp_path: Path,
) -> None:
    class EmptyPocGenerator:
        def generate(
            self,
            source: Path,
            vulnerability: Vulnerability,
            taint: TaintResult,
            *,
            max_candidates: int = 3,
        ) -> tuple[PocCandidate, ...]:
            del source, vulnerability, taint, max_candidates
            return ()

    candidates = run_generator(
        generator=EmptyPocGenerator(),
        source=tmp_path,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
    )

    assert candidates == ()