"""Tests for the PoC refiner abstraction."""

from __future__ import annotations

from pathlib import Path

from reveal.models import (
    Component,
    PocAttempt,
    PocCandidate,
    PocResult,
    ReachabilityStatus,
    ReproductionStatus,
    TaintPath,
    TaintResult,
    Vulnerability,
)
from reveal.reproduction import PocRefiner


class FakePocRefiner:
    """Minimal refiner used to verify the shared interface."""

    def refine(
        self,
        source: Path,
        vulnerability: Vulnerability,
        taint: TaintResult,
        previous_result: PocResult,
        *,
        max_candidates: int = 3,
    ) -> tuple[PocCandidate, ...]:
        del source, vulnerability, taint

        if not previous_result.attempts:
            return ()

        last_attempt = previous_result.attempts[-1]
        diagnostic = (
            last_attempt.stderr.strip()
            or last_attempt.error
            or "No execution diagnostic was available."
        )

        candidates = (
            PocCandidate(
                language=last_attempt.candidate.language,
                code=(
                    f"{last_attempt.candidate.code.rstrip()}\n"
                    "// Refined after the previous execution failure.\n"
                ),
                expected_signal=last_attempt.candidate.expected_signal,
                description=f"Refined using diagnostic: {diagnostic}",
            ),
            PocCandidate(
                language=last_attempt.candidate.language,
                code=(
                    "'use strict';\n"
                    f"{last_attempt.candidate.code.rstrip()}\n"
                ),
                expected_signal=last_attempt.candidate.expected_signal,
                description="Alternative refined candidate.",
            ),
        )

        return candidates[:max_candidates]


def run_refiner(
    refiner: PocRefiner,
    source: Path,
    vulnerability: Vulnerability,
    taint: TaintResult,
    previous_result: PocResult,
    *,
    max_candidates: int = 3,
) -> tuple[PocCandidate, ...]:
    """Execute any implementation satisfying the refiner protocol."""

    return refiner.refine(
        source=source,
        vulnerability=vulnerability,
        taint=taint,
        previous_result=previous_result,
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
                source_file=Path("src/routes.js"),
                source_line=5,
                source="request.query",
                sink_file=Path("src/routes.js"),
                sink_line=10,
                sink="minimist(request.query)",
                sink_argument=0,
            ),
        ),
        reason="Remote input reaches the selected API.",
    )


def create_previous_result() -> PocResult:
    candidate = PocCandidate(
        language="javascript",
        code=(
            "const minimist = require('minimist');\n"
            "minimist(['--__proto__.polluted', 'true']);\n"
        ),
        expected_signal="REVEAL_REPRODUCED",
        description="Initial PoC candidate.",
    )

    return PocResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        target_api="<module>",
        status=ReproductionStatus.NOT_REPRODUCED,
        attempts=(
            PocAttempt(
                number=1,
                candidate=candidate,
                exit_code=1,
                stdout="",
                stderr="Expected signal was not emitted.",
                reproduced=False,
            ),
        ),
        reason="The initial candidate did not reproduce the vulnerability.",
    )


def test_refiner_accepts_structural_implementation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    candidates = run_refiner(
        refiner=FakePocRefiner(),
        source=source,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        previous_result=create_previous_result(),
    )

    assert len(candidates) == 2
    assert candidates[0].language == "javascript"
    assert "Refined after" in candidates[0].code
    assert candidates[0].expected_signal == "REVEAL_REPRODUCED"
    assert "Expected signal was not emitted." in candidates[0].description


def test_refiner_respects_candidate_limit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    candidates = run_refiner(
        refiner=FakePocRefiner(),
        source=source,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        previous_result=create_previous_result(),
        max_candidates=1,
    )

    assert len(candidates) == 1


def test_refiner_can_return_no_candidates_without_attempts(
    tmp_path: Path,
) -> None:
    previous_result = PocResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        target_api="<module>",
        status=ReproductionStatus.ERROR,
        reason="PoC generation failed before execution.",
    )

    candidates = run_refiner(
        refiner=FakePocRefiner(),
        source=tmp_path,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        previous_result=previous_result,
    )

    assert candidates == ()