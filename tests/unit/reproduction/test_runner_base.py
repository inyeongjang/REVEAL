"""Tests for the PoC runner abstraction."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reveal.models import (
    Component,
    PocAttempt,
    PocCandidate,
    PocResult,
    ReproductionStatus,
    Vulnerability,
)
from reveal.reproduction import PocRunner


class FakePocRunner:
    """Minimal runner used to verify the shared interface."""

    def run(
        self,
        source: Path,
        vulnerability: Vulnerability,
        target_api: str,
        candidates: Sequence[PocCandidate],
        work_dir: Path,
    ) -> PocResult:
        del source

        work_dir.mkdir(parents=True, exist_ok=True)

        if not candidates:
            return PocResult(
                vulnerability_id=vulnerability.id,
                target_api=target_api,
                status=ReproductionStatus.SKIPPED,
                reason="No PoC candidates were provided.",
            )

        attempts: list[PocAttempt] = []

        for number, candidate in enumerate(candidates, start=1):
            reproduced = candidate.expected_signal in candidate.code

            attempts.append(
                PocAttempt(
                    number=number,
                    candidate=candidate,
                    exit_code=0 if reproduced else 1,
                    stdout=(
                        candidate.expected_signal
                        if reproduced
                        else ""
                    ),
                    reproduced=reproduced,
                )
            )

            if reproduced:
                return PocResult(
                    vulnerability_id=vulnerability.id,
                    target_api=target_api,
                    status=ReproductionStatus.REPRODUCED,
                    attempts=tuple(attempts),
                    evidence=(
                        f"Candidate {number} emitted the expected signal."
                    ),
                )

        return PocResult(
            vulnerability_id=vulnerability.id,
            target_api=target_api,
            status=ReproductionStatus.NOT_REPRODUCED,
            attempts=tuple(attempts),
            reason="No candidate emitted the expected signal.",
        )


def run_poc(
    runner: PocRunner,
    source: Path,
    vulnerability: Vulnerability,
    target_api: str,
    candidates: Sequence[PocCandidate],
    work_dir: Path,
) -> PocResult:
    """Execute any implementation satisfying the runner protocol."""

    return runner.run(
        source=source,
        vulnerability=vulnerability,
        target_api=target_api,
        candidates=candidates,
        work_dir=work_dir,
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


def create_candidate(
    *,
    code: str,
    expected_signal: str = "REVEAL_REPRODUCED",
) -> PocCandidate:
    return PocCandidate(
        language="javascript",
        code=code,
        expected_signal=expected_signal,
        description="Test PoC candidate.",
    )


def test_runner_accepts_structural_implementation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "reproduction"
    source.mkdir()

    result = run_poc(
        runner=FakePocRunner(),
        source=source,
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(
            create_candidate(
                code="console.log('REVEAL_REPRODUCED');",
            ),
        ),
        work_dir=work_dir,
    )

    assert result.status is ReproductionStatus.REPRODUCED
    assert result.vulnerability_id == "GHSA-xvch-5gv4-984h"
    assert result.target_api == "<module>"
    assert result.attempt_count == 1
    assert result.attempts[0].number == 1
    assert result.attempts[0].exit_code == 0
    assert result.attempts[0].reproduced is True
    assert result.evidence
    assert work_dir.is_dir()


def test_runner_stops_after_successful_candidate(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    result = run_poc(
        runner=FakePocRunner(),
        source=source,
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(
            create_candidate(
                code="console.error('failed');",
            ),
            create_candidate(
                code="console.log('REVEAL_REPRODUCED');",
            ),
            create_candidate(
                code="console.log('REVEAL_REPRODUCED');",
            ),
        ),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.REPRODUCED
    assert result.attempt_count == 2
    assert result.attempts[0].reproduced is False
    assert result.attempts[1].reproduced is True


def test_runner_returns_not_reproduced_after_all_failures(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    result = run_poc(
        runner=FakePocRunner(),
        source=source,
        vulnerability=create_vulnerability(),
        target_api="parse",
        candidates=(
            create_candidate(code="console.error('failed one');"),
            create_candidate(code="console.error('failed two');"),
        ),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.NOT_REPRODUCED
    assert result.attempt_count == 2
    assert all(
        not attempt.reproduced
        for attempt in result.attempts
    )
    assert result.reason


def test_runner_skips_empty_candidate_sequence(
    tmp_path: Path,
) -> None:
    result = run_poc(
        runner=FakePocRunner(),
        source=tmp_path / "project",
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.SKIPPED
    assert result.attempts == ()
    assert result.reason == "No PoC candidates were provided."