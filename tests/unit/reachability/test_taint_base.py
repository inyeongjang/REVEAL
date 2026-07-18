"""Tests for the taint reachability analyzer abstraction."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reveal.models import (
    ApiUsage,
    Component,
    ReachabilityStatus,
    TaintResult,
    Vulnerability,
)
from reveal.reachability import TaintAnalyzer


class FakeTaintAnalyzer:
    """Minimal analyzer used to verify the shared interface."""

    def analyze(
        self,
        source: Path,
        vulnerability: Vulnerability,
        targets: Sequence[ApiUsage],
        work_dir: Path,
    ) -> tuple[TaintResult, ...]:
        if not source.is_dir():
            return ()

        work_dir.mkdir(parents=True, exist_ok=True)

        target_apis: list[str] = []

        for target in targets:
            if target.api not in target_apis:
                target_apis.append(target.api)

        return tuple(
            TaintResult(
                vulnerability_id=vulnerability.id,
                target_api=target_api,
                status=ReachabilityStatus.UNKNOWN,
                reason="Fake analyzer does not perform data-flow analysis.",
            )
            for target_api in target_apis
        )


def run_analyzer(
    analyzer: TaintAnalyzer,
    source: Path,
    vulnerability: Vulnerability,
    targets: Sequence[ApiUsage],
    work_dir: Path,
) -> tuple[TaintResult, ...]:
    """Execute any implementation satisfying the analyzer protocol."""

    return analyzer.analyze(
        source=source,
        vulnerability=vulnerability,
        targets=targets,
        work_dir=work_dir,
    )


def create_vulnerability() -> Vulnerability:
    component = Component(
        name="minimist",
        version="0.0.8",
        ecosystem="npm",
        purl="pkg:npm/minimist@0.0.8",
    )

    return Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        component=component,
        aliases=("CVE-2021-44906",),
        description="Prototype pollution in minimist.",
    )


def test_taint_analyzer_accepts_structural_implementation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "reachability"
    source.mkdir()

    targets = (
        ApiUsage(
            package="minimist",
            api="<module>",
            file=Path("src/routes/arguments.js"),
            line=13,
            column=12,
        ),
        ApiUsage(
            package="minimist",
            api="<module>",
            file=Path("src/routes/other.js"),
            line=8,
            column=5,
        ),
    )

    results = run_analyzer(
        analyzer=FakeTaintAnalyzer(),
        source=source,
        vulnerability=create_vulnerability(),
        targets=targets,
        work_dir=work_dir,
    )

    assert len(results) == 1
    assert results[0].vulnerability_id == "GHSA-xvch-5gv4-984h"
    assert results[0].target_api == "<module>"
    assert results[0].status is ReachabilityStatus.UNKNOWN
    assert work_dir.is_dir()


def test_taint_analyzer_accepts_multiple_target_apis(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    targets = (
        ApiUsage(
            package="minimist",
            api="<module>",
            file=Path("src/app.js"),
            line=10,
        ),
        ApiUsage(
            package="minimist",
            api="parse",
            file=Path("src/app.js"),
            line=15,
        ),
    )

    results = run_analyzer(
        analyzer=FakeTaintAnalyzer(),
        source=source,
        vulnerability=create_vulnerability(),
        targets=targets,
        work_dir=tmp_path / "reachability",
    )

    assert tuple(result.target_api for result in results) == (
        "<module>",
        "parse",
    )


def test_taint_analyzer_accepts_empty_target_list(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    source.mkdir()

    results = run_analyzer(
        analyzer=FakeTaintAnalyzer(),
        source=source,
        vulnerability=create_vulnerability(),
        targets=(),
        work_dir=tmp_path / "reachability",
    )

    assert results == ()