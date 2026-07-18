"""Tests for the package usage analyzer abstraction."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from reveal.models import ApiUsage
from reveal.reachability import UsageAnalyzer


class FakeUsageAnalyzer:
    """Minimal analyzer used to verify the shared interface."""

    def analyze(
        self,
        source: Path,
        packages: Sequence[str],
        work_dir: Path,
    ) -> tuple[ApiUsage, ...]:
        work_dir.mkdir(parents=True, exist_ok=True)

        return tuple(
            ApiUsage(
                package=package,
                api=f"{package}.example",
                file=source / "app.js",
                line=index,
            )
            for index, package in enumerate(packages, start=1)
        )


def run_analyzer(
    analyzer: UsageAnalyzer,
    source: Path,
    packages: Sequence[str],
    work_dir: Path,
) -> tuple[ApiUsage, ...]:
    """Execute any implementation satisfying the usage analyzer protocol."""

    return analyzer.analyze(
        source=source,
        packages=packages,
        work_dir=work_dir,
    )


def test_usage_analyzer_accepts_structural_implementation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    usages = run_analyzer(
        analyzer=FakeUsageAnalyzer(),
        source=source,
        packages=("minimist", "lodash"),
        work_dir=work_dir,
    )

    assert len(usages) == 2
    assert usages[0].package == "minimist"
    assert usages[0].api == "minimist.example"
    assert usages[0].file == source / "app.js"
    assert usages[0].line == 1
    assert usages[1].package == "lodash"
    assert work_dir.is_dir()


def test_usage_analyzer_accepts_empty_package_list(
    tmp_path: Path,
) -> None:
    source = tmp_path / "project"
    work_dir = tmp_path / "analysis"
    source.mkdir()

    usages = run_analyzer(
        analyzer=FakeUsageAnalyzer(),
        source=source,
        packages=(),
        work_dir=work_dir,
    )

    assert usages == ()