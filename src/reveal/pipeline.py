"""End-to-end REVEAL analysis pipeline orchestration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from reveal.exceptions import PipelineError
from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    ApiUsage,
    PocResult,
    ReachabilityStatus,
    ScanResult,
    TaintResult,
    VexStatement,
    Vulnerability,
)
from reveal.reachability import (
    TaintAnalyzer,
    UsageAnalyzer,
    VulnerableApiSelector,
)
from reveal.reproduction import PocGenerator, PocRunner
from reveal.sbom import SbomGenerator
from reveal.vex import VexDecisionPolicy, VexWriter
from reveal.vulnerabilities import VulnerabilityScanner


@dataclass(frozen=True, slots=True)
class VulnerabilityAnalysis:
    """All normalized evidence produced for one vulnerability."""

    vulnerability: Vulnerability
    mapping: ApiMappingResult
    taint_results: tuple[TaintResult, ...]
    poc_results: tuple[PocResult, ...]
    vex_statement: VexStatement


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Complete result of one REVEAL pipeline execution."""

    scan: ScanResult
    usages: tuple[ApiUsage, ...]
    analyses: tuple[VulnerabilityAnalysis, ...]
    vex_path: Path | None = None

    @property
    def vulnerability_count(self) -> int:
        """Return the number of analyzed vulnerabilities."""

        return len(self.analyses)


class AnalysisPipeline:
    """Coordinate all REVEAL analysis stages."""

    def __init__(
        self,
        *,
        sbom_generator: SbomGenerator,
        vulnerability_scanner: VulnerabilityScanner,
        usage_analyzer: UsageAnalyzer,
        api_selector: VulnerableApiSelector,
        taint_analyzer: TaintAnalyzer,
        poc_generator: PocGenerator,
        poc_runner: PocRunner,
        vex_policy: VexDecisionPolicy,
        vex_writer: VexWriter,
        max_poc_candidates: int = 3,
    ) -> None:
        if max_poc_candidates < 1:
            raise ValueError("max_poc_candidates must be at least one")

        self.sbom_generator = sbom_generator
        self.vulnerability_scanner = vulnerability_scanner
        self.usage_analyzer = usage_analyzer
        self.api_selector = api_selector
        self.taint_analyzer = taint_analyzer
        self.poc_generator = poc_generator
        self.poc_runner = poc_runner
        self.vex_policy = vex_policy
        self.vex_writer = vex_writer
        self.max_poc_candidates = max_poc_candidates

    def run(
        self,
        *,
        source: Path,
        work_dir: Path,
        vex_output_path: Path,
    ) -> PipelineResult:
        """Run all applicable analysis stages for the target project."""

        if not source.is_dir():
            raise PipelineError(
                f"Source directory does not exist: {source}"
            )

        _create_directory(work_dir)

        sbom = self.sbom_generator.generate(
            source=source,
            output_path=work_dir / "sbom.cdx.json",
        )
        scan = self.vulnerability_scanner.scan(
            sbom=sbom,
            output_path=work_dir / "grype.json",
        )

        packages = _vulnerable_packages(scan)

        if packages:
            usages = self.usage_analyzer.analyze(
                source=source,
                packages=packages,
                work_dir=work_dir / "usage",
            )
        else:
            usages = ()

        analyses: list[VulnerabilityAnalysis] = []

        for vulnerability_index, vulnerability in enumerate(
            scan.vulnerabilities,
            start=1,
        ):
            vulnerability_dir = (
                work_dir
                / "vulnerabilities"
                / (
                    f"{vulnerability_index:03d}-"
                    f"{_safe_path_segment(vulnerability.id)}"
                )
            )

            analysis = self._analyze_vulnerability(
                source=source,
                vulnerability=vulnerability,
                usages=usages,
                work_dir=vulnerability_dir,
            )
            analyses.append(analysis)

        normalized_analyses = tuple(analyses)
        vex_path: Path | None = None

        if normalized_analyses:
            vex_path = self.vex_writer.write(
                statements=tuple(
                    analysis.vex_statement
                    for analysis in normalized_analyses
                ),
                output_path=vex_output_path,
            )

        return PipelineResult(
            scan=scan,
            usages=usages,
            analyses=normalized_analyses,
            vex_path=vex_path,
        )

    def _analyze_vulnerability(
        self,
        *,
        source: Path,
        vulnerability: Vulnerability,
        usages: tuple[ApiUsage, ...],
        work_dir: Path,
    ) -> VulnerabilityAnalysis:
        mapping = self.api_selector.select(
            vulnerability=vulnerability,
            usages=usages,
        )

        target_usages = _select_target_usages(
            vulnerability=vulnerability,
            mapping=mapping,
            usages=usages,
        )

        taint_results: tuple[TaintResult, ...] = ()

        if (
            mapping.status is ApiMappingStatus.MAPPED
            and target_usages
        ):
            taint_results = self.taint_analyzer.analyze(
                source=source,
                vulnerability=vulnerability,
                targets=target_usages,
                work_dir=work_dir / "taint",
            )

        poc_results = self._reproduce_reachable_targets(
            source=source,
            vulnerability=vulnerability,
            taint_results=taint_results,
            work_dir=work_dir / "reproduction",
        )

        vex_statement = self.vex_policy.decide(
            vulnerability=vulnerability,
            mapping=mapping,
            taint_results=taint_results,
            poc_results=poc_results,
        )

        return VulnerabilityAnalysis(
            vulnerability=vulnerability,
            mapping=mapping,
            taint_results=taint_results,
            poc_results=poc_results,
            vex_statement=vex_statement,
        )

    def _reproduce_reachable_targets(
        self,
        *,
        source: Path,
        vulnerability: Vulnerability,
        taint_results: tuple[TaintResult, ...],
        work_dir: Path,
    ) -> tuple[PocResult, ...]:
        poc_results: list[PocResult] = []

        for taint_index, taint_result in enumerate(
            taint_results,
            start=1,
        ):
            if taint_result.status is not ReachabilityStatus.REACHABLE:
                continue

            candidates = self.poc_generator.generate(
                source=source,
                vulnerability=vulnerability,
                taint=taint_result,
                max_candidates=self.max_poc_candidates,
            )

            poc_result = self.poc_runner.run(
                source=source,
                vulnerability=vulnerability,
                target_api=taint_result.target_api,
                candidates=candidates,
                work_dir=work_dir / f"{taint_index:03d}",
            )
            poc_results.append(poc_result)

        return tuple(poc_results)


def _vulnerable_packages(
    scan: ScanResult,
) -> tuple[str, ...]:
    packages: list[str] = []

    for vulnerability in scan.vulnerabilities:
        package = vulnerability.component.name

        if package not in packages:
            packages.append(package)

    return tuple(packages)


def _select_target_usages(
    *,
    vulnerability: Vulnerability,
    mapping: ApiMappingResult,
    usages: tuple[ApiUsage, ...],
) -> tuple[ApiUsage, ...]:
    if mapping.status is not ApiMappingStatus.MAPPED:
        return ()

    target_apis = set(mapping.target_apis)

    return tuple(
        usage
        for usage in usages
        if (
            usage.package == vulnerability.component.name
            and usage.api in target_apis
        )
    )


def _safe_path_segment(value: str) -> str:
    normalized = re.sub(
        r"[^A-Za-z0-9._-]+",
        "-",
        value,
    ).strip("-._")

    return (normalized or "vulnerability")[:80]


def _create_directory(path: Path) -> None:
    try:
        path.mkdir(
            parents=True,
            exist_ok=True,
        )
    except OSError as error:
        raise PipelineError(
            f"Failed to create pipeline working directory: {path}"
        ) from error