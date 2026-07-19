"""Normalized JSON analysis artifact generation."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from reveal.artifacts.base import VulnerabilityAnalysisView
from reveal.exceptions import ArtifactWriteError
from reveal.models import (
    ApiMappingResult,
    ApiMappingStatus,
    ApiUsage,
    Component,
    PocAttempt,
    PocCandidate,
    PocResult,
    ReachabilityStatus,
    ReproductionStatus,
    Sbom,
    ScanResult,
    TaintPath,
    TaintResult,
    VexStatement,
    VexStatus,
    Vulnerability,
)

_SCHEMA_VERSION = 1


class JsonAnalysisArtifactWriter:
    """Write complete REVEAL analysis evidence as normalized JSON."""

    def write(
        self,
        *,
        scan: ScanResult,
        usages: Sequence[ApiUsage],
        analyses: Sequence[VulnerabilityAnalysisView],
        output_path: Path,
        vex_path: Path | None = None,
        timestamp: datetime | None = None,
    ) -> Path:
        """Write one normalized analysis artifact."""

        normalized_usages = tuple(usages)
        normalized_analyses = tuple(analyses)
        generated_at = timestamp or datetime.now(timezone.utc)

        document: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "generated_at": _format_timestamp(generated_at),
            "tool": {
                "name": "REVEAL",
            },
            "summary": _serialize_summary(
                scan=scan,
                usages=normalized_usages,
                analyses=normalized_analyses,
            ),
            "scan": {
                "sbom": _serialize_sbom(scan.sbom),
                "vulnerabilities": [
                    _serialize_vulnerability(vulnerability)
                    for vulnerability in scan.vulnerabilities
                ],
            },
            "usages": [
                _serialize_usage(usage)
                for usage in normalized_usages
            ],
            "analyses": [
                _serialize_analysis(analysis)
                for analysis in normalized_analyses
            ],
            "outputs": {
                "openvex": (
                    str(vex_path)
                    if vex_path is not None
                    else None
                ),
            },
        }

        serialized = json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
        ) + "\n"

        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            output_path.write_text(
                serialized,
                encoding="utf-8",
            )
        except OSError as error:
            raise ArtifactWriteError(
                f"Failed to write analysis artifact: {output_path}"
            ) from error

        return output_path


def _serialize_summary(
    *,
    scan: ScanResult,
    usages: tuple[ApiUsage, ...],
    analyses: tuple[VulnerabilityAnalysisView, ...],
) -> dict[str, object]:
    vex_status_counts = {
        status.value: 0
        for status in VexStatus
    }

    for analysis in analyses:
        vex_status_counts[analysis.vex_statement.status.value] += 1

    return {
        "component_count": len(scan.sbom.components),
        "vulnerability_count": len(scan.vulnerabilities),
        "observed_usage_count": len(usages),
        "mapped_vulnerability_count": sum(
            analysis.mapping.status is ApiMappingStatus.MAPPED
            for analysis in analyses
        ),
        "reachable_target_count": sum(
            taint.status is ReachabilityStatus.REACHABLE
            for analysis in analyses
            for taint in analysis.taint_results
        ),
        "reproduced_target_count": sum(
            poc.status is ReproductionStatus.REPRODUCED
            for analysis in analyses
            for poc in analysis.poc_results
        ),
        "vex_status_counts": vex_status_counts,
    }


def _serialize_analysis(
    analysis: VulnerabilityAnalysisView,
) -> dict[str, object]:
    return {
        "vulnerability": _serialize_vulnerability(
            analysis.vulnerability
        ),
        "mapping": _serialize_mapping(analysis.mapping),
        "taint_results": [
            _serialize_taint_result(result)
            for result in analysis.taint_results
        ],
        "poc_results": [
            _serialize_poc_result(result)
            for result in analysis.poc_results
        ],
        "vex_statement": _serialize_vex_statement(
            analysis.vex_statement
        ),
    }


def _serialize_sbom(sbom: Sbom) -> dict[str, object]:
    return {
        "format": sbom.format,
        "generator": sbom.generator,
        "document_path": str(sbom.document_path),
        "components": [
            _serialize_component(component)
            for component in sbom.components
        ],
    }


def _serialize_component(
    component: Component,
) -> dict[str, object]:
    return {
        "name": component.name,
        "version": component.version,
        "ecosystem": component.ecosystem,
        "purl": component.purl,
    }


def _serialize_vulnerability(
    vulnerability: Vulnerability,
) -> dict[str, object]:
    return {
        "id": vulnerability.id,
        "aliases": list(vulnerability.aliases),
        "description": vulnerability.description,
        "severity": vulnerability.severity,
        "fixed_versions": list(vulnerability.fixed_versions),
        "urls": list(vulnerability.urls),
        "component": _serialize_component(
            vulnerability.component
        ),
    }


def _serialize_usage(
    usage: ApiUsage,
) -> dict[str, object]:
    return {
        "package": usage.package,
        "api": usage.api,
        "file": usage.file.as_posix(),
        "line": usage.line,
        "column": usage.column,
    }


def _serialize_mapping(
    mapping: ApiMappingResult,
) -> dict[str, object]:
    return {
        "vulnerability_id": mapping.vulnerability_id,
        "status": mapping.status.value,
        "target_apis": list(mapping.target_apis),
        "rationale": mapping.rationale,
        "confidence": mapping.confidence,
    }


def _serialize_taint_result(
    result: TaintResult,
) -> dict[str, object]:
    return {
        "vulnerability_id": result.vulnerability_id,
        "target_api": result.target_api,
        "status": result.status.value,
        "paths": [
            _serialize_taint_path(path)
            for path in result.paths
        ],
        "reason": result.reason,
    }


def _serialize_taint_path(
    path: TaintPath,
) -> dict[str, object]:
    return {
        "source_file": path.source_file.as_posix(),
        "source_line": path.source_line,
        "source": path.source,
        "sink_file": path.sink_file.as_posix(),
        "sink_line": path.sink_line,
        "sink": path.sink,
        "sink_argument": path.sink_argument,
        "steps": list(path.steps),
    }


def _serialize_poc_result(
    result: PocResult,
) -> dict[str, object]:
    return {
        "vulnerability_id": result.vulnerability_id,
        "target_api": result.target_api,
        "status": result.status.value,
        "attempts": [
            _serialize_poc_attempt(attempt)
            for attempt in result.attempts
        ],
        "evidence": result.evidence,
        "reason": result.reason,
    }


def _serialize_poc_attempt(
    attempt: PocAttempt,
) -> dict[str, object]:
    return {
        "number": attempt.number,
        "candidate": _serialize_poc_candidate(
            attempt.candidate
        ),
        "exit_code": attempt.exit_code,
        "stdout": attempt.stdout,
        "stderr": attempt.stderr,
        "timed_out": attempt.timed_out,
        "reproduced": attempt.reproduced,
        "error": attempt.error,
    }


def _serialize_poc_candidate(
    candidate: PocCandidate,
) -> dict[str, object]:
    return {
        "language": candidate.language,
        "code": candidate.code,
        "expected_signal": candidate.expected_signal,
        "description": candidate.description,
    }


def _serialize_vex_statement(
    statement: VexStatement,
) -> dict[str, object]:
    return {
        "vulnerability_id": statement.vulnerability_id,
        "products": list(statement.products),
        "status": statement.status.value,
        "justification": statement.justification,
        "impact_statement": statement.impact_statement,
        "action_statement": statement.action_statement,
    }


def _format_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ArtifactWriteError(
            "Analysis artifact timestamps must include timezone information."
        )

    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )