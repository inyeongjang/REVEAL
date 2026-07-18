"""Grype-based vulnerability scanner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, cast

from reveal.exceptions import VulnerabilityScanError
from reveal.models import Component, Sbom, ScanResult, Vulnerability


class GrypeVulnerabilityScanner:
    """Scan an SBOM and normalize Grype vulnerability findings."""

    def __init__(
        self,
        executable: str = "grype",
        timeout_seconds: int = 300,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def scan(self, sbom: Sbom, output_path: Path) -> ScanResult:
        """Scan an SBOM document and return normalized findings."""

        if not sbom.document_path.is_file():
            raise VulnerabilityScanError(
                f"SBOM document does not exist: {sbom.document_path}"
            )

        output_path.parent.mkdir(parents=True, exist_ok=True)

        command = [
            self.executable,
            f"sbom:{sbom.document_path}",
            "--quiet",
            "--output",
            "json",
            "--file",
            str(output_path),
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError as error:
            raise VulnerabilityScanError(
                f"Grype executable was not found: {self.executable}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise VulnerabilityScanError(
                f"Grype timed out after {self.timeout_seconds} seconds"
            ) from error
        except OSError as error:
            raise VulnerabilityScanError(
                f"Failed to execute Grype: {error}"
            ) from error

        if result.returncode != 0:
            message = (
                result.stderr.strip()
                or result.stdout.strip()
                or "unknown error"
            )
            raise VulnerabilityScanError(
                f"Grype failed with exit code {result.returncode}: {message}"
            )

        if not output_path.is_file():
            raise VulnerabilityScanError(
                f"Grype completed without creating a report: {output_path}"
            )

        return self._parse(sbom, output_path)

    @staticmethod
    def _parse(sbom: Sbom, report_path: Path) -> ScanResult:
        """Parse a Grype JSON report into the shared domain model."""

        document = _read_json_object(report_path)
        raw_matches = document.get("matches", [])

        if not isinstance(raw_matches, list):
            raise VulnerabilityScanError(
                "Invalid Grype report: matches must be an array"
            )

        vulnerabilities: list[Vulnerability] = []

        for raw_match in raw_matches:
            if not isinstance(raw_match, dict):
                continue

            vulnerability = _normalize_match(
                cast(dict[str, Any], raw_match),
                sbom,
            )

            if vulnerability is not None:
                vulnerabilities.append(vulnerability)

        return ScanResult(
            sbom=sbom,
            vulnerabilities=tuple(vulnerabilities),
        )


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise VulnerabilityScanError(
            f"Failed to read Grype report: {path}"
        ) from error
    except json.JSONDecodeError as error:
        raise VulnerabilityScanError(
            f"Grype produced invalid JSON: {path}"
        ) from error

    if not isinstance(value, dict):
        raise VulnerabilityScanError(
            "Invalid Grype report: root value must be an object"
        )

    return cast(dict[str, Any], value)


def _normalize_match(
    match: dict[str, Any],
    sbom: Sbom,
) -> Vulnerability | None:
    raw_vulnerability = match.get("vulnerability")
    raw_artifact = match.get("artifact")

    if not isinstance(raw_vulnerability, dict):
        return None

    if not isinstance(raw_artifact, dict):
        return None

    vulnerability_data = cast(dict[str, Any], raw_vulnerability)
    artifact_data = cast(dict[str, Any], raw_artifact)

    vulnerability_id = _optional_string(vulnerability_data.get("id"))

    if vulnerability_id is None:
        return None

    component = _resolve_component(artifact_data, sbom)

    if component is None:
        return None

    aliases = _extract_aliases(
        primary_id=vulnerability_id,
        related=match.get("relatedVulnerabilities"),
    )

    return Vulnerability(
        id=vulnerability_id,
        component=component,
        aliases=aliases,
        description=_string_or_empty(
            vulnerability_data.get("description")
        ),
        severity=_optional_string(
            vulnerability_data.get("severity")
        ),
        fixed_versions=_extract_fixed_versions(
            vulnerability_data.get("fix")
        ),
        urls=_extract_urls(vulnerability_data),
    )


def _resolve_component(
    artifact: dict[str, Any],
    sbom: Sbom,
) -> Component | None:
    name = _optional_string(artifact.get("name"))

    if name is None:
        return None

    version = _string_or_empty(artifact.get("version"))
    purl = _optional_string(artifact.get("purl"))

    if purl is not None:
        for component in sbom.components:
            if component.purl == purl:
                return component

    for component in sbom.components:
        if component.name == name and component.version == version:
            return component

    artifact_type = _optional_string(artifact.get("type"))

    return Component(
        name=name,
        version=version,
        ecosystem=_extract_ecosystem(purl, artifact_type),
        purl=purl,
    )


def _extract_aliases(
    primary_id: str,
    related: object,
) -> tuple[str, ...]:
    if not isinstance(related, list):
        return ()

    aliases: list[str] = []

    for item in related:
        if not isinstance(item, dict):
            continue

        related_id = _optional_string(item.get("id"))

        if (
            related_id is not None
            and related_id != primary_id
            and related_id not in aliases
        ):
            aliases.append(related_id)

    return tuple(aliases)


def _extract_fixed_versions(fix: object) -> tuple[str, ...]:
    if not isinstance(fix, dict):
        return ()

    versions = fix.get("versions")

    if not isinstance(versions, list):
        return ()

    return tuple(
        version
        for version in versions
        if isinstance(version, str) and version
    )


def _extract_urls(
    vulnerability: dict[str, Any],
) -> tuple[str, ...]:
    urls: list[str] = []
    raw_urls = vulnerability.get("urls")

    if isinstance(raw_urls, list):
        for value in raw_urls:
            if isinstance(value, str) and value and value not in urls:
                urls.append(value)

    data_source = _optional_string(
        vulnerability.get("dataSource")
    )

    if data_source is not None and data_source not in urls:
        urls.append(data_source)

    return tuple(urls)


def _extract_ecosystem(
    purl: str | None,
    artifact_type: str | None,
) -> str:
    if purl is not None and purl.startswith("pkg:"):
        package_type = purl.removeprefix("pkg:").split("/", maxsplit=1)[0]

        if package_type:
            return package_type

    return artifact_type or "unknown"


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value

    return None


def _string_or_empty(value: object) -> str:
    if isinstance(value, str):
        return value

    return ""