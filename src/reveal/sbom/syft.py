"""Syft-based SBOM generator."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, cast

from reveal.exceptions import SbomGenerationError
from reveal.models import Component, Sbom


class SyftSbomGenerator:
    """Generate and normalize CycloneDX JSON SBOMs using Syft."""

    def __init__(
        self,
        executable: str = "syft",
        timeout_seconds: int = 300,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def generate(self, source: Path, output_path: Path) -> Sbom:
        """Generate a CycloneDX JSON SBOM for a source directory."""

        if not source.exists():
            raise SbomGenerationError(f"SBOM source does not exist: {source}")

        if not source.is_dir():
            raise SbomGenerationError(f"SBOM source is not a directory: {source}")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        command = [
            self.executable,
            "scan",
            str(source),
            "--quiet",
            "--output",
            f"cyclonedx-json={output_path}",
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
            raise SbomGenerationError(
                f"Syft executable was not found: {self.executable}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise SbomGenerationError(
                f"Syft timed out after {self.timeout_seconds} seconds"
            ) from error
        except OSError as error:
            raise SbomGenerationError(f"Failed to execute Syft: {error}") from error

        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "unknown error"
            raise SbomGenerationError(
                f"Syft failed with exit code {result.returncode}: {message}"
            )

        if not output_path.is_file():
            raise SbomGenerationError(
                f"Syft completed without creating the SBOM: {output_path}"
            )

        return self._parse(output_path)

    @staticmethod
    def _parse(document_path: Path) -> Sbom:
        """Parse a CycloneDX JSON document into the shared SBOM model."""

        document = _read_json_object(document_path)
        raw_components = document.get("components", [])

        if not isinstance(raw_components, list):
            raise SbomGenerationError(
                "Invalid CycloneDX document: components must be an array"
            )

        components: list[Component] = []

        for raw_component in raw_components:
            if not isinstance(raw_component, dict):
                continue

            component = _normalize_component(
                cast(dict[str, Any], raw_component)
            )

            if component is not None:
                components.append(component)

        return Sbom(
            format="cyclonedx-json",
            generator="syft",
            document_path=document_path,
            components=tuple(components),
        )


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise SbomGenerationError(f"Failed to read SBOM document: {path}") from error
    except json.JSONDecodeError as error:
        raise SbomGenerationError(
            f"Syft produced invalid JSON: {path}"
        ) from error

    if not isinstance(value, dict):
        raise SbomGenerationError(
            "Invalid CycloneDX document: root value must be an object"
        )

    return cast(dict[str, Any], value)


def _normalize_component(data: dict[str, Any]) -> Component | None:
    name = data.get("name")

    if not isinstance(name, str) or not name:
        return None

    raw_version = data.get("version")
    version = raw_version if isinstance(raw_version, str) else ""

    raw_purl = data.get("purl")
    purl = raw_purl if isinstance(raw_purl, str) and raw_purl else None

    return Component(
        name=name,
        version=version,
        ecosystem=_ecosystem_from_purl(purl),
        purl=purl,
    )


def _ecosystem_from_purl(purl: str | None) -> str:
    if purl is None or not purl.startswith("pkg:"):
        return "unknown"

    package_type = purl.removeprefix("pkg:").split("/", maxsplit=1)[0]
    package_type = package_type.split("@", maxsplit=1)[0]

    return package_type or "unknown"