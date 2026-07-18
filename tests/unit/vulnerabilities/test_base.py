"""Tests for the vulnerability scanner abstraction."""

from pathlib import Path

from reveal.models import Component, Sbom, ScanResult, Vulnerability
from reveal.vulnerabilities import VulnerabilityScanner


class FakeVulnerabilityScanner:
    """Minimal scanner used to verify the shared interface."""

    def scan(self, sbom: Sbom, output_path: Path) -> ScanResult:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("{}", encoding="utf-8")

        component = sbom.components[0]
        vulnerability = Vulnerability(
            id="TEST-2026-0001",
            component=component,
            description="Test vulnerability",
        )

        return ScanResult(
            sbom=sbom,
            vulnerabilities=(vulnerability,),
        )


def run_scanner(
    scanner: VulnerabilityScanner,
    sbom: Sbom,
    output_path: Path,
) -> ScanResult:
    """Execute any implementation satisfying the scanner protocol."""

    return scanner.scan(sbom, output_path)


def test_scanner_protocol_accepts_structural_implementation(
    tmp_path: Path,
) -> None:
    component = Component(
        name="example-package",
        version="1.0.0",
        ecosystem="npm",
        purl="pkg:npm/example-package@1.0.0",
    )
    sbom = Sbom(
        format="cyclonedx-json",
        generator="fake",
        document_path=tmp_path / "sbom.json",
        components=(component,),
    )
    output_path = tmp_path / "vulnerabilities.json"

    result = run_scanner(
        FakeVulnerabilityScanner(),
        sbom,
        output_path,
    )

    assert result.sbom == sbom
    assert result.finding_count == 1
    assert result.vulnerabilities[0].id == "TEST-2026-0001"
    assert result.vulnerabilities[0].component == component
    assert output_path.exists()