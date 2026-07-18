"""Tests for the SBOM generator abstraction."""

from pathlib import Path

from reveal.models import Sbom
from reveal.sbom import SbomGenerator


class FakeSbomGenerator:
    """Minimal generator used to verify the shared interface."""

    def generate(self, source: Path, output_path: Path) -> Sbom:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("{}", encoding="utf-8")

        return Sbom(
            format="test-json",
            generator="fake",
            document_path=output_path,
            components=(),
        )


def run_generator(
    generator: SbomGenerator,
    source: Path,
    output_path: Path,
) -> Sbom:
    """Execute any implementation satisfying the generator protocol."""

    return generator.generate(source, output_path)


def test_generator_protocol_accepts_structural_implementation(tmp_path: Path) -> None:
    source = tmp_path / "project"
    output_path = tmp_path / "output" / "sbom.json"
    source.mkdir()

    result = run_generator(
        FakeSbomGenerator(),
        source,
        output_path,
    )

    assert result.generator == "fake"
    assert result.document_path == output_path
    assert output_path.exists()