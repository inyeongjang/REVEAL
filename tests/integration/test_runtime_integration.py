"""Integration tests for configured REVEAL runtime execution."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

import reveal.cli as cli
import reveal.default_builders as default_builders
from reveal.bootstrap import bootstrap_runtime
from reveal.config import (
    AnalysisConfig,
    LlmConfig,
    LlmProvider,
    RuntimeConfig,
    ToolConfig,
)
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
    VexStatus,
    Vulnerability,
)


def create_vulnerability() -> Vulnerability:
    """Create one deterministic vulnerable component."""

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
        fixed_versions=("1.2.6",),
    )


def create_candidate() -> PocCandidate:
    """Create one deterministic PoC candidate."""

    return PocCandidate(
        language="javascript",
        code=(
            "console.log('REVEAL_REPRODUCED');\n"
        ),
        expected_signal="REVEAL_REPRODUCED",
        description="Emit the expected reproduction signal.",
    )


def install_fake_adapters(
    monkeypatch: pytest.MonkeyPatch,
    *,
    vulnerability: Vulnerability,
    records: dict[str, object],
) -> None:
    """Replace external adapters with deterministic implementations."""

    class FakeOllamaLlmClient:
        def __init__(
            self,
            *,
            model: str,
            endpoint: str,
            timeout_seconds: float,
        ) -> None:
            records["llm_client"] = self
            records["llm_model"] = model
            records["llm_endpoint"] = endpoint
            records["llm_timeout"] = timeout_seconds

    class FakeCodeQLClient:
        def __init__(
            self,
            executable: str,
            timeout_seconds: int,
        ) -> None:
            records["codeql_client"] = self
            records["codeql_executable"] = executable
            records["codeql_timeout"] = timeout_seconds

    class FakeSyftSbomGenerator:
        def __init__(
            self,
            executable: str = "syft",
            timeout_seconds: int = 300,
        ) -> None:
            records["syft_executable"] = executable
            records["syft_timeout"] = timeout_seconds

        def generate(
            self,
            source: Path,
            output_path: Path,
        ) -> Sbom:
            records["sbom_source"] = source

            output_path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                    }
                ),
                encoding="utf-8",
            )

            return Sbom(
                format="cyclonedx-json",
                generator="fake-syft",
                document_path=output_path,
                components=(vulnerability.component,),
            )

    class FakeGrypeVulnerabilityScanner:
        def __init__(
            self,
            executable: str = "grype",
            timeout_seconds: int = 300,
        ) -> None:
            records["grype_executable"] = executable
            records["grype_timeout"] = timeout_seconds

        def scan(
            self,
            sbom: Sbom,
            output_path: Path,
        ) -> ScanResult:
            records["scanner_sbom"] = sbom

            output_path.write_text(
                json.dumps(
                    {
                        "matches": [
                            {
                                "vulnerability": {
                                    "id": vulnerability.id,
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            return ScanResult(
                sbom=sbom,
                vulnerabilities=(vulnerability,),
            )

    class FakeCodeQLUsageAnalyzer:
        def __init__(
            self,
            client: FakeCodeQLClient | None = None,
        ) -> None:
            records["usage_codeql_client"] = client

        def analyze(
            self,
            source: Path,
            packages: Sequence[str],
            work_dir: Path,
        ) -> tuple[ApiUsage, ...]:
            records["usage_source"] = source
            records["usage_packages"] = tuple(packages)
            records["usage_work_dir"] = work_dir

            return (
                ApiUsage(
                    package="minimist",
                    api="<module>",
                    file=Path("src/app.js"),
                    line=10,
                    column=5,
                ),
            )

    class FakeLlmVulnerableApiSelector:
        def __init__(
            self,
            client: object,
            retriever: object | None = None,
            evidence_limit: int = 5,
        ) -> None:
            records["selector_llm_client"] = client
            records["selector_retriever"] = retriever
            records["selector_evidence_limit"] = (
                evidence_limit
            )

        def select(
            self,
            vulnerability: Vulnerability,
            usages: Sequence[ApiUsage],
        ) -> ApiMappingResult:
            records["selector_usages"] = tuple(usages)

            return ApiMappingResult(
                vulnerability_id=vulnerability.id,
                status=ApiMappingStatus.MAPPED,
                target_apis=("<module>",),
                rationale=(
                    "The observed module call reaches the "
                    "vulnerable package entry point."
                ),
                confidence=0.95,
            )

    class FakeCodeQLTaintAnalyzer:
        def __init__(
            self,
            client: FakeCodeQLClient,
        ) -> None:
            records["taint_codeql_client"] = client

        def analyze(
            self,
            source: Path,
            vulnerability: Vulnerability,
            targets: Sequence[ApiUsage],
            work_dir: Path,
        ) -> tuple[TaintResult, ...]:
            records["taint_source"] = source
            records["taint_targets"] = tuple(targets)
            records["taint_work_dir"] = work_dir

            return (
                TaintResult(
                    vulnerability_id=vulnerability.id,
                    target_api="<module>",
                    status=ReachabilityStatus.REACHABLE,
                    paths=(
                        TaintPath(
                            source_file=Path("src/app.js"),
                            source_line=5,
                            source="request.query",
                            sink_file=Path("src/app.js"),
                            sink_line=10,
                            sink="minimist(request.query)",
                            sink_argument=0,
                            steps=(
                                "request.query",
                                "minimist(request.query)",
                            ),
                        ),
                    ),
                ),
            )

    class FakeLlmPocGenerator:
        def __init__(
            self,
            client: object,
        ) -> None:
            records["generator_llm_client"] = client

        def generate(
            self,
            source: Path,
            vulnerability: Vulnerability,
            taint: TaintResult,
            *,
            max_candidates: int = 3,
        ) -> tuple[PocCandidate, ...]:
            records["generator_source"] = source
            records["generator_vulnerability"] = (
                vulnerability.id
            )
            records["generator_target_api"] = (
                taint.target_api
            )
            records["generator_max_candidates"] = (
                max_candidates
            )

            return (create_candidate(),)

    class FakeDockerPocRunner:
        def __init__(
            self,
            *,
            image: str = "node:22-bookworm-slim",
            executable: str = "docker",
            timeout_seconds: float = 30.0,
            memory_limit: str = "256m",
            cpu_limit: float = 1.0,
            pids_limit: int = 64,
            max_output_chars: int = 65_536,
        ) -> None:
            records["docker_image"] = image
            records["docker_executable"] = executable
            records["docker_timeout"] = timeout_seconds
            records["docker_memory"] = memory_limit
            records["docker_cpu"] = cpu_limit
            records["docker_pids"] = pids_limit
            records["docker_output_limit"] = (
                max_output_chars
            )

        def run(
            self,
            source: Path,
            vulnerability: Vulnerability,
            target_api: str,
            candidates: Sequence[PocCandidate],
            work_dir: Path,
        ) -> PocResult:
            normalized_candidates = tuple(candidates)
            candidate = normalized_candidates[0]

            records["runner_source"] = source
            records["runner_target_api"] = target_api
            records["runner_candidates"] = (
                normalized_candidates
            )
            records["runner_work_dir"] = work_dir

            attempt = PocAttempt(
                number=1,
                candidate=candidate,
                exit_code=0,
                stdout=(
                    f"{candidate.expected_signal}\n"
                ),
                stderr="",
                reproduced=True,
            )

            return PocResult(
                vulnerability_id=vulnerability.id,
                target_api=target_api,
                status=ReproductionStatus.REPRODUCED,
                attempts=(attempt,),
                evidence=(
                    "The expected reproduction signal "
                    "was observed."
                ),
            )

    monkeypatch.setattr(
        default_builders,
        "OllamaLlmClient",
        FakeOllamaLlmClient,
    )
    monkeypatch.setattr(
        default_builders,
        "CodeQLClient",
        FakeCodeQLClient,
    )
    monkeypatch.setattr(
        default_builders,
        "SyftSbomGenerator",
        FakeSyftSbomGenerator,
    )
    monkeypatch.setattr(
        default_builders,
        "GrypeVulnerabilityScanner",
        FakeGrypeVulnerabilityScanner,
    )
    monkeypatch.setattr(
        default_builders,
        "CodeQLUsageAnalyzer",
        FakeCodeQLUsageAnalyzer,
    )
    monkeypatch.setattr(
        default_builders,
        "LlmVulnerableApiSelector",
        FakeLlmVulnerableApiSelector,
    )
    monkeypatch.setattr(
        default_builders,
        "CodeQLTaintAnalyzer",
        FakeCodeQLTaintAnalyzer,
    )
    monkeypatch.setattr(
        default_builders,
        "LlmPocGenerator",
        FakeLlmPocGenerator,
    )
    monkeypatch.setattr(
        default_builders,
        "DockerPocRunner",
        FakeDockerPocRunner,
    )


def create_runtime_config(
    *,
    tools: ToolConfig | None = None,
) -> RuntimeConfig:
    """Create an Ollama configuration without PoC refinement."""

    return RuntimeConfig(
        llm=LlmConfig(
            provider=LlmProvider.OLLAMA,
            model="integration-test-model",
            ollama_base_url="http://127.0.0.1:11434",
            timeout_seconds=45.0,
        ),
        tools=tools or ToolConfig(),
        analysis=AnalysisConfig(
            retrieval_top_k=7,
            max_poc_candidates=2,
            max_poc_refinement_rounds=2,
            enable_poc_refinement=False,
        ),
    )


def create_executable(
    path: Path,
) -> Path:
    """Create one executable shell stub."""

    path.write_text(
        "#!/bin/sh\nexit 0\n",
        encoding="utf-8",
    )
    path.chmod(0o755)

    return path


def test_default_runtime_executes_complete_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerability = create_vulnerability()
    records: dict[str, object] = {}

    install_fake_adapters(
        monkeypatch,
        vulnerability=vulnerability,
        records=records,
    )

    config = create_runtime_config()
    runtime = bootstrap_runtime(
        config=config,
        component_factory=(
            default_builders
            .create_default_runtime_component_factory()
        ),
        document_id="urn:uuid:integration-test",
    )

    source = tmp_path / "project"
    source.mkdir()
    (source / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "minimist": "0.0.8",
                }
            }
        ),
        encoding="utf-8",
    )

    work_dir = tmp_path / "work"
    vex_path = work_dir / "openvex.json"
    analysis_path = work_dir / "analysis.json"

    result = runtime.pipeline.run(
        source=source,
        work_dir=work_dir,
        vex_output_path=vex_path,
        analysis_output_path=analysis_path,
    )

    assert result.vulnerability_count == 1
    assert len(result.analyses) == 1

    analysis = result.analyses[0]

    assert analysis.mapping.status is (
        ApiMappingStatus.MAPPED
    )
    assert analysis.taint_results[0].status is (
        ReachabilityStatus.REACHABLE
    )
    assert analysis.poc_results[0].status is (
        ReproductionStatus.REPRODUCED
    )
    assert analysis.vex_statement.status is (
        VexStatus.AFFECTED
    )

    assert result.vex_path == vex_path
    assert result.artifact_path == analysis_path

    assert vex_path.is_file()
    assert analysis_path.is_file()
    assert (work_dir / "sbom.cdx.json").is_file()
    assert (work_dir / "grype.json").is_file()

    vex_document = json.loads(
        vex_path.read_text(encoding="utf-8")
    )
    analysis_document = json.loads(
        analysis_path.read_text(encoding="utf-8")
    )

    assert isinstance(vex_document, dict)
    assert isinstance(analysis_document, dict)

    assert records["usage_codeql_client"] is (
        records["taint_codeql_client"]
    )
    assert records["usage_codeql_client"] is (
        records["codeql_client"]
    )

    assert records["selector_llm_client"] is (
        records["generator_llm_client"]
    )
    assert records["selector_llm_client"] is (
        records["llm_client"]
    )

    assert records["usage_packages"] == ("minimist",)
    assert records["selector_evidence_limit"] == 7
    assert records["generator_max_candidates"] == 2


def test_analyze_cli_executes_default_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vulnerability = create_vulnerability()
    records: dict[str, object] = {}

    install_fake_adapters(
        monkeypatch,
        vulnerability=vulnerability,
        records=records,
    )

    source = tmp_path / "project"
    source.mkdir()
    (source / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "minimist": "0.0.8",
                }
            }
        ),
        encoding="utf-8",
    )

    executable_dir = tmp_path / "tools"
    executable_dir.mkdir()

    syft_path = create_executable(
        executable_dir / "syft"
    )
    grype_path = create_executable(
        executable_dir / "grype"
    )
    codeql_path = create_executable(
        executable_dir / "codeql"
    )
    docker_path = create_executable(
        executable_dir / "docker"
    )

    monkeypatch.setenv(
        "REVEAL_LLM_PROVIDER",
        "ollama",
    )
    monkeypatch.setenv(
        "REVEAL_LLM_MODEL",
        "integration-test-model",
    )
    monkeypatch.setenv(
        "REVEAL_ENABLE_POC_REFINEMENT",
        "false",
    )
    monkeypatch.setenv(
        "REVEAL_SYFT_PATH",
        str(syft_path),
    )
    monkeypatch.setenv(
        "REVEAL_GRYPE_PATH",
        str(grype_path),
    )
    monkeypatch.setenv(
        "REVEAL_CODEQL_PATH",
        str(codeql_path),
    )
    monkeypatch.setenv(
        "REVEAL_DOCKER_PATH",
        str(docker_path),
    )

    monkeypatch.delenv(
        "REVEAL_CORPUS_PATH",
        raising=False,
    )

    work_dir = tmp_path / "work"

    exit_code = cli.main(
        [
            "analyze",
            str(source),
            "--work-dir",
            str(work_dir),
            "--document-id",
            "urn:uuid:cli-integration-test",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == cli.ExitCode.SUCCESS
    assert captured.err == ""

    assert "[1/3] Loading configuration..." in captured.out
    assert "[2/3] Checking runtime dependencies..." in (
        captured.out
    )
    assert "Resolved 4 dependencies" in captured.out
    assert "[3/3] Running analysis pipeline..." in (
        captured.out
    )
    assert "REVEAL analysis completed." in captured.out
    assert "Vulnerabilities analyzed: 1" in captured.out

    assert (work_dir / "sbom.cdx.json").is_file()
    assert (work_dir / "grype.json").is_file()
    assert (work_dir / "openvex.json").is_file()
    assert (work_dir / "analysis.json").is_file()

    assert records["usage_codeql_client"] is (
        records["taint_codeql_client"]
    )
    assert records["selector_llm_client"] is (
        records["generator_llm_client"]
    )