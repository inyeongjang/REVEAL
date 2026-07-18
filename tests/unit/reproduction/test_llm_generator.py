"""Tests for the LLM-based PoC generator."""

from __future__ import annotations

from pathlib import Path

import pytest

from reveal.exceptions import PocGenerationError
from reveal.llm import LlmRequest, LlmResponse
from reveal.models import (
    Component,
    ReachabilityStatus,
    TaintPath,
    TaintResult,
    Vulnerability,
)
from reveal.reproduction.llm_generator import LlmPocGenerator


class FakeLlmClient:
    """Deterministic LLM client for PoC generator tests."""

    def __init__(self, response_text: str) -> None:
        self.response_text = response_text
        self.requests: list[LlmRequest] = []

    def generate(self, request: LlmRequest) -> LlmResponse:
        self.requests.append(request)

        return LlmResponse(
            text=self.response_text,
            provider="fake",
            model="fake-model",
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
        fixed_versions=("1.2.6",),
    )


def create_taint_result(
    *,
    status: ReachabilityStatus = ReachabilityStatus.REACHABLE,
    sink_file: Path = Path("src/routes/arguments.js"),
) -> TaintResult:
    paths = ()

    if status is ReachabilityStatus.REACHABLE:
        paths = (
            TaintPath(
                source_file=Path("src/routes/arguments.js"),
                source_line=4,
                source="request.query",
                sink_file=sink_file,
                sink_line=10,
                sink="minimist(request.query)",
                sink_argument=0,
                steps=(
                    "request.query",
                    "arguments",
                    "minimist(arguments)",
                ),
            ),
        )

    return TaintResult(
        vulnerability_id="GHSA-xvch-5gv4-984h",
        target_api="<module>",
        status=status,
        paths=paths,
        reason="Test taint result.",
    )


def create_project(tmp_path: Path) -> Path:
    source = tmp_path / "project"
    source_file = source / "src/routes/arguments.js"
    source_file.parent.mkdir(parents=True)

    source_file.write_text(
        "\n".join(
            (
                "const express = require('express');",
                "const minimist = require('minimist');",
                "",
                "const router = express.Router();",
                "",
                "router.get('/parse', (request, response) => {",
                "  const raw = request.query.arguments;",
                "  const arguments = raw.split(',');",
                "",
                "  const parsed = minimist(arguments);",
                "  response.json(parsed);",
                "});",
                "",
                "module.exports = router;",
            )
        ),
        encoding="utf-8",
    )

    return source


def test_generate_returns_normalized_candidates(
    tmp_path: Path,
) -> None:
    source = create_project(tmp_path)
    client = FakeLlmClient(
        """
        {
          "candidates": [
            {
              "language": "javascript",
              "code": "console.log('REVEAL_REPRODUCED');",
              "expected_signal": "REVEAL_REPRODUCED",
              "description": "Exercise the vulnerable parser."
            }
          ]
        }
        """
    )
    generator = LlmPocGenerator(client)

    candidates = generator.generate(
        source=source,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
    )

    assert len(candidates) == 1
    assert candidates[0].language == "javascript"
    assert candidates[0].expected_signal == "REVEAL_REPRODUCED"
    assert candidates[0].description == "Exercise the vulnerable parser."

    assert len(client.requests) == 1

    request = client.requests[0]

    assert request.temperature == 0.0
    assert request.max_tokens == 4096
    assert request.json_schema is not None
    assert "GHSA-xvch-5gv4-984h" in request.user_prompt
    assert '"target_api": "<module>"' in request.user_prompt
    assert "const parsed = minimist(arguments);" in request.user_prompt
    assert '"sink_line": 10' in request.user_prompt


def test_generate_respects_candidate_limit_and_removes_duplicates(
    tmp_path: Path,
) -> None:
    source = create_project(tmp_path)
    client = FakeLlmClient(
        """
        {
          "candidates": [
            {
              "language": "javascript",
              "code": "console.log('ONE');",
              "expected_signal": "ONE",
              "description": "First candidate."
            },
            {
              "language": "javascript",
              "code": "console.log('ONE');",
              "expected_signal": "ONE",
              "description": "Duplicate candidate."
            },
            {
              "language": "javascript",
              "code": "console.log('TWO');",
              "expected_signal": "TWO",
              "description": "Second candidate."
            }
          ]
        }
        """
    )
    generator = LlmPocGenerator(client)

    candidates = generator.generate(
        source=source,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        max_candidates=2,
    )

    assert len(candidates) == 2
    assert tuple(
        candidate.expected_signal
        for candidate in candidates
    ) == (
        "ONE",
        "TWO",
    )


def test_generate_returns_empty_for_non_reachable_result(
    tmp_path: Path,
) -> None:
    client = FakeLlmClient(
        """
        {
          "candidates": []
        }
        """
    )
    generator = LlmPocGenerator(client)

    candidates = generator.generate(
        source=tmp_path / "missing",
        vulnerability=create_vulnerability(),
        taint=create_taint_result(
            status=ReachabilityStatus.UNREACHABLE,
        ),
    )

    assert candidates == ()
    assert client.requests == []


def test_generate_accepts_empty_candidate_response(
    tmp_path: Path,
) -> None:
    source = create_project(tmp_path)
    client = FakeLlmClient(
        """
        {
          "candidates": []
        }
        """
    )
    generator = LlmPocGenerator(client)

    candidates = generator.generate(
        source=source,
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
    )

    assert candidates == ()


def test_generate_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    source = create_project(tmp_path)
    generator = LlmPocGenerator(
        FakeLlmClient("not valid JSON")
    )

    with pytest.raises(
        PocGenerationError,
        match="invalid JSON",
    ):
        generator.generate(
            source=source,
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
        )


def test_generate_rejects_invalid_candidate(
    tmp_path: Path,
) -> None:
    source = create_project(tmp_path)
    generator = LlmPocGenerator(
        FakeLlmClient(
            """
            {
              "candidates": [
                {
                  "language": "",
                  "code": "console.log('test');",
                  "expected_signal": "test",
                  "description": "Invalid language."
                }
              ]
            }
            """
        )
    )

    with pytest.raises(
        PocGenerationError,
        match="language",
    ):
        generator.generate(
            source=source,
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
        )


def test_generate_rejects_mismatched_vulnerability(
    tmp_path: Path,
) -> None:
    source = create_project(tmp_path)
    taint = TaintResult(
        vulnerability_id="CVE-OTHER",
        target_api="<module>",
        status=ReachabilityStatus.REACHABLE,
        paths=create_taint_result().paths,
    )
    generator = LlmPocGenerator(
        FakeLlmClient('{"candidates": []}')
    )

    with pytest.raises(
        PocGenerationError,
        match="does not match",
    ):
        generator.generate(
            source=source,
            vulnerability=create_vulnerability(),
            taint=taint,
        )


def test_generate_rejects_missing_source_directory(
    tmp_path: Path,
) -> None:
    generator = LlmPocGenerator(
        FakeLlmClient('{"candidates": []}')
    )

    with pytest.raises(
        PocGenerationError,
        match="Source directory does not exist",
    ):
        generator.generate(
            source=tmp_path / "missing",
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
        )


def test_generate_rejects_path_outside_project(
    tmp_path: Path,
) -> None:
    source = create_project(tmp_path)
    outside_file = tmp_path / "outside.js"
    outside_file.write_text(
        "console.log('outside');",
        encoding="utf-8",
    )
    generator = LlmPocGenerator(
        FakeLlmClient('{"candidates": []}')
    )

    with pytest.raises(
        PocGenerationError,
        match="escapes the project directory",
    ):
        generator.generate(
            source=source,
            vulnerability=create_vulnerability(),
            taint=create_taint_result(
                sink_file=Path("../outside.js"),
            ),
        )


def test_generate_rejects_non_positive_candidate_limit(
    tmp_path: Path,
) -> None:
    generator = LlmPocGenerator(
        FakeLlmClient('{"candidates": []}')
    )

    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        generator.generate(
            source=tmp_path,
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
            max_candidates=0,
        )