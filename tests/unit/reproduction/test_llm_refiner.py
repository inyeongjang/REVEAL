"""Tests for the LLM-based PoC refiner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reveal.exceptions import PocRefinementError
from reveal.llm import LlmRequest, LlmResponse
from reveal.models import (
    Component,
    PocAttempt,
    PocCandidate,
    PocResult,
    ReachabilityStatus,
    ReproductionStatus,
    TaintPath,
    TaintResult,
    Vulnerability,
)
from reveal.reproduction.llm_refiner import LlmPocRefiner


class FakeLlmClient:
    """Deterministic LLM client for PoC refinement tests."""

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


def create_project(tmp_path: Path) -> Path:
    source = tmp_path / "project"
    source.mkdir()

    return source


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
    )


def create_taint_result(
    *,
    vulnerability_id: str = "GHSA-xvch-5gv4-984h",
    target_api: str = "<module>",
    status: ReachabilityStatus = ReachabilityStatus.REACHABLE,
) -> TaintResult:
    paths = ()

    if status is ReachabilityStatus.REACHABLE:
        paths = (
            TaintPath(
                source_file=Path("src/routes.js"),
                source_line=5,
                source="request.query",
                sink_file=Path("src/routes.js"),
                sink_line=10,
                sink="minimist(request.query)",
                sink_argument=0,
            ),
        )

    return TaintResult(
        vulnerability_id=vulnerability_id,
        target_api=target_api,
        status=status,
        paths=paths,
    )


def create_candidate() -> PocCandidate:
    return PocCandidate(
        language="javascript",
        code=(
            "const minimist = require('minimist');\n"
            "minimist(['--__proto__.polluted', 'true']);\n"
        ),
        expected_signal="REVEAL_REPRODUCED",
        description="Initial PoC candidate.",
    )


def create_previous_result(
    *,
    vulnerability_id: str = "GHSA-xvch-5gv4-984h",
    target_api: str = "<module>",
    status: ReproductionStatus = ReproductionStatus.NOT_REPRODUCED,
    include_attempt: bool = True,
) -> PocResult:
    attempts = ()

    if include_attempt:
        attempts = (
            PocAttempt(
                number=1,
                candidate=create_candidate(),
                exit_code=1,
                stdout="",
                stderr="TypeError: verification value was undefined",
                reproduced=False,
            ),
        )

    return PocResult(
        vulnerability_id=vulnerability_id,
        target_api=target_api,
        status=status,
        attempts=attempts,
        reason="The initial PoC did not reproduce the vulnerability.",
    )


def test_refine_returns_normalized_candidate(
    tmp_path: Path,
) -> None:
    refined_code = (
        "const minimist = require('minimist');\n"
        "const before = Object.prototype.polluted;\n"
        "minimist([\n"
        "  '--constructor.prototype.polluted',\n"
        "  'true',\n"
        "]);\n"
        "if (\n"
        "  before === undefined\n"
        "  && Object.prototype.polluted === 'true'\n"
        ") {\n"
        "  console.log('REVEAL_REPRODUCED');\n"
        "} else {\n"
        "  process.exit(1);\n"
        "}\n"
    )
    client = FakeLlmClient(
        json.dumps(
            {
                "candidates": [
                    {
                        "language": "javascript",
                        "code": refined_code,
                        "expected_signal": "REVEAL_REPRODUCED",
                        "description": (
                            "Check the prototype value after parsing."
                        ),
                    }
                ]
            }
        )
    )
    refiner = LlmPocRefiner(client)

    candidates = refiner.refine(
        source=create_project(tmp_path),
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        previous_result=create_previous_result(),
    )

    assert len(candidates) == 1
    assert candidates[0].language == "javascript"
    assert candidates[0].expected_signal == "REVEAL_REPRODUCED"
    assert "Object.prototype.polluted" in candidates[0].code

    assert len(client.requests) == 1

    request = client.requests[0]

    assert request.temperature == 0.0
    assert request.max_tokens == 4096
    assert request.json_schema is not None
    assert "TypeError: verification value was undefined" in (
        request.user_prompt
    )
    assert "minimist(['--__proto__.polluted'" in request.user_prompt
    assert '"target_api": "<module>"' in request.user_prompt


def test_refine_removes_previous_and_duplicate_code(
    tmp_path: Path,
) -> None:
    previous_code = create_candidate().code
    revised_code = (
        "const minimist = require('minimist');\n"
        "minimist(['--constructor.prototype.polluted', 'true']);\n"
        "if (Object.prototype.polluted === 'true') {\n"
        "  console.log('REVEAL_REPRODUCED');\n"
        "}\n"
    )
    client = FakeLlmClient(
        json.dumps(
            {
                "candidates": [
                    {
                        "language": "javascript",
                        "code": previous_code,
                        "expected_signal": "REVEAL_REPRODUCED",
                        "description": "Unchanged candidate.",
                    },
                    {
                        "language": "javascript",
                        "code": revised_code,
                        "expected_signal": "REVEAL_REPRODUCED",
                        "description": "Revised candidate.",
                    },
                    {
                        "language": "javascript",
                        "code": revised_code,
                        "expected_signal": "REVEAL_REPRODUCED",
                        "description": "Duplicate revised candidate.",
                    },
                ]
            }
        )
    )
    refiner = LlmPocRefiner(client)

    candidates = refiner.refine(
        source=create_project(tmp_path),
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        previous_result=create_previous_result(),
    )

    assert len(candidates) == 1
    assert candidates[0].code == revised_code.strip()


def test_refine_rejects_changed_expected_signal(
    tmp_path: Path,
) -> None:
    client = FakeLlmClient(
        json.dumps(
            {
                "candidates": [
                    {
                        "language": "javascript",
                        "code": "console.log('ALWAYS_SUCCESS');",
                        "expected_signal": "ALWAYS_SUCCESS",
                        "description": "Changed validation signal.",
                    }
                ]
            }
        )
    )
    refiner = LlmPocRefiner(client)

    with pytest.raises(
        PocRefinementError,
        match="changed the expected signal",
    ):
        refiner.refine(
            source=create_project(tmp_path),
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
            previous_result=create_previous_result(),
        )


def test_refine_skips_reproduced_result(
    tmp_path: Path,
) -> None:
    client = FakeLlmClient('{"candidates": []}')
    refiner = LlmPocRefiner(client)

    candidates = refiner.refine(
        source=tmp_path / "missing",
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        previous_result=create_previous_result(
            status=ReproductionStatus.REPRODUCED,
        ),
    )

    assert candidates == ()
    assert client.requests == []


def test_refine_skips_result_without_attempts(
    tmp_path: Path,
) -> None:
    client = FakeLlmClient('{"candidates": []}')
    refiner = LlmPocRefiner(client)

    candidates = refiner.refine(
        source=tmp_path / "missing",
        vulnerability=create_vulnerability(),
        taint=create_taint_result(),
        previous_result=create_previous_result(
            include_attempt=False,
        ),
    )

    assert candidates == ()
    assert client.requests == []


def test_refine_rejects_mismatched_vulnerability(
    tmp_path: Path,
) -> None:
    refiner = LlmPocRefiner(
        FakeLlmClient('{"candidates": []}')
    )

    with pytest.raises(
        PocRefinementError,
        match="Previous PoC result vulnerability",
    ):
        refiner.refine(
            source=create_project(tmp_path),
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
            previous_result=create_previous_result(
                vulnerability_id="CVE-OTHER",
            ),
        )


def test_refine_rejects_mismatched_target_api(
    tmp_path: Path,
) -> None:
    refiner = LlmPocRefiner(
        FakeLlmClient('{"candidates": []}')
    )

    with pytest.raises(
        PocRefinementError,
        match="target API",
    ):
        refiner.refine(
            source=create_project(tmp_path),
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
            previous_result=create_previous_result(
                target_api="parse",
            ),
        )


def test_refine_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    refiner = LlmPocRefiner(
        FakeLlmClient("not valid JSON")
    )

    with pytest.raises(
        PocRefinementError,
        match="invalid JSON",
    ):
        refiner.refine(
            source=create_project(tmp_path),
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
            previous_result=create_previous_result(),
        )


def test_refine_rejects_missing_source_directory(
    tmp_path: Path,
) -> None:
    refiner = LlmPocRefiner(
        FakeLlmClient('{"candidates": []}')
    )

    with pytest.raises(
        PocRefinementError,
        match="Source directory does not exist",
    ):
        refiner.refine(
            source=tmp_path / "missing",
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
            previous_result=create_previous_result(),
        )


def test_refine_rejects_non_positive_candidate_limit(
    tmp_path: Path,
) -> None:
    refiner = LlmPocRefiner(
        FakeLlmClient('{"candidates": []}')
    )

    with pytest.raises(
        ValueError,
        match="at least one",
    ):
        refiner.refine(
            source=tmp_path,
            vulnerability=create_vulnerability(),
            taint=create_taint_result(),
            previous_result=create_previous_result(),
            max_candidates=0,
        )