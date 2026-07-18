"""Tests for the Docker PoC runner."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from reveal.exceptions import PocExecutionError
from reveal.models import (
    Component,
    PocCandidate,
    ReproductionStatus,
    Vulnerability,
)
from reveal.reproduction.docker_runner import DockerPocRunner


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


def create_candidate(
    *,
    language: str = "javascript",
    code: str = "console.log('REVEAL_REPRODUCED');",
    expected_signal: str = "REVEAL_REPRODUCED",
) -> PocCandidate:
    return PocCandidate(
        language=language,
        code=code,
        expected_signal=expected_signal,
        description="Test PoC candidate.",
    )


def create_project(tmp_path: Path) -> Path:
    source = tmp_path / "project"
    source.mkdir()
    return source


def test_run_returns_reproduced_for_exact_signal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="diagnostic\nREVEAL_REPRODUCED\n",
            stderr="",
        )

    monkeypatch.setattr(
        "reveal.reproduction.docker_runner.subprocess.run",
        fake_run,
    )

    source = create_project(tmp_path)
    work_dir = tmp_path / "reproduction"
    runner = DockerPocRunner(image="test-node-image")

    result = runner.run(
        source=source,
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(create_candidate(),),
        work_dir=work_dir,
    )

    assert result.status is ReproductionStatus.REPRODUCED
    assert result.attempt_count == 1
    assert result.attempts[0].reproduced is True
    assert result.attempts[0].exit_code == 0

    assert len(calls) == 1

    command, keyword_arguments = calls[0]

    assert command[:2] == ["docker", "run"]
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges:true" in command
    assert "--pull=never" in command
    assert "test-node-image" in command
    assert command[-2:] == ["node", "-"]

    assert keyword_arguments["input"] == (
        "console.log('REVEAL_REPRODUCED');"
    )
    assert keyword_arguments["timeout"] == 30.0

    attempt_dir = work_dir / "attempt-001"

    assert (attempt_dir / "poc.js").is_file()
    assert (attempt_dir / "command.txt").is_file()
    assert (
        attempt_dir / "stdout.txt"
    ).read_text(encoding="utf-8") == (
        "diagnostic\nREVEAL_REPRODUCED\n"
    )


def test_run_returns_not_reproduced_after_normal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs

        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="not reproduced\n",
            stderr="candidate failed\n",
        )

    monkeypatch.setattr(
        "reveal.reproduction.docker_runner.subprocess.run",
        fake_run,
    )

    result = DockerPocRunner().run(
        source=create_project(tmp_path),
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(create_candidate(),),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.NOT_REPRODUCED
    assert result.attempt_count == 1
    assert result.attempts[0].reproduced is False
    assert result.attempts[0].error is None


def test_run_requires_signal_to_be_an_exact_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="prefix REVEAL_REPRODUCED suffix\n",
            stderr="",
        )

    monkeypatch.setattr(
        "reveal.reproduction.docker_runner.subprocess.run",
        fake_run,
    )

    result = DockerPocRunner().run(
        source=create_project(tmp_path),
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(create_candidate(),),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.NOT_REPRODUCED
    assert result.attempts[0].reproduced is False


def test_run_returns_inconclusive_after_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)

        if command[1] == "run":
            raise subprocess.TimeoutExpired(
                cmd=command,
                timeout=10,
                output="partial output",
                stderr="still running",
            )

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "reveal.reproduction.docker_runner.subprocess.run",
        fake_run,
    )

    result = DockerPocRunner(
        timeout_seconds=10,
    ).run(
        source=create_project(tmp_path),
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(create_candidate(),),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.INCONCLUSIVE
    assert result.attempts[0].timed_out is True
    assert result.attempts[0].exit_code is None
    assert result.attempts[0].stdout == "partial output"

    assert len(calls) == 2
    assert calls[1][1:3] == ["rm", "--force"]


def test_run_returns_error_for_unsupported_language(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del command, kwargs
        raise AssertionError("Docker must not be called")

    monkeypatch.setattr(
        "reveal.reproduction.docker_runner.subprocess.run",
        unexpected_run,
    )

    result = DockerPocRunner().run(
        source=create_project(tmp_path),
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(
            create_candidate(
                language="python",
                code="print('REVEAL_REPRODUCED')",
            ),
        ),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.ERROR
    assert result.attempts[0].exit_code is None
    assert "Unsupported PoC language" in (
        result.attempts[0].error or ""
    )


def test_run_returns_error_for_docker_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        del kwargs

        return subprocess.CompletedProcess(
            args=command,
            returncode=125,
            stdout="",
            stderr="docker daemon unavailable",
        )

    monkeypatch.setattr(
        "reveal.reproduction.docker_runner.subprocess.run",
        fake_run,
    )

    result = DockerPocRunner().run(
        source=create_project(tmp_path),
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(create_candidate(),),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.ERROR
    assert result.attempts[0].exit_code == 125
    assert "docker daemon unavailable" in (
        result.attempts[0].error or ""
    )


def test_run_skips_empty_candidate_sequence(
    tmp_path: Path,
) -> None:
    result = DockerPocRunner().run(
        source=tmp_path / "missing",
        vulnerability=create_vulnerability(),
        target_api="<module>",
        candidates=(),
        work_dir=tmp_path / "reproduction",
    )

    assert result.status is ReproductionStatus.SKIPPED
    assert result.attempts == ()


def test_run_rejects_missing_source_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        PocExecutionError,
        match="Source directory does not exist",
    ):
        DockerPocRunner().run(
            source=tmp_path / "missing",
            vulnerability=create_vulnerability(),
            target_api="<module>",
            candidates=(create_candidate(),),
            work_dir=tmp_path / "reproduction",
        )


@pytest.mark.parametrize(
    ("argument", "value", "message"),
    [
        ("image", "", "image"),
        ("executable", "", "executable"),
        ("timeout_seconds", 0, "timeout_seconds"),
        ("memory_limit", "", "memory_limit"),
        ("cpu_limit", 0, "cpu_limit"),
        ("pids_limit", 0, "pids_limit"),
        ("max_output_chars", 0, "max_output_chars"),
    ],
)
def test_runner_rejects_invalid_configuration(
    argument: str,
    value: object,
    message: str,
) -> None:
    arguments: dict[str, object] = {
        "image": "node-image",
        "executable": "docker",
        "timeout_seconds": 30.0,
        "memory_limit": "256m",
        "cpu_limit": 1.0,
        "pids_limit": 64,
        "max_output_chars": 65_536,
    }
    arguments[argument] = value

    with pytest.raises(ValueError, match=message):
        DockerPocRunner(**arguments)  # type: ignore[arg-type]