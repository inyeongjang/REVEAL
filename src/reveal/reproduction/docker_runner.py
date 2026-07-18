"""Docker-based isolated proof-of-concept execution."""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from reveal.exceptions import PocExecutionError
from reveal.models import (
    PocAttempt,
    PocCandidate,
    PocResult,
    ReproductionStatus,
    Vulnerability,
)

_DOCKER_ERROR_EXIT_CODES = {125, 126, 127, 137}
_JAVASCRIPT_LANGUAGES = {
    "javascript",
    "js",
    "node",
    "nodejs",
}


class DockerPocRunner:
    """Execute JavaScript PoC candidates in restricted Docker containers."""

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
        if not image.strip():
            raise ValueError("image must not be empty")

        if not executable.strip():
            raise ValueError("executable must not be empty")

        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        if not memory_limit.strip():
            raise ValueError("memory_limit must not be empty")

        if cpu_limit <= 0:
            raise ValueError("cpu_limit must be greater than zero")

        if pids_limit < 1:
            raise ValueError("pids_limit must be at least one")

        if max_output_chars < 1:
            raise ValueError("max_output_chars must be at least one")

        self.image = image
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit
        self.max_output_chars = max_output_chars

    def run(
        self,
        source: Path,
        vulnerability: Vulnerability,
        target_api: str,
        candidates: Sequence[PocCandidate],
        work_dir: Path,
    ) -> PocResult:
        """Execute candidates until one reproduces the vulnerability."""

        if not candidates:
            return PocResult(
                vulnerability_id=vulnerability.id,
                target_api=target_api,
                status=ReproductionStatus.SKIPPED,
                reason="No PoC candidates were provided.",
            )

        if not source.is_dir():
            raise PocExecutionError(
                f"Source directory does not exist: {source}"
            )

        if not target_api.strip():
            raise PocExecutionError("target_api must not be empty")

        source_root = source.resolve()
        work_dir.mkdir(parents=True, exist_ok=True)

        attempts: list[PocAttempt] = []

        for number, candidate in enumerate(candidates, start=1):
            attempt = self._run_candidate(
                source=source_root,
                candidate=candidate,
                number=number,
                work_dir=work_dir,
            )
            attempts.append(attempt)

            if attempt.reproduced:
                return PocResult(
                    vulnerability_id=vulnerability.id,
                    target_api=target_api,
                    status=ReproductionStatus.REPRODUCED,
                    attempts=tuple(attempts),
                    evidence=(
                        f"Candidate {number} exited successfully and emitted "
                        f"the expected signal: {candidate.expected_signal}"
                    ),
                )

        return _create_unsuccessful_result(
            vulnerability=vulnerability,
            target_api=target_api,
            attempts=tuple(attempts),
        )

    def _run_candidate(
        self,
        *,
        source: Path,
        candidate: PocCandidate,
        number: int,
        work_dir: Path,
    ) -> PocAttempt:
        attempt_dir = work_dir / f"attempt-{number:03d}"
        attempt_dir.mkdir(parents=True, exist_ok=True)

        candidate_path = attempt_dir / "poc.js"
        _write_text(candidate_path, candidate.code)

        language = candidate.language.strip().casefold()

        if language not in _JAVASCRIPT_LANGUAGES:
            error = (
                "Unsupported PoC language for Docker execution: "
                f"{candidate.language}"
            )
            _write_text(attempt_dir / "error.txt", error)

            return PocAttempt(
                number=number,
                candidate=candidate,
                error=error,
            )

        if not candidate.expected_signal.strip():
            error = "PoC expected signal must not be empty."
            _write_text(attempt_dir / "error.txt", error)

            return PocAttempt(
                number=number,
                candidate=candidate,
                error=error,
            )

        container_name = _container_name(number)
        command = self._build_command(
            source=source,
            container_name=container_name,
        )

        _write_text(
            attempt_dir / "command.txt",
            shlex.join(command),
        )

        try:
            completed = subprocess.run(
                command,
                input=candidate.code,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError as error:
            raise PocExecutionError(
                f"Docker executable was not found: {self.executable}"
            ) from error
        except subprocess.TimeoutExpired as error:
            self._remove_container(container_name)

            stdout = _coerce_output(error.stdout)
            stderr = _coerce_output(error.stderr)

            self._write_outputs(
                attempt_dir=attempt_dir,
                stdout=stdout,
                stderr=stderr,
            )

            return PocAttempt(
                number=number,
                candidate=candidate,
                stdout=_truncate(stdout, self.max_output_chars),
                stderr=_truncate(stderr, self.max_output_chars),
                timed_out=True,
                reproduced=False,
                error=(
                    "PoC execution timed out after "
                    f"{self.timeout_seconds} seconds."
                ),
            )
        except OSError as error:
            raise PocExecutionError(
                f"Failed to execute Docker: {error}"
            ) from error

        stdout = completed.stdout
        stderr = completed.stderr

        self._write_outputs(
            attempt_dir=attempt_dir,
            stdout=stdout,
            stderr=stderr,
        )

        execution_error = _docker_execution_error(
            return_code=completed.returncode,
            stderr=stderr,
        )
        reproduced = (
            execution_error is None
            and _contains_expected_signal(
                stdout=stdout,
                expected_signal=candidate.expected_signal,
            )
            and completed.returncode == 0
        )

        return PocAttempt(
            number=number,
            candidate=candidate,
            exit_code=completed.returncode,
            stdout=_truncate(stdout, self.max_output_chars),
            stderr=_truncate(stderr, self.max_output_chars),
            reproduced=reproduced,
            error=execution_error,
        )

    def _build_command(
        self,
        *,
        source: Path,
        container_name: str,
    ) -> list[str]:
        return [
            self.executable,
            "run",
            "--rm",
            "--interactive",
            "--pull=never",
            "--name",
            container_name,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            f"--pids-limit={self.pids_limit}",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpu_limit}",
            "--user=65534:65534",
            "--workdir=/workspace",
            "--env=HOME=/tmp",
            "--env=NODE_PATH=/workspace/node_modules",
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
            "--mount",
            f"type=bind,src={source},dst=/workspace,readonly",
            self.image,
            "node",
            "-",
        ]

    def _remove_container(self, container_name: str) -> None:
        try:
            subprocess.run(
                [
                    self.executable,
                    "rm",
                    "--force",
                    container_name,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            return

    def _write_outputs(
        self,
        *,
        attempt_dir: Path,
        stdout: str,
        stderr: str,
    ) -> None:
        _write_text(
            attempt_dir / "stdout.txt",
            _truncate(stdout, self.max_output_chars),
        )
        _write_text(
            attempt_dir / "stderr.txt",
            _truncate(stderr, self.max_output_chars),
        )


def _create_unsuccessful_result(
    *,
    vulnerability: Vulnerability,
    target_api: str,
    attempts: tuple[PocAttempt, ...],
) -> PocResult:
    timed_out = any(attempt.timed_out for attempt in attempts)
    failed_to_execute = tuple(
        attempt
        for attempt in attempts
        if attempt.error is not None
    )
    completed_attempts = tuple(
        attempt
        for attempt in attempts
        if attempt.exit_code is not None and attempt.error is None
    )

    if failed_to_execute and not completed_attempts and not timed_out:
        return PocResult(
            vulnerability_id=vulnerability.id,
            target_api=target_api,
            status=ReproductionStatus.ERROR,
            attempts=attempts,
            reason="No PoC candidate could be executed successfully.",
        )

    if timed_out or failed_to_execute:
        return PocResult(
            vulnerability_id=vulnerability.id,
            target_api=target_api,
            status=ReproductionStatus.INCONCLUSIVE,
            attempts=attempts,
            reason=(
                "PoC reproduction was inconclusive because at least one "
                "candidate timed out or could not be executed."
            ),
        )

    return PocResult(
        vulnerability_id=vulnerability.id,
        target_api=target_api,
        status=ReproductionStatus.NOT_REPRODUCED,
        attempts=attempts,
        reason=(
            "All PoC candidates completed without emitting their expected "
            "reproduction signals."
        ),
    )


def _docker_execution_error(
    *,
    return_code: int,
    stderr: str,
) -> str | None:
    if return_code in _DOCKER_ERROR_EXIT_CODES or return_code < 0:
        detail = stderr.strip()

        if detail:
            return (
                f"Docker could not execute the PoC "
                f"(exit code {return_code}): {detail}"
            )

        return (
            "Docker could not execute the PoC "
            f"(exit code {return_code})."
        )

    return None


def _contains_expected_signal(
    *,
    stdout: str,
    expected_signal: str,
) -> bool:
    expected = expected_signal.strip()

    if not expected:
        return False

    return any(
        line.strip() == expected
        for line in stdout.splitlines()
    )


def _container_name(attempt_number: int) -> str:
    suffix = uuid4().hex[:10]

    return f"reveal-poc-{attempt_number}-{suffix}"


def _coerce_output(value: str | bytes | None) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    return value


def _truncate(value: str, maximum: int) -> str:
    if len(value) <= maximum:
        return value

    marker = "\n...[output truncated by REVEAL]"

    return value[: maximum - len(marker)] + marker


def _write_text(path: Path, value: str) -> None:
    try:
        path.write_text(
            value,
            encoding="utf-8",
        )
    except OSError as error:
        raise PocExecutionError(
            f"Failed to write PoC execution artifact: {path}"
        ) from error