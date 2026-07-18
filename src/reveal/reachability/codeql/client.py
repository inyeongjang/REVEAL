"""Low-level CodeQL CLI client."""

from __future__ import annotations

import subprocess
from pathlib import Path

from reveal.exceptions import CodeQLAnalysisError


class CodeQLClient:
    """Execute CodeQL database and query commands."""

    def __init__(
        self,
        executable: str = "codeql",
        timeout_seconds: int = 600,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")

        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def create_database(
        self,
        source: Path,
        database_path: Path,
    ) -> None:
        """Create a JavaScript/TypeScript CodeQL database."""

        database_path.parent.mkdir(parents=True, exist_ok=True)

        command = [
            self.executable,
            "database",
            "create",
            str(database_path),
            "--language=javascript-typescript",
            f"--source-root={source}",
            "--build-mode=none",
            "--overwrite",
        ]

        self._run(command, operation="CodeQL database creation")

    def run_query(
        self,
        database_path: Path,
        query_path: Path,
        output_path: Path,
    ) -> None:
        """Run one query and save its BQRS result."""

        output_path.parent.mkdir(parents=True, exist_ok=True)

        command = [
            self.executable,
            "query",
            "run",
            f"--database={database_path}",
            f"--output={output_path}",
            str(query_path),
        ]

        self._run(command, operation="CodeQL query execution")

        if not output_path.is_file():
            raise CodeQLAnalysisError(
                f"CodeQL did not create the BQRS result: {output_path}"
            )

    def decode_bqrs(
        self,
        bqrs_path: Path,
        output_path: Path,
    ) -> None:
        """Decode a BQRS result into headerless CSV."""

        output_path.parent.mkdir(parents=True, exist_ok=True)

        command = [
            self.executable,
            "bqrs",
            "decode",
            "--format=csv",
            "--no-titles",
            f"--output={output_path}",
            str(bqrs_path),
        ]

        self._run(command, operation="CodeQL BQRS decoding")

        if not output_path.is_file():
            raise CodeQLAnalysisError(
                f"CodeQL did not create the decoded CSV result: {output_path}"
            )

    def _run(
        self,
        command: list[str],
        operation: str,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError as error:
            raise CodeQLAnalysisError(
                f"CodeQL executable was not found: {self.executable}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise CodeQLAnalysisError(
                f"{operation} timed out after {self.timeout_seconds} seconds"
            ) from error
        except OSError as error:
            raise CodeQLAnalysisError(
                f"Failed to execute CodeQL: {error}"
            ) from error

        if result.returncode != 0:
            message = (
                result.stderr.strip()
                or result.stdout.strip()
                or "unknown error"
            )
            raise CodeQLAnalysisError(
                f"{operation} failed with exit code "
                f"{result.returncode}: {message}"
            )

        return result