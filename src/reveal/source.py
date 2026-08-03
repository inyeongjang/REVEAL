"""Resolve local directories and public GitHub repositories."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse

from reveal.exceptions import PipelineError


_GITHUB_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")
_CLONE_TIMEOUT_SECONDS = 300


@dataclass(frozen=True, slots=True)
class ResolvedSource:
    """A source project resolved to a local directory."""

    path: Path
    original: str
    repository_url: str | None = None

    @property
    def is_remote(self) -> bool:
        """Return whether the source was cloned from a repository."""

        return self.repository_url is not None


@contextmanager
def resolve_source(
    value: str | Path,
    work_dir: Path | None = None,
) -> Iterator[ResolvedSource]:
    """Resolve a local directory or public GitHub repository URL."""

    original = str(value).strip()

    if not original:
        raise PipelineError("Source must not be empty.")

    local_path = Path(original).expanduser()

    if local_path.is_dir():
        yield ResolvedSource(
            path=local_path.resolve(),
            original=original,
        )
        return

    if local_path.exists():
        raise PipelineError(
            f"Source is not a directory: {local_path.resolve()}"
        )

    repository_url = _normalize_github_url(original)

    if work_dir is not None:
        work_dir.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="reveal-source-", dir=work_dir) as temporary:
        destination = Path(temporary) / "repository"
        _clone_repository(repository_url, destination)

        yield ResolvedSource(
            path=destination.resolve(),
            original=original,
            repository_url=repository_url,
        )


def _normalize_github_url(value: str) -> str:
    parsed = urlparse(value)

    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise PipelineError(
            "Source does not exist as a local directory and is not a "
            "supported public GitHub HTTPS URL."
        )

    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise PipelineError(
            "GitHub URLs must not contain credentials, ports, queries, "
            "or fragments."
        )

    parts = [part for part in parsed.path.split("/") if part]

    if len(parts) != 2:
        raise PipelineError(
            "GitHub repository URL must have the form "
            "https://github.com/OWNER/REPOSITORY."
        )

    owner, repository = parts

    if repository.endswith(".git"):
        repository = repository[:-4]

    if (
        not owner
        or not repository
        or _GITHUB_NAME_PATTERN.fullmatch(owner) is None
        or _GITHUB_NAME_PATTERN.fullmatch(repository) is None
    ):
        raise PipelineError(
            "GitHub repository owner or name contains unsupported "
            "characters."
        )

    return f"https://github.com/{owner}/{repository}.git"


def _clone_repository(
    repository_url: str,
    destination: Path,
) -> None:
    try:
        completed = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--",
                repository_url,
                str(destination),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=_CLONE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise PipelineError(
            "Git is required to analyze repository URLs."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise PipelineError(
            "Repository clone timed out after "
            f"{_CLONE_TIMEOUT_SECONDS} seconds."
        ) from error

    if completed.returncode != 0:
        detail = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or "unknown Git error"
        )
        raise PipelineError(
            f"Failed to clone repository: {detail}"
        )

    if not destination.is_dir():
        raise PipelineError(
            "Git clone completed without creating the source directory."
        )