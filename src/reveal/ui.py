"""Terminal output helpers for the REVEAL CLI."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

LOGO_LINES = (
    r" ____  _____ __     _______    _    _",
    r"|  _ \| ____|\ \   / / ____|  / \  | |",
    r"| |_) |  _|   \ \ / /|  _|   / _ \ | |",
    r"|  _ <| |___   \ V / | |___ / ___ \| |___",
    r"|_| \_\_____|   \_/  |_____/_/   \_\_____|",
)

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_BLUE = "\033[34m"
_CYAN = "\033[36m"


class ConsoleUI:
    """Render REVEAL progress and result messages in a terminal."""

    def __init__(
        self,
        *,
        quiet: bool = False,
        verbose: bool = False,
        color: bool | None = None,
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
    ) -> None:
        self.quiet = quiet
        self.verbose = verbose
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        self.color = (
            _stream_supports_color(self.stdout)
            if color is None
            else color
        )

    def banner(self) -> None:
        """Print the REVEAL ASCII logo."""

        if self.quiet:
            return

        logo = "\n".join(LOGO_LINES)
        self._write(self._paint(logo, _BOLD, _CYAN))
        self._write("")

    def stage(
        self,
        current: int,
        total: int,
        title: str,
    ) -> None:
        """Print the beginning of a top-level stage."""

        if self.quiet:
            return

        marker = self._paint(
            f"[{current}/{total}]",
            _BOLD,
            _BLUE,
        )
        self._write(f"{marker} {title}")

    def success(
        self,
        message: str,
        *,
        indent: int = 6,
    ) -> None:
        """Print a successful stage result."""

        if self.quiet:
            return

        label = self._paint("OK", _BOLD, _GREEN)
        self._write(f"{' ' * indent}{label}  {message}")

    def warning(
        self,
        message: str,
        *,
        indent: int = 6,
    ) -> None:
        """Print a warning result."""

        if self.quiet:
            return

        label = self._paint("WARN", _BOLD, _YELLOW)
        self._write(f"{' ' * indent}{label}  {message}")

    def skipped(
        self,
        message: str,
        *,
        indent: int = 6,
    ) -> None:
        """Print a skipped stage result."""

        if self.quiet:
            return

        label = self._paint("SKIP", _BOLD, _DIM)
        self._write(f"{' ' * indent}{label}  {message}")

    def vulnerability(
        self,
        current: int,
        total: int,
        label: str,
    ) -> None:
        """Print the vulnerability currently being analyzed."""

        if self.quiet:
            return

        marker = self._paint(
            f"[{current}/{total}]",
            _BOLD,
            _CYAN,
        )
        self._write(f"            {marker} {label}")

    def vulnerability_summary(
        self,
        values: tuple[str, ...],
    ) -> None:
        """Print a compact vulnerability analysis summary."""

        if self.quiet:
            return

        summary = " \u2192 ".join(values)
        self._write(f"                  {summary}")

    def detail(
        self,
        label: str,
        value: str,
        *,
        description: str = "",
    ) -> None:
        """Print one verbose vulnerability detail."""

        if self.quiet or not self.verbose:
            return

        rendered_label = self._paint(
            f"{label:<14}",
            _DIM,
        )
        rendered_value = self._paint(value, _BOLD)

        line = f"                  {rendered_label} {rendered_value}"

        if description:
            line = f"{line}  {description}"

        self._write(line)

    def debug(
        self,
        label: str,
        value: str,
    ) -> None:
        """Print additional information in verbose mode."""

        if self.quiet or not self.verbose:
            return

        rendered_label = self._paint(
            f"{label:<14}",
            _DIM,
        )
        self._write(f"      {rendered_label} {value}")

    def section(self, title: str) -> None:
        """Print a result section title."""

        if self.quiet:
            return

        self._write("")
        self._write(self._paint(title, _BOLD))

    def field(
        self,
        label: str,
        value: str | int | Path,
    ) -> None:
        """Print a labeled result value."""

        if self.quiet:
            return

        rendered_label = self._paint(
            f"{label:<18}",
            _DIM,
        )
        self._write(f"  {rendered_label}{value}")

    def summary(
        self,
        values: Mapping[str, int],
    ) -> None:
        """Print a collection of labeled integer results."""

        if self.quiet:
            return

        for label, value in values.items():
            self.field(label, value)

    def error(
        self,
        *,
        category: str,
        message: str,
    ) -> None:
        """Print an error message to stderr."""

        label = self._paint(
            f"{category} error",
            _BOLD,
            _RED,
            use_color=_stream_supports_color(self.stderr),
        )
        self._write_error(f"reveal: {label}: {message}")

    def hint(self, message: str) -> None:
        """Print an error recovery hint to stderr."""

        label = self._paint(
            "hint",
            _BOLD,
            _YELLOW,
            use_color=_stream_supports_color(self.stderr),
        )
        self._write_error(f"        {label}: {message}")

    def _write(self, message: str) -> None:
        print(message, file=self.stdout)

    def _write_error(self, message: str) -> None:
        print(message, file=self.stderr)

    def _paint(
        self,
        text: str,
        *codes: str,
        use_color: bool | None = None,
    ) -> str:
        enabled = self.color if use_color is None else use_color

        if not enabled or not codes:
            return text

        return f"{''.join(codes)}{text}{_RESET}"


def _stream_supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False

    if os.environ.get("TERM", "").lower() == "dumb":
        return False

    return stream.isatty()