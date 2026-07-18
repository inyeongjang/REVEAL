"""Tests for the REVEAL command-line interface."""

import pytest

from reveal import __version__
from reveal.cli import build_parser, main


def test_parser_uses_reveal_as_program_name() -> None:
    parser = build_parser()

    assert parser.prog == "reveal"


def test_main_returns_success() -> None:
    assert main([]) == 0


def test_version_option(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--version"])

    captured = capsys.readouterr()

    assert error.value.code == 0
    assert captured.out.strip() == f"reveal {__version__}"