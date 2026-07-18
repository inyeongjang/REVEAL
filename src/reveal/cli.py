"""Command-line interface for REVEAL."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from reveal import __version__


def build_parser() -> argparse.ArgumentParser:
    """Create the REVEAL command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="reveal",
        description=(
            "LLM-assisted reachability-to-exploitability verification "
            "for SBOM vulnerabilities"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the REVEAL command-line interface."""

    parser = build_parser()
    parser.parse_args(argv)
    return 0