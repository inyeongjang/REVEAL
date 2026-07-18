# REVEAL

REVEAL is an LLM-assisted tool for analyzing whether vulnerabilities reported
from an SBOM are reachable and reproducible in a target application.

## Repository Structure

```text
REVEAL/
├── pyproject.toml              # Project metadata, build settings, CLI entry point, and tool config
├── README.md                   # Project overview and usage notes
├── src/
│   └── reveal/
│       ├── __init__.py         # Package metadata such as __version__
│       ├── __main__.py         # Enables python -m reveal
│       ├── cli.py              # Command-line parser and main() implementation
│       ├── models.py           # Core data models used by the application
│       ├── exceptions.py       # Custom exception types
│       ├── sbom/
│       │   ├── __init__.py     # SBOM package exports
│       │   ├── base.py         # Base SBOM abstractions
│       │   └── syft.py         # Syft-specific SBOM handling
│       └── vulnerabilities/
│           ├── __init__.py     # Vulnerability package exports
│           ├── base.py         # Base vulnerability abstractions
│           └── grype.py        # Grype-specific vulnerability handling
└── tests/
    ├── test_cli.py             # CLI behavior tests
    └── unit/
        ├── test_models.py      # Model unit tests
        ├── sbom/
        │   ├── test_base.py    # SBOM base tests
        │   └── test_syft.py    # Syft integration/unit tests
        └── vulnerabilities/
            └── test_base.py    # Vulnerability base tests
```

## Current Status

The project is currently under development.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```