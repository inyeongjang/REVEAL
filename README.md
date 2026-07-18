# REVEAL

REVEAL is an LLM-assisted tool for analyzing whether vulnerabilities reported
from an SBOM are reachable and reproducible in a target application.

## Repository Structure

## Repository Structure

```text
REVEAL/
├── CHANGELOG.md                            # Release notes and change history
├── LICENSE                                 # Project license
├── README.md                               # Project overview, setup, and usage notes
├── pyproject.toml                          # Build metadata, dependencies, and tool configuration 
├── src/                                    # Main application source code
│   └── reveal/
│       ├── __init__.py                     # Package metadata and public exports
│       ├── __main__.py                     # Enables python -m reveal
│       ├── cli.py                          # Command-line entry point and argument parsing
│       ├── exceptions.py                   # Custom exception definitions
│       ├── llm/                            # LLM integration layer
│       │   ├── __init__.py                 # LLM package exports
│       │   └── base.py                     # Base LLM abstractions
│       ├── models.py                       # Core data models
│       ├── reachability/                   # Reachability analysis logic
│       │   ├── __init__.py                 # Reachability package exports
│       │   ├── api_selector.py             # API-based reachability selection logic
│       │   ├── base.py                     # Base reachability abstractions
│       │   ├── codeql/                     # CodeQL-based reachability analysis
│       │   │   ├── __init__.py             # CodeQL reachability exports
│       │   │   ├── client.py               # CodeQL client integration
│       │   │   └── usage_analyzer.py       # CodeQL usage analysis
│       │   └── llm_selector.py             # LLM-assisted reachability selection
│       ├── resources/                      # Static resource files used by the app
│       │   ├── codeql/                     # CodeQL resource files
│       │   │   └── javascript/             # JavaScript CodeQL resources
│       │   │       └── usage/              # Usage-analysis templates and pack config
│       │   │           ├── qlpack.yml      # CodeQL pack definition
│       │   │           └── usage.ql.tmpl   # CodeQL query template
│       │   └── prompts/                    # Prompt templates and related assets
│       ├── sbom/                           # SBOM parsing and handling
│       │   ├── __init__.py                 # SBOM package exports
│       │   ├── base.py                     # Base SBOM abstractions
│       │   └── syft.py                     # Syft-specific SBOM handling
│       └── vulnerabilities/                # Vulnerability parsing and handling
│           ├── __init__.py                 # Vulnerability package exports
│           ├── base.py                     # Base vulnerability abstractions
│           └── grype.py                    # Grype-specific vulnerability handling
└── tests/                                  # Test suite
    ├── test_cli.py                         # CLI behavior tests
    └── unit/                               # Unit tests grouped by subsystem
        ├── test_models.py                  # Core model tests
        ├── llm/                            # LLM layer tests
        │   └── test_base.py                # Base LLM tests
        ├── reachability/                   # Reachability tests
        │   ├── test_api_selector.py        # API selector tests
        │   ├── test_base.py                # Base reachability tests
        │   ├── test_llm_selector.py        # LLM selector tests
        │   └── codeql/                     # CodeQL reachability tests
        │       ├── test_client.py          # CodeQL client tests
        │       └── test_usage_analyzer.py  # CodeQL usage analyzer tests
        ├── sbom/                           # SBOM tests
        │   ├── test_base.py                # SBOM base tests
        │   └── test_syft.py                # Syft tests
        └── vulnerabilities/                # Vulnerability tests
            ├── test_base.py                # Vulnerability base tests
            └── test_grype.py               # Grype tests
```

## Current Status

The project is currently under development.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```