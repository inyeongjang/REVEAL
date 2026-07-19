# REVEAL

REVEAL is an LLM-assisted tool for analyzing whether vulnerabilities reported
from an SBOM are reachable and reproducible in a target application.

## Repository Structure

```text
REVEAL/
├── CHANGELOG.md
├── LICENSE
├── README.md
├── pyproject.toml
├── src/
│   └── reveal/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── exceptions.py
│       ├── models.py
│       ├── pipeline.py
│       ├── llm/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── ollama.py
│       │   └── openai.py
│       ├── reachability/
│       │   ├── __init__.py
│       │   ├── api_selector.py
│       │   ├── base.py
│       │   ├── closed_corpus.py
│       │   ├── llm_selector.py
│       │   ├── retriever.py
│       │   └── codeql/
│       │       ├── __init__.py
│       │       ├── client.py
│       │       ├── taint_analyzer.py
│       │       └── usage_analyzer.py
│       ├── reproduction/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── docker_runner.py
│       │   └── llm_generator.py
│       ├── resources/
│       │   ├── codeql/
│       │   │   └── javascript/
│       │   │       ├── taint/
│       │   │       │   ├── qlpack.yml
│       │   │       │   └── taint.ql.tmpl
│       │   │       └── usage/
│       │   │           ├── qlpack.yml
│       │   │           └── usage.ql.tmpl
│       │   └── prompts/
│       │       ├── api_mapping.txt
│       │       └── poc_generation.txt
│       ├── sbom/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   └── syft.py
│       ├── vex/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── openvex.py
│       │   └── policy.py
│       └── vulnerabilities/
│           ├── __init__.py
│           ├── base.py
│           └── grype.py
└── tests/
    ├── test_cli.py
    └── unit/
        ├── test_models.py
        ├── test_pipeline.py
        ├── llm/
        │   ├── test_base.py
        │   ├── test_ollama.py
        │   └── test_openai.py
        ├── reachability/
        │   ├── test_api_selector.py
        │   ├── test_base.py
        │   ├── test_closed_corpus.py
        │   ├── test_llm_selector.py
        │   ├── test_retriever.py
        │   ├── test_taint_base.py
        │   └── codeql/
        │       ├── test_client.py
        │       ├── test_shared_database.py
        │       ├── test_taint_analyzer.py
        │       └── test_usage_analyzer.py
        ├── reproduction/
        │   ├── test_base.py
        │   ├── test_docker_runner.py
        │   ├── test_llm_generator.py
        │   └── test_runner_base.py
        ├── sbom/
        │   ├── test_base.py
        │   └── test_syft.py
        ├── vex/
        │   ├── test_base.py
        │   ├── test_openvex.py
        │   ├── test_policy.py
        │   └── test_writer_base.py
        └── vulnerabilities/
            ├── test_base.py
            └── test_grype.py
```

## Current Status

The project is currently under development.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

- Windows PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

- Windows Command Prompt (cmd.exe)

```bat
.venv\Scripts\activate.bat
```

## Prerequisites

REVEAL integrates with external tools during analysis. Make sure these are
installed and available in PATH:

- Syft (SBOM generation)
- Grype (vulnerability scanning)
- CodeQL CLI (usage/taint reachability analysis)
- Docker (isolated PoC execution)

Python requirements:

- Python 3.10+

## Quickstart

Install in editable mode for local development:

```bash
pip install -e ".[dev]"
```

Basic CLI checks:

```bash
reveal --version
python -m reveal --version
```

## Optional OpenAI support

OpenAI integration is available through the optional dependency group.

```bash
pip install -e ".[openai]"
```

Set your API key before running OpenAI-backed flows:

```bash
export OPENAI_API_KEY="<your-api-key>"
```

Windows PowerShell:

```powershell
$env:OPENAI_API_KEY = "<your-api-key>"
```

## Quality checks

Run static checks and tests:

```bash
ruff check . --fix
ruff check .
mypy src/reveal
pytest
```

Run only the shared database regression test:

```bash
pytest tests/unit/reachability/codeql/test_shared_database.py -q
```

## Build package

```bash
python -m build
```