# REVEAL

> **Determine whether dependency vulnerabilities are actually used, reachable, and exploitable.**

[![License](https://img.shields.io/github/license/inyeongjang/REVEAL)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg?logo=docker\&logoColor=white)](https://www.docker.com/)

## 🚀 Overview

**REVEAL** is a CLI-based vulnerability exploitability analysis pipeline for JavaScript and TypeScript projects.

It combines SBOM generation, dependency vulnerability scanning, CodeQL analysis, LLM-assisted vulnerable API mapping, isolated PoC execution, and OpenVEX generation.

```text
Target Repository
→ Syft SBOM
→ Grype Vulnerability Scan
→ CodeQL Usage Analysis
→ LLM Vulnerable API Mapping
→ CodeQL Reachability Analysis
→ PoC Generation and Execution
→ OpenVEX Generation
```

## ✨ Features

* CycloneDX SBOM generation with **Syft**
* Dependency vulnerability scanning with **Grype**
* Package usage and taint analysis with **CodeQL**
* Vulnerable API mapping with **OpenAI** or **Ollama**
* LLM-based PoC generation and refinement
* Restricted PoC execution in Docker
* OpenVEX and normalized analysis output
* LLM prompt and response tracing

## ⚡ Getting Started

### 1. Prerequisites

* Git
* Docker Desktop or Docker Engine
* Docker Compose v2

Syft, Grype, CodeQL, Python, Node.js, and REVEAL are included in the Docker image.

### 2. Installation

```bash
git clone https://github.com/inyeongjang/REVEAL.git
cd REVEAL
cp .env.example .env
```

### 3. LLM Configuration

#### OpenAI

Edit `.env`:

```env
REVEAL_LLM_PROVIDER=openai
REVEAL_LLM_MODEL=<OPENAI_MODEL>
REVEAL_OPENAI_API_KEY=<OPENAI_API_KEY>
```

#### Ollama

Run Ollama on the host:

```bash
ollama pull qwen2.5-coder:7b
```

Edit `.env`:

```env
REVEAL_LLM_PROVIDER=ollama
REVEAL_LLM_MODEL=qwen2.5-coder:7b
REVEAL_OLLAMA_BASE_URL=http://host.docker.internal:11434
```

API mapping, PoC generation, and PoC refinement use the same provider and model during one analysis run.

### 4. Build

```bash
docker compose build
docker pull node:22-bookworm-slim
```

### 5. Run

Analyze a public GitHub repository:

```bash
docker compose run --rm reveal \
  reveal analyze \
  https://github.com/OWNER/REPOSITORY \
  --work-dir .reveal \
  --verbose
```

Analyze a local repository placed under the REVEAL directory:

```bash
docker compose run --rm reveal \
  reveal analyze \
  ./targets/target-project \
  --work-dir .reveal \
  --verbose
```

View all CLI options:

```bash
docker compose run --rm reveal reveal analyze --help
```

## 📂 Output

Results are stored in `.reveal/`.

```text
.reveal/
├── sbom.cdx.json
├── grype.json
├── analysis.json
├── openvex.json
├── llm-api-mapping.jsonl
├── llm-poc-generation.jsonl
└── llm-poc-refinement.jsonl
```

| File            | Description                                 |
| --------------- | ------------------------------------------- |
| `sbom.cdx.json` | CycloneDX SBOM                              |
| `grype.json`    | Raw Grype scan result                       |
| `analysis.json` | Evidence collected from all analysis stages |
| `openvex.json`  | Final OpenVEX document                      |
| `llm-*.jsonl`   | LLM prompts, responses, and metadata        |

## 🛠️ Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run checks:

```bash
ruff check .
mypy src/reveal
pytest
```

## 📌 Current Limitations

* JavaScript and TypeScript projects only
* JavaScript/Node.js PoC execution only
* One shared LLM provider and model per run
* An unsuccessful PoC does not by itself prove non-exploitability
* Currently an alpha research prototype

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch.
3. Run the tests and static checks.
4. Open a Pull Request.

## 📄 License

This project is licensed under the [MIT License](./LICENSE).

## 🙋 Contact

* [GitHub Issues](https://github.com/inyeongjang/REVEAL/issues)
* [Maintainer](https://github.com/inyeongjang)
