# Changelog

All notable changes to REVEAL will be documented in this file.

## Unreleased

### Changed

- Reused one CodeQL database across package usage and vulnerability taint analyses
- Namespaced CodeQL query artifacts by analysis stage and vulnerability
- Converted expected usage, API mapping, taint, PoC, and VEX decision failures into conservative analysis results
- Continued analyzing remaining vulnerabilities after recoverable per-vulnerability failures
- Tool-independent PoC refinement abstraction based on prior execution evidence
- Bounded PoC refinement and re-execution with duplicate candidate suppression

### Added

- Initial Python package structure
- Basic command-line entry point
- Shared domain models for SBOM, vulnerability, reachability, reproduction, and VEX data
- Tool-independent SBOM generator abstraction
- Syft adapter for CycloneDX JSON SBOM generation
- Tool-independent vulnerability scanner abstraction
- Grype adapter for SBOM-based vulnerability scanning
- Tool-independent package usage analyzer abstraction
- CodeQL adapter for JavaScript package API usage analysis
- Tool-independent vulnerable API selector abstraction
- Provider-independent LLM client abstraction
- LLM-based vulnerable API selection from observed dependency usages
- OpenAI Responses API adapter for LLM-backed analysis
- Ollama generate API adapter for local LLM-backed analysis
- Tool-independent vulnerability evidence retriever abstraction
- Closed-corpus vulnerability evidence retrieval with identifier and text matching
- Evidence-backed fallback for unresolved vulnerable API mappings
- Tool-independent taint reachability analyzer abstraction
- CodeQL remote-input taint reachability analysis for selected dependency APIs
- Tool-independent proof-of-concept generator abstraction
- LLM-based PoC generation from vulnerability, taint, and source-code evidence
- Tool-independent isolated PoC runner abstraction
- Restricted Docker runner for isolated JavaScript PoC execution
- Conservative VEX decision policy for API usage, reachability, and PoC evidence
- OpenVEX 0.2.0 JSON document generation and validation
- End-to-end analysis pipeline orchestration across SBOM, vulnerability, reachability, reproduction, and VEX stages
- Normalized JSON analysis artifacts containing SBOM, API mapping, taint, PoC, and VEX evidence
- LLM-based PoC refinement using prior candidate code and execution diagnostics
- Bounded PoC refinement and re-execution with duplicate candidate suppression
- Environment-based runtime configuration for LLM providers, external tools, analysis limits, and OpenVEX metadata
- Type-safe runtime dependency bootstrap for assembling configured analysis pipelines