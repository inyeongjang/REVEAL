# Changelog

All notable changes to REVEAL will be documented in this file.

## Unreleased

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