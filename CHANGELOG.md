# Changelog

All notable changes to ToolAtlas are documented here.

## [0.2.0] - 2026-08-17

### Added

- Repository supply-chain gate for bounded offline scanning of agent context, MCP configuration, and source-adjacent text.
- Deterministic repository manifest and SHA-256 lockfile generation and verification.
- Baseline creation and checking for explicit accepted findings and pull-request drift.
- Hidden Unicode, secret-like literal, risky command sink, and cross-file correlation rules.
- Repository SARIF 2.1.0 output with physical file locations and a reusable composite GitHub Action.
- Adversarial tests for path safety, oversized files, lock drift, baseline drift, and compound findings.

### Security notes

The lockfile proves content consistency, not publisher identity or signed provenance. The scanner does not execute, import, or contact the network.

## [0.1.0] - 2026-08-16

### Added

- Deterministic capability normalization for generic and MCP-like JSON catalogs.
- Explainable rules for destructive capabilities, secret-like inputs, broad scopes, and suspicious metadata.
- Versioned manifest generation with canonical SHA-256 digest.
- Least-privilege policy compilation and manifest drift detection.
- Terminal, JSON, and SARIF 2.1.0 renderers.
- Offline-first CLI with stable exit codes and bounded input parsing.
- Tests, architecture documentation, contribution guide, security policy, and CI foundation.
