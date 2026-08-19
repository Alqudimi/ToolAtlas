# Changelog

All notable changes to ToolAtlas are documented here.

## [Unreleased]

### Added

- Adversarial input-validation and CLI boundary coverage across the adapter, domain, application, and CLI layers (`tests/test_adversarial_coverage.py`).
- Regression tests for rejected malformed JSON, invalid UTF-8, oversized payloads, invalid record shapes, scope and metadata schema violations, lockfile tampering, malformed baseline findings, repository path-safety edges (escaping symlinks, non-directory roots, file-count limits), `diff` drift exit codes, `baseline --check` new-finding reporting, `stdin` scans, and `KeyboardInterrupt` error rendering.

## [0.3.0] - 2026-08-18

### Added

- Deterministic SARIF `partialFingerprints` for capability and repository findings.
- Stable `toolatlas/v1` fingerprint namespace to prevent duplicate GitHub Code Scanning alerts across runs.
- Regression coverage for physical locations and fingerprint presence.

### Security notes

Fingerprints improve alert identity and deduplication; they do not change rule confidence or prove that a repository is safe.

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
