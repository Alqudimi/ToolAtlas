# Changelog

All notable changes to ToolAtlas are documented here.

## [Unreleased]

### Added

- Regression contract tests for the `repo-policy` gate: severity-boundary evaluation across `MEDIUM`/`HIGH`/`CRITICAL` thresholds, partial `--allow-rule` suppression with cross-file correlation (`TA110`) co-existing, no-op behavior for unknown allow rules, `INVALID_INPUT` (exit 2) for non-directory and missing roots, `UNSAFE_PATH` for escaping symlinks, `--output` file writing for both terminal and JSON policy payloads, and clean-repository pass output.

### Security notes

Exit code and policy evaluation semantics of the pre-deploy gate are now regression-proof; a failure to detect threshold or allow-rule regressions would have turned a failing gate into a passing one.

## [0.5.0] - 2026-08-20

### Added

- Deterministic `repo-policy` command for repository findings.
- Severity threshold evaluation with explicit repeated `--allow-rule` exceptions.
- Terminal and JSON policy explanations with stable exit code `3` for violations.
- Unit and CLI contract tests for pass, fail, exception, and JSON behavior.

### Security notes

Policy exceptions are explicit and reviewable. ToolAtlas does not infer trust from a rule exception and does not claim runtime enforcement; `repo-policy` is a pre-deploy static gate.

## [0.4.0] - 2026-08-19

### Added

- Configurable `--max-files` and `--max-file-bytes` bounds for `repo-scan`, `lock`, and `baseline`.
- Fail-closed CLI coverage for oversized files and repository file-count limits.
- Documentation examples for tightening resource bounds in constrained CI environments.

### Security notes

The secure defaults remain 2,000 scannable files and 1,000,000 bytes per file. Lower limits can reduce denial-of-service exposure; higher limits should be reviewed for the target runner.

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
