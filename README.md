# ToolAtlas

**The capability lockfile and static analyzer for AI agents and MCP tool ecosystems.**

[![CI](https://github.com/Alqudimi/ToolAtlas/actions/workflows/ci.yml/badge.svg)](https://github.com/Alqudimi/ToolAtlas/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-2ea44f)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange)](CHANGELOG.md)

ToolAtlas turns an agent or MCP capability catalog into a deterministic, reviewable manifest. It identifies risky capability declarations, compiles a least-privilege policy, and detects capability drift in CI. It is local-first and offline by default: no gateway, database, cloud account, model API, network call, or tool execution is required.

> **ToolAtlas is a static capability analyzer, not a sandbox, MCP gateway, conformance suite, or LLM judge.** It analyzes declarations and produces evidence for human and CI review; it does not execute the capabilities it sees.

## Why it exists

Agent repositories increasingly connect models to tools, files, APIs, and automation. Runtime gateways and observability platforms are valuable after deployment, while protocol conformance suites answer whether an implementation speaks a protocol correctly. A repository still needs an early, portable answer to a simpler governance question: **what can this agent reach, and did that surface change in this pull request?**

ToolAtlas is designed as that missing pre-runtime layer. Its manifest can be checked into a repository, diffed like a lockfile, reviewed by security engineers, and consumed by future runtime adapters without coupling the core to a provider or framework.

## Features

| Capability | Outcome |
|---|---|
| Deterministic inventory | Normalizes generic and MCP-like JSON catalogs into a versioned manifest. |
| Explainable risk rules | Flags destructive operations, secret-like inputs, broad scopes, and suspicious metadata with evidence and remediation. |
| Policy compiler | Produces an explicit allow/deny policy from findings and a severity threshold. |
| Drift detection | Reports added, removed, and changed capabilities with a stable exit code. |
| CI-ready reports | Emits terminal, JSON, and SARIF 2.1.0 output. |
| Safe by default | Parses bounded data only; never executes commands or contacts the network. |
| Extensible core | Adapters, rules, and reporters have separate boundaries for future MCP/OpenAPI/A2A integrations. |
| Repository gate | Scans agent context and MCP configuration without executing repository content. |
| Reproducible lockfile | Records bounded file inventory, SHA-256 digests, and scanner version for drift checks. |
| Baseline enforcement | Distinguishes accepted findings from new findings in pull requests. |
| Cross-file correlation | Connects secret-like content with network-capable behavior to surface compound risk. |
| Stable SARIF identity | Emits deterministic `partialFingerprints` so GitHub Code Scanning can deduplicate alerts across runs. |

## Quick start

ToolAtlas requires Python 3.11 or newer.

```bash
git clone https://github.com/Alqudimi/ToolAtlas.git
cd ToolAtlas
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'

toolatlas scan examples/catalog.json --format terminal
toolatlas scan examples/catalog.json --format sarif --output toolatlas.sarif
toolatlas policy examples/catalog.json --output toolatlas-policy.json
```

The example intentionally contains risky declarations. A scan therefore exits with code `3`, while still producing a useful report. This is suitable for advisory review first and enforcement after a repository adds an explicit policy.

### Agent repository gate

ToolAtlas can scan a repository of agent instructions, skills, MCP configuration, and source-adjacent text without importing or executing any file:

```bash
toolatlas repo-scan . --format terminal
toolatlas repo-scan . --format sarif --output toolatlas.sarif
toolatlas repo-scan . --max-files 500 --max-file-bytes 500000
toolatlas lock . --output toolatlas.lock.json
toolatlas lock . --output toolatlas.lock.json --verify
toolatlas baseline . --output toolatlas.baseline.json
toolatlas baseline . --output toolatlas.baseline.json --check
```

The lockfile is a reproducibility record, not a publisher signature or SLSA attestation. The baseline is intentionally explicit: new findings fail with exit code `3`, while the report remains available for review. Repository commands default to 2,000 scannable files and 1,000,000 bytes per file; use `--max-files` and `--max-file-bytes` to tighten these limits for CI or constrained environments. Path traversal, oversized files, invalid UTF-8, hidden Unicode, secret-like literals, risky command sinks, and compound cross-file signals are tested as untrusted-input cases.

## Input contract

ToolAtlas accepts a generic catalog:

```json
{
  "capabilities": [
    {
      "id": "tool:read_repository",
      "kind": "tool",
      "name": "read_repository",
      "description": "Read source files",
      "input_names": [],
      "scopes": ["repo:read"]
    }
  ]
}
```

It also accepts an MCP-like shape with `tools`, `resources`, and `prompts` arrays. Unknown metadata is treated as untrusted input and is not copied into generated policy decisions. IDs are stable when explicitly supplied; otherwise the adapter derives `kind:name`.

## Commands and exit codes

```text
toolatlas scan INPUT [--format terminal|json|sarif] [--output PATH]
toolatlas policy INPUT [--max-severity info|low|medium|high|critical] [--output PATH]
toolatlas diff BEFORE AFTER [--format terminal|json] [--output PATH]
toolatlas repo-scan ROOT [--format terminal|json|sarif] [--output PATH] [--max-files N] [--max-file-bytes N]
toolatlas lock ROOT [--output PATH] [--verify] [--max-files N] [--max-file-bytes N]
toolatlas baseline ROOT [--output PATH] [--check] [--max-files N] [--max-file-bytes N]
```

| Code | Meaning |
|---:|---|
| 0 | Successful scan, policy compilation, or no manifest drift. |
| 2 | Invalid input, unsafe path, malformed schema, or size limit. |
| 3 | High/critical advisory findings triggered the scan threshold. |
| 4 | Manifest drift was detected. |
| 5 | Unexpected internal failure. |

Use `-` as the input or output path to stream through standard input/output. ToolAtlas does not interpolate environment variables into catalog values and never accepts a command to execute.

## Architecture

```text
JSON catalog
    |
    v
JSON adapter -> domain capabilities -> deterministic risk rules
                                      |
                                      v
                                manifest + digest
                                  /      |      \
                                 /       |       \
                            policy     diff     SARIF/JSON
```

The domain models are independent of the CLI and filesystem. The adapter owns boundary validation, the application service owns orchestration and canonical hashing, and reporting is a pure rendering layer. See [`docs/architecture.md`](docs/architecture.md) for the full design and security boundary.

## GitHub Actions

A repository can use the published composite action after checking out its code:

```yaml
- uses: actions/checkout@v4
- uses: Alqudimi/ToolAtlas@v0.4.0
  with:
    path: .
    fail-on-high: 'true'
```

The example uses the reviewed `v0.4.0` release tag. For stronger supply-chain pinning, reference the full commit SHA. The action emits SARIF with physical file locations and deterministic `partialFingerprints`, then uploads the report as a workflow artifact. Tighten scanner resources in constrained runners with `--max-files` and `--max-file-bytes` when using the CLI directly.

A repository can also run ToolAtlas as a normal Python quality gate and upload SARIF through the standard GitHub code-scanning action. The included workflow demonstrates the pattern without requiring Docker or external services.

```yaml
- run: toolatlas scan capabilities.json --format sarif --output toolatlas.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: toolatlas.sarif
```

## Development

```bash
make install
make test
make lint
make typecheck
make audit
make build
make demo
```

Tests cover normalization, deterministic digests, malformed and duplicate input, secret-like fields, risk findings, policy compilation, manifest drift, SARIF physical locations and fingerprints, repository traversal safety, hidden Unicode, lock verification, baseline enforcement, CLI output, and stable exit codes. Repository scanning is bounded and benchmarkable; the benchmark suite measures file inventory and digest work without making an environment-independent throughput promise.

## Security

Treat catalogs as untrusted input. The parser is bounded and strict, and the application has no subprocess, socket, HTTP, dynamic import, or model-provider path. ToolAtlas is not a sandbox and must not be used as the sole control for untrusted code. Please read [`SECURITY.md`](SECURITY.md) before reporting a vulnerability.

## Roadmap

The next release can add an MCP initialize/list adapter, richer SARIF suppression metadata, OpenAPI and A2A adapters, and signed manifests. A future runtime adapter may consume the manifest, but the deterministic offline core will remain the compatibility boundary.

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md), preserve deterministic output, add regression tests for behavior changes, and keep adapters separate from policy and reporting logic.

## License

ToolAtlas is released under the [MIT License](LICENSE).
