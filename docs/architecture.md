# ToolAtlas Architecture

## Product boundary

ToolAtlas is a local-first capability inventory and static policy compiler for AI agents and MCP ecosystems. It analyzes declared or discovered tool metadata without executing tools, network calls, model calls, or arbitrary user commands. The output is a versioned manifest that can be reviewed, diffed, checked in, and consumed by CI or a future runtime adapter.

ToolAtlas is not an MCP gateway, sandbox, observability backend, conformance suite, or LLM judge. Those boundaries are intentional: the core must remain deterministic, offline-capable, and safe to run on untrusted configuration and metadata.

## Core flow

```text
MCP/fixture input
      |
      v
Adapter -> Boundary validation -> Normalization
                              |
                              v
                       Capability graph
                       /      |       \
                      /       |        \
                 Risk rules  Policy   Manifest
                      |       compiler    |
                      v          |        v
                 Findings  ->  Policy  ->  JSON/SARIF/diff
```

## Bounded contexts

| Context | Responsibility | Forbidden dependency |
|---|---|---|
| `domain` | Immutable capability models, risk findings, manifest contract, policy rules | CLI, filesystem, network, subprocess |
| `adapters` | Parse JSON/YAML and translate external formats into domain input | Policy decisions and report formatting |
| `application` | Orchestrate scan, policy compilation, manifest diffing, deterministic ordering | CLI presentation details |
| `reporting` | Render stable terminal/JSON/SARIF output | Discovery or policy mutation |
| CLI | Validate arguments, load files, map typed errors to exit codes | Business rules |

## Public contract

The stable public library surface is intentionally small:

```python
scan(source: SourceDocument, options: ScanOptions) -> ScanResult
compile_policy(result: ScanResult, options: PolicyOptions) -> CompiledPolicy
compare_manifests(before: Manifest, after: Manifest) -> ManifestDiff
render_json(value: ReportValue) -> str
render_sarif(result: ScanResult) -> str
```

The CLI exposes these operations:

```text
toolatlas scan INPUT --format terminal|json|sarif --output PATH
toolatlas policy INPUT --output POLICY.json
toolatlas diff BASE CURRENT --format terminal|json
```

All commands use stable machine-readable exit codes: `0` pass, `2` invalid input, `3` policy/risk threshold failed, `4` manifest drift detected, `5` internal failure. Errors are structured internally and rendered without tracebacks by default.

## Manifest contract

Manifest schema version `1` contains producer metadata, source identity, normalized capabilities, findings, policy summary, and deterministic digest. Capabilities have an explicit kind (`tool`, `resource`, `prompt`), stable identity, human description, input names, declared scopes, and provenance. Unknown fields from adapters are ignored rather than copied into policy decisions. Stable ordering is by capability kind, normalized name, and source location.

## Risk model

The MVP uses explainable deterministic rules. Rules inspect names, descriptions, declared scopes, and input metadata. Examples include destructive verbs (`delete`, `drop`, `destroy`, `execute`), broad filesystem/network scopes, secret-like input names, and combinations such as write access plus external network. Findings contain a rule ID, severity, confidence, capability ID, evidence, and remediation. No rule claims to prove maliciousness; the output is a review signal.

Severity values are `info`, `low`, `medium`, `high`, and `critical`. A policy may define a maximum allowed severity and explicit capability allowlists. A high or critical finding can fail CI when configured, while default scanning remains advisory.

## Security model

Inputs are untrusted data. The parser uses size limits, UTF-8 decoding with explicit failure, strict schema validation, no dynamic imports, no shell execution, no URL fetching, and no interpolation of environment secrets. File paths are resolved and checked against the requested input/output boundaries. SARIF and terminal output escape control characters. Generated policies never contain parameter values or secrets; they contain capability IDs and scopes only.

## Extensibility

Adapters implement a protocol that yields `RawCapability` records. The domain does not know whether the source was MCP JSON, OpenAPI, a future A2A catalog, or a hand-written fixture. Risk rules implement a protocol and are registered explicitly. Reporters implement a protocol over immutable result objects. A future signed manifest can extend the schema with optional fields without changing the core decision model.

## Performance strategy

The MVP is a single-process, streaming-friendly analyzer. It parses bounded documents, uses O(n) normalization and rule evaluation, and computes one SHA-256 digest over canonical JSON. There is no database or cache. Benchmarks measure scan time for 10, 100, 1,000, and 10,000 capabilities. The algorithm deliberately favors predictable memory use and deterministic output over premature concurrency.

## Deployment strategy

The primary distribution is a Python package and standalone CLI. A GitHub Action invokes the CLI and uploads SARIF. A future OCI image or server adapter can wrap the same application layer without modifying domain logic.
