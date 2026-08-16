# Extension Contract

ToolAtlas is intentionally extensible through data contracts rather than framework inheritance.

## Adapter boundary

An adapter accepts a bounded external document and returns `tuple[Capability, ...]`. The application layer then runs the same normalization, rules, digest, policy, and report flow for every adapter. This means an MCP adapter can be added without changing the risk engine or CLI report semantics.

## Rule boundary

A rule consumes an immutable `Capability` and yields zero or more `Finding` values. Findings must have a stable ID, severity, evidence, remediation, and confidence. Rules should be deterministic and conservative: a finding is a review signal, not proof of malicious intent.

## Reporter boundary

Reporters consume `ScanResult` or `ManifestDiff` and return text. JSON is the machine contract, terminal output is for humans, and SARIF is the CI integration contract. Reporters must not mutate manifests or recompute policy decisions.

## Compatibility

Manifest `schema_version` is the compatibility boundary. New fields should be additive and optional. Existing field meanings, ordering, digest canonicalization, and CLI exit codes must remain stable within a major schema version. A future signed manifest can add signature metadata without changing the unsigned manifest's semantic payload.

## Planned adapters

The next adapters are an MCP initialize/list response adapter, OpenAPI operation inventory, and A2A capability catalog. Each adapter will be opt-in and offline-friendly when given a saved fixture. Live network discovery, if added later, must be a separate explicit adapter with its own SSRF and credential threat model.
