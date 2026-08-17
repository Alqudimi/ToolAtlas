# Repository Supply-Chain Gate

## Scope

The repository gate inspects bounded UTF-8 text and structured configuration. It never imports modules, executes scripts, launches MCP servers, resolves dependencies, calls the network, or evaluates model output. A repository is data, not instructions to the scanner.

## Scan pipeline

```text
repository root
    |
    v
safe traversal ---- reject escaping symlink / oversized file / invalid UTF-8
    |
    v
file classification ---- agent context / MCP config / source / document
    |
    v
atomic rules ---- hidden Unicode / secret-like literals / risky sinks
    |
    v
correlation ---- secret signal + network-capable signal across files
    |
    v
manifest + digest ---- JSON / SARIF / terminal / lock / baseline
```

## Lockfile contract

A lockfile contains schema version, scanner version, root name, sorted relative file entries, byte sizes, SHA-256 digests, file kinds, line counts, and the manifest digest. It detects content drift and inventory drift. It does not establish publisher identity, signature validity, or SLSA provenance. Users requiring those guarantees must add a separate signed provenance system.

The serializer uses sorted keys and stable indentation. Running the same scan twice on unchanged content produces byte-identical output and the same digest.

## Baseline contract

A baseline contains the manifest digest and stable finding keys in the form `RULE_ID:relative/path:line`. The check command reports only keys not present in the baseline. Baselines are not suppressions of truth: they are explicit accepted debt and should be reviewed when scanner rules change.

## Severity and exit behavior

High and critical findings return exit code 3. Invalid or unsafe input returns 2. Lock drift returns 4. A clean repository returns 0. The terminal and SARIF outputs remain available even when the process returns a finding-related non-zero code, which makes CI artifacts useful for review.

## Extension points

Future adapters can map MCP `tools/list`, OpenAPI operations, A2A skills, or repository-specific manifests into the same `SourceFile` and finding contracts. New rules should be pure functions over bounded content and must carry a stable rule ID, evidence, remediation, confidence, and source location. Correlation rules should consume normalized findings rather than reimplementing parsing.
