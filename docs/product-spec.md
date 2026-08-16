# ToolAtlas Product Specification

## Vision

ToolAtlas gives every AI-enabled repository a reviewable answer to one question: **what capabilities can this agent reach, and did that capability surface change safely?** It is the capability lockfile and static analyzer for tool-using agents.

## Target users

The primary users are developers shipping MCP servers or agent applications, platform engineers reviewing tool access, security engineers enforcing repository policy, and open-source maintainers who need deterministic CI feedback without a cloud account.

## Core use cases

| Use case | Outcome |
|---|---|
| Inventory a tool catalog | A normalized manifest lists tools, resources, prompts, scopes, and provenance. |
| Review capability risk | Findings explain why a capability deserves attention and how to reduce exposure. |
| Generate least-privilege policy | A checked-in policy names allowed capability IDs and a severity threshold. |
| Detect drift in pull requests | A baseline/current diff identifies added, removed, changed, and newly risky capabilities. |
| Integrate with GitHub | SARIF output can be uploaded by a workflow and fail only when repository policy requires it. |

## Functional requirements

The MVP must accept a bounded JSON document with either a `capabilities` array or an MCP-like `tools`, `resources`, and `prompts` shape. It must normalize both shapes into the same manifest, reject malformed documents with actionable errors, never execute declared commands, apply deterministic risk rules, write a stable manifest, render JSON/terminal/SARIF, compile a policy, and compare two manifests.

The CLI must support stdin only when explicitly requested with `-`, refuse output paths that resolve to the input path, and preserve stable exit codes. The library must be usable without importing the CLI module.

## Non-functional requirements

The project must be offline by default, Python 3.11+, typed with mypy, linted and formatted with Ruff, tested with pytest, packaged with a PEP 621 `pyproject.toml`, and documented with examples. Output ordering and digest values must be reproducible across runs. No dependency may be needed at runtime for network access, process execution, telemetry, or an LLM.

## Advanced roadmap

The next release can add an MCP initialize/list adapter, OpenAPI and A2A adapters, baseline policy review, SARIF suppression metadata, signed manifests, a pre-commit hook, and a small web viewer. Later releases can add runtime enforcement adapters and registry integrations, but those remain consumers of the manifest contract rather than reasons to couple the core to a gateway.

## Acceptance criteria

A clean environment can install the package, run the sample scan, generate a policy, compare a modified fixture, and receive stable exit codes. Tests cover valid inputs, malformed inputs, bounded size failures, dangerous capability detection, redaction of secret-like metadata, deterministic output, SARIF validity, policy thresholds, manifest drift, stdin behavior, and path safety. CI runs the quality gate on Linux with supported Python versions and performs dependency auditing and a build.
