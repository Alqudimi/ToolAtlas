# Development Guide

## Local workflow

Create a Python 3.11+ virtual environment and install the development extra. The project has no runtime network dependency, so the CLI can be exercised entirely offline.

```bash
python -m venv .venv
. .venv/bin/activate
make install
make test
make lint
make format
make typecheck
make audit
make build
```

## Test strategy

Unit tests exercise the domain and rules with in-memory records. Integration-style tests invoke the public CLI, write temporary catalogs, validate JSON and SARIF output, and assert stable exit codes. Fixtures are deliberately synthetic and contain no real credentials or network targets.

## Adding a rule

Add a deterministic function in `domain/rules.py`, give it a stable rule ID, include evidence and remediation, and add tests for both the matching and non-matching paths. A rule must be explainable from catalog metadata and must not call an LLM or external service.

## Adding an adapter

An adapter belongs under `adapters`. It validates an external format at the boundary and returns `Capability` values. It must preserve provenance, reject malformed input, respect size limits, and never execute a declared command. Add an example and a regression test before documenting the adapter as supported.

## Release checklist

Run the full quality gate, build both sdist and wheel, install the wheel in a clean virtual environment, run the example, update `CHANGELOG.md`, and create a signed or annotated version tag through the release workflow. Do not publish a security or performance claim that is not backed by a reproducible check.
