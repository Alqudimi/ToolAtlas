# Contributing to ToolAtlas

Thank you for helping make ToolAtlas safer and more useful. Start by opening an issue for behavior changes or a discussion for larger design work. Small documentation and test improvements can go directly into a pull request.

## Development setup

Use Python 3.11 or newer, create a virtual environment, and install the development extra:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
make test lint typecheck audit build
```

## Design rules

Keep business rules in `src/toolatlas/domain`, boundary parsing in `adapters`, orchestration in `application`, and output formatting in `reporting`. New adapters must translate into the versioned capability contract. They must not execute commands, make network requests, or make policy decisions.

Every behavior change needs a regression test. Preserve stable output ordering, typed errors, documented exit codes, and the offline-by-default security boundary. Avoid adding a dependency when the standard library is sufficient.

## Pull requests

Use a focused branch and a Conventional Commit-style title such as `feat: add MCP catalog adapter` or `fix: reject duplicate capability IDs`. Explain the problem, the design choice, security impact, and verification commands. Do not include secrets or real customer data in fixtures.

## Review checklist

A maintainer will check contract compatibility, input validation, deterministic output, failure behavior, test quality, documentation, and dependency impact. Changes that weaken the no-execution/no-network boundary require an explicit architecture discussion and threat model update.
