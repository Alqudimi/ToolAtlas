"""Allow ``python -m toolatlas`` to invoke the CLI."""

from toolatlas.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
