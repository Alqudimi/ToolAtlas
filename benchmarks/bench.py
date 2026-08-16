"""Small deterministic benchmark for capability normalization and risk analysis."""

from __future__ import annotations

import json
import time

from toolatlas.adapters.json_source import parse_document
from toolatlas.application.services import scan


def main() -> None:
    for size in (10, 100, 1_000, 10_000):
        document = {"capabilities": [{"name": f"read_{index}", "scopes": ["repo:read"]} for index in range(size)]}
        payload = json.dumps(document).encode()
        started = time.perf_counter()
        capabilities = parse_document(payload, f"benchmark-{size}", len(payload) + 1, size)
        result = scan(capabilities, f"benchmark-{size}")
        elapsed_ms = (time.perf_counter() - started) * 1_000
        print(f"capabilities={size:>5} elapsed_ms={elapsed_ms:>9.3f} digest={result.manifest.digest[:12]}")


if __name__ == "__main__":
    main()
