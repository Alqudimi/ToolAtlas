"""Small reproducible measurements for capability and repository scans."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from toolatlas.adapters.json_source import parse_document
from toolatlas.application.repository_scan import lock_from_manifest, scan_repository
from toolatlas.application.services import scan


def _capability_benchmark() -> None:
    for size in (10, 100, 1_000, 10_000):
        document = {
            "capabilities": [
                {"name": f"read_{index}", "scopes": ["repo:read"]} for index in range(size)
            ]
        }
        payload = json.dumps(document).encode()
        started = time.perf_counter()
        capabilities = parse_document(payload, f"benchmark-{size}", len(payload) + 1, size)
        result = scan(capabilities, f"benchmark-{size}")
        elapsed_ms = (time.perf_counter() - started) * 1_000
        print(
            f"capabilities={size:>5} elapsed_ms={elapsed_ms:>9.3f} "
            f"digest={result.manifest.digest[:12]}"
        )


def _repository_benchmark() -> None:
    with tempfile.TemporaryDirectory(prefix="toolatlas-bench-") as directory:
        root = Path(directory)
        for index in range(100):
            (root / f"skill-{index:03d}.md").write_text(
                f"Read-only skill {index}.\n", encoding="utf-8"
            )
        started = time.perf_counter()
        manifest = scan_repository(root)
        elapsed_ms = (time.perf_counter() - started) * 1_000
        lock = lock_from_manifest(manifest)
        print(
            f"repository_files={len(lock.entries):>5} elapsed_ms={elapsed_ms:>9.3f} "
            f"digest={manifest.digest[:12]}"
        )


def main() -> None:
    _capability_benchmark()
    _repository_benchmark()


if __name__ == "__main__":
    main()
