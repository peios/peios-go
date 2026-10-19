#!/usr/bin/env python3
"""Record the exact supplied reference inputs, including uncommitted Rust changes."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def fingerprints(root: Path, paths: list[str]) -> dict[str, str]:
    """Hash source files and libraries without walking caches or build outputs."""
    result = {}
    for name in paths:
        entry = root / name
        files = entry.rglob("*") if entry.is_dir() else [entry]
        for path in sorted(files):
            if path.is_file():
                with path.open("rb") as stream:
                    result[str(path.relative_to(root))] = hashlib.file_digest(
                        stream, "sha256"
                    ).hexdigest()
    return result


def main() -> None:
    """Write source identities to the explicit output path."""
    sdk = Path(os.environ["PEIOS_SDK"])
    rust = Path(os.environ["PEIOS_RUST_SDK"])
    revision = subprocess.check_output(
        ["git", "-C", str(rust), "rev-parse", "HEAD"], text=True
    ).strip()
    record = {
        "c_sdk": fingerprints(sdk, ["include", "lib/libpeios.so.0"]),
        "rust_sdk": {
            "revision": revision,
            "files": fingerprints(
                rust,
                [
                    "peios/src",
                    "peios/Cargo.toml",
                    "peios-sys/src",
                    "peios-sys/build.rs",
                    "peios-sys/Cargo.toml",
                ],
            ),
        },
    }
    Path(sys.argv[1]).write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
