#!/usr/bin/env python3
"""Make a deterministic initramfs from explicit, statically linked SDK probes."""

import argparse
import gzip
import stat
from pathlib import Path


def write_archive(files: dict[str, Path], output: Path) -> None:
    """Write root-owned files and parent directories using the newc format."""
    entries = {}
    for name, path in files.items():
        for parent in Path(name).parents:
            if str(parent) != ".":
                entries[str(parent)] = (stat.S_IFDIR | 0o755, b"")
        entries[name] = (stat.S_IFREG | 0o755, path.read_bytes())
    for name in ["proc", "sys", "dev", "tmp"]:
        entries[name] = (stat.S_IFDIR | 0o755, b"")
    archive = bytearray()
    for inode, (name, (mode, data)) in enumerate(
        [*sorted(entries.items()), ("TRAILER!!!", (0, b""))], 1
    ):
        encoded = name.encode() + b"\0"
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        archive += b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + encoded
        archive += b"\0" * (-len(archive) % 4)
        archive += data
        archive += b"\0" * (-len(archive) % 4)
    output.write_bytes(gzip.compress(archive, mtime=0))


def main() -> None:
    """Build an isolated image without mounting any host directory in the guest."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["init", "probe", "c-oracle", "rust-oracle", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    files = {
        "init": args.init,
        "probe.test": args.probe,
        "c-oracle": args.c_oracle,
        "rust-oracle": args.rust_oracle,
    }
    write_archive(files, args.output)


if __name__ == "__main__":
    main()
