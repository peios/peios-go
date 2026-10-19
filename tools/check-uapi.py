#!/usr/bin/env python3
"""Verify the recorded kernel inputs and regenerate Go declarations for comparison."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    """Check provenance and generated declarations without a sibling repository."""
    subprocess.run(["python3", "tools/update-kernel-inputs.py", "check"], cwd=ROOT, check=True)
    subprocess.run(["bash", "tools/gen-uapi.sh", "--check"], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
