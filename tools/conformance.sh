#!/usr/bin/env bash
# Exercise native Bazel reference drivers against the Go SDK contract corpus.
set -euo pipefail
: "${PEIOS_SDK:?set PEIOS_SDK to matching C SDK headers and libraries}"
: "${PEIOS_RUST_SDK:?set PEIOS_RUST_SDK to the Rust SDK source directory}"
cd "$(dirname "$0")/.."
build_dir=${PEIOS_CONFORMANCE_BUILD:-$PWD/build/conformance}
mkdir -p "$build_dir"
python3 tools/check-uapi.py
python3 tools/check-parity.py
python3 tools/record-references.py "$build_dir/sources.json"
./bazel test //conformance:differential-tests "$@"
