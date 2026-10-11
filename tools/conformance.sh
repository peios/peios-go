#!/usr/bin/env bash
# Build and exercise the public C and Rust APIs from sibling checkouts.
set -euo pipefail
cd "$(dirname "$0")/.."
sdk_dir=$PWD
workspace_dir=$(dirname "$PWD")
build_dir=${PEIOS_CONFORMANCE_BUILD:-$PWD/build/conformance}
mkdir -p "$build_dir"
build_dir=$(realpath "$build_dir")
python3 tools/check-uapi.py
python3 tools/check-parity.py
python3 - "$workspace_dir" "$build_dir" <<'PY'
import json, pathlib, subprocess, sys
root,out=map(pathlib.Path,sys.argv[1:])
record={}
for name in ['pkm','libpeios','peios-rs']:
    path=root/name
    record[name]={'revision':subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip(), 'diff':subprocess.check_output(['git','-C',str(path),'diff','HEAD'],text=True)}
(out/'sources.json').write_text(json.dumps(record,indent=2)+'\n')
PY
# Always rebuild the library; never compare against an installed or stale .so.
CARGO_TARGET_DIR="$build_dir/libpeios" cargo build --offline --locked --release --manifest-path "$workspace_dir/libpeios/Cargo.toml"
lib_dir="$build_dir/libpeios/release"
ln -sfn libpeios.so "$lib_dir/libpeios.so.0"
cc -Wall -Wextra -Werror -I"$workspace_dir/libpeios/include" -I"$workspace_dir/pkm/uapi" conformance/oracle.c -L"$lib_dir" -Wl,-rpath,"$lib_dir" -lpeios -o "$build_dir/c-oracle"
PEIOS_LIB_DIR="$lib_dir" PEIOS_INCLUDE="$workspace_dir/libpeios/include" PKM_UAPI="$workspace_dir/pkm/uapi" BINDGEN_EXTRA_CLANG_ARGS="-isystem $(cc -print-file-name=include)" CARGO_TARGET_DIR="$build_dir/rust" cargo build --offline --locked --manifest-path conformance/rust/Cargo.toml
export PEIOS_C_ORACLE="$build_dir/c-oracle" PEIOS_RUST_ORACLE="$build_dir/rust/debug/peios-go-rust-oracle"
export LD_LIBRARY_PATH="$lib_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" PEIOS_REQUIRE_CONFORMANCE=1
# Race is a host check; normal and native builds also run with CGO_ENABLED=0.
go test -count=1 ./...
