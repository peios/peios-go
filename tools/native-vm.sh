#!/usr/bin/env bash
# Run native SDK probes in a networkless, disposable initramfs guest.
set -euo pipefail
: "${PEIOS_TEST_KERNEL:?set PEIOS_TEST_KERNEL to a built Peios bzImage}"
: "${PEIOS_SDK:?set PEIOS_SDK to matching development headers and libraries}"
: "${PEIOS_RUST_SDK:?set PEIOS_RUST_SDK to the Rust SDK source directory}"
cd "$(dirname "$0")/.."
build_dir=${PEIOS_NATIVE_BUILD:-$PWD/build/native}
mkdir -p "$build_dir"
bazel_startup=()
if [[ -n ${PEIOS_BAZEL_OUTPUT_BASE:-} ]]; then
    bazel_startup+=("--output_base=$PEIOS_BAZEL_OUTPUT_BASE")
fi
./bazel "${bazel_startup[@]}" build //conformance/native:tests //conformance/vm-init:init //conformance:c-oracle //conformance:rust-oracle "$@"
execution_root=$(./bazel "${bazel_startup[@]}" info execution_root)
built_artifact() {
    local result
    result=$(./bazel "${bazel_startup[@]}" cquery "$1" --output=files)
    [[ -n $result && $result != *$'\n'* ]]
    printf '%s/%s\n' "$execution_root" "$result"
}
python3 tools/vm-image.py --init "$(built_artifact //conformance/vm-init:init)" \
    --probe "$(built_artifact //conformance/native:tests)" \
    --c-oracle "$(built_artifact //conformance:c-oracle)" \
    --rust-oracle "$(built_artifact //conformance:rust-oracle)" \
    --library "$PEIOS_SDK/lib/libpeios.so.0" --output "$build_dir/initramfs.cpio.gz"
python3 tools/record-references.py "$build_dir/sources.json"
sha256sum "$PEIOS_TEST_KERNEL" >"$build_dir/kernel.sha256"
timeout 180 qemu-system-x86_64 -machine q35 -accel tcg -m 768 -smp 2 \
    -nodefaults -no-reboot -display none -serial stdio -monitor none \
    -kernel "$PEIOS_TEST_KERNEL" -initrd "$build_dir/initramfs.cpio.gz" \
    -append 'console=ttyS0 quiet panic=1 rdinit=/init' >"$build_dir/serial.log" 2>&1 || vm_status=$?
cat "$build_dir/serial.log"
test "${vm_status:-0}" -eq 0
grep -q '^PEIOS_GO_NATIVE_PASS' "$build_dir/serial.log"
! grep -Eq '^PEIOS_GO_NATIVE_FAIL|BUG:|Oops:|Kernel panic|WARNING:|possible circular locking' "$build_dir/serial.log"
