#!/usr/bin/env bash
# Networkless, ephemeral initramfs VM. Requires an explicit Peios kernel image.
set -euo pipefail
: "${PEIOS_TEST_KERNEL:?set PEIOS_TEST_KERNEL to a built Peios bzImage}"
cd "$(dirname "$0")/.."
build_dir=$PWD/build/native
ref_dir=$PWD/build/conformance
mkdir -p "$build_dir"
# Build reference drivers first using tools/conformance.sh.
test -x "$ref_dir/c-oracle"
test -x "$ref_dir/rust/debug/peios-go-rust-oracle"
CGO_ENABLED=0 go test -c -o "$build_dir/probe.test" ./conformance/native
CGO_ENABLED=0 go build -o "$build_dir/init" ./conformance/vm-init
python3 tools/vm-image.py "$build_dir" "$ref_dir"
sha256sum "$PEIOS_TEST_KERNEL" > "$build_dir/kernel.sha256"
# TCG works without /dev/kvm; no networking or host filesystem is exposed.
timeout 180 qemu-system-x86_64 -machine q35 -accel tcg -m 768 -smp 2 -nodefaults -no-reboot -display none -serial stdio -monitor none -kernel "$PEIOS_TEST_KERNEL" -initrd "$build_dir/initramfs.cpio.gz" -append 'console=ttyS0 quiet panic=1 rdinit=/init' > "$build_dir/serial.log" 2>&1 || vm_status=$?
cat "$build_dir/serial.log"
test "${vm_status:-0}" -eq 0
grep -q '^PEIOS_GO_NATIVE_PASS' "$build_dir/serial.log"
! grep -q '^PEIOS_GO_NATIVE_FAIL' "$build_dir/serial.log"
