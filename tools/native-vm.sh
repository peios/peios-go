#!/usr/bin/env bash
# Run native SDK probes in a networkless, disposable initramfs guest.
set -euo pipefail
: "${PEIOS_TEST_KERNEL:?set PEIOS_TEST_KERNEL to a built Peios bzImage}"
cd "$(dirname "$0")/.."
build_dir=${PEIOS_NATIVE_BUILD:-$PWD/build/native}
mkdir -p "$build_dir"
built=$(pekit build vm_init native_tests c_oracle rust_oracle)
# pekit prints each target's output, indented, on the line after its name.
built_artifact() {
    local result
    result=$(printf '%s\n' "$built" | sed -n "/^built \/$1\$/{n;s/^  //p;}")
    [[ -n $result && $result != *$'\n'* ]]
    printf '%s/%s\n' "$PWD" "$result"
}
python3 tools/vm-image.py --init "$(built_artifact vm_init)" \
    --probe "$(built_artifact native_tests)" \
    --c-oracle "$(built_artifact c_oracle)" \
    --rust-oracle "$(built_artifact rust_oracle)" \
    --output "$build_dir/initramfs.cpio.gz"
# pekit.lock pins the SDK and peios-rs the reference programs are built from.
cp pekit.lock "$build_dir/pekit.lock"
sha256sum "$PEIOS_TEST_KERNEL" >"$build_dir/kernel.sha256"
timeout 180 qemu-system-x86_64 -machine q35 -accel tcg -m 768 -smp 2 \
    -nodefaults -no-reboot -display none -serial stdio -monitor none \
    -kernel "$PEIOS_TEST_KERNEL" -initrd "$build_dir/initramfs.cpio.gz" \
    -append 'console=ttyS0 quiet panic=1 rdinit=/init' >"$build_dir/serial.log" 2>&1 || vm_status=$?
cat "$build_dir/serial.log"
test "${vm_status:-0}" -eq 0
grep -q '^PEIOS_GO_NATIVE_PASS' "$build_dir/serial.log"
! grep -Eq '^PEIOS_GO_NATIVE_FAIL|BUG:|Oops:|Kernel panic|WARNING:|possible circular locking' "$build_dir/serial.log"
