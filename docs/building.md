# Building and Testing peios-go

Use pekit to build and test the Go SDK. Pekit compiles each Go package on
its own, so a change rebuilds only the packages it reaches. The supported
development host is x86-64 Linux.

## Before you start

You need pekit and Git. Everything else is pinned and fetched by pekit on
the first build: Go 1.26.8, the Bootlin C toolchains, Rust 1.98.1, Python
3.14, busybox, libclang, and the Peios SDK and peios-rs sources. The first
build needs network access; later builds find what they need in pekit's
store, and every step runs without network access in a sandbox that holds
only its declared inputs.

The build files use the gcslib libraries named in `workspace.gcsl` and the
build files, and the libraries of the Peios SDK and peios-rs. `pekit lock`
pins their commits in `pekit.lock`. The module has no Go dependencies, so
it needs no `go.sum` and no module pins.

Go runtime users need no C SDK. Portable codecs are pure Go, and the SDK
builds without cgo.

## Test

```sh
pekit test
```

| Test | Check |
|---|---|
| `access`, `event`, `internal_native`, `msgpack`, `process`, `registry`, `registry_source`, `security`, `socket`, `token` | Each package's tests |
| `conformance` | The contract corpus, compared with libpeios through its C and Rust interfaces |
| `parity` | libpeios's public headers are the reviewed ones, and each public symbol maps to a Go declaration |
| `vet` | `go vet` of every package |
| `race` | Every package's tests with the race detector |

Ordinary tests skip Peios system calls. A test whose inputs did not change
is found in the store and not run again.

The `conformance` test runs with two reference programs, which pekit
builds:

| Target | Program |
|---|---|
| `c_oracle` | `conformance/oracle.c`, linked with the SDK's static libpeios |
| `rust_oracle` | `conformance/rust`, which uses peios-rs |

Both are static musl programs. The SDK and peios-rs are taken at the
commits `pekit.lock` pins; `conformance/rust/Cargo.lock` takes peios-rs at
the same commit, which the rust library requires. Go remains an
independent implementation with no runtime dependency on either reference.

## Native tests

Run native probes only in the disposable VM:

```sh
export PEIOS_TEST_KERNEL=/absolute/path/to/bzImage
tools/native-vm.sh
```

The harness builds the native tests' program, the guest's init, and both
reference programs with pekit. It boots them in a temporary initramfs
without host mounts or networking, using an explicitly supplied Peios
kernel image and QEMU. Its output under `build/native/` records the kernel
digest and a copy of `pekit.lock`, which names the reference sources. This
is a targeted SDK check, not release-image or hardware qualification.

## Full check

```sh
python3 tools/prepare-style-tools.py "$HOME/.cache/peios-go-style"
export PEIOS_STYLE_BIN="$HOME/.cache/peios-go-style/bin"
tools/check
```

`tools/check` checks owned source style, verifies the kernel inputs'
provenance, regenerates the Go declarations to compare them, and then runs
`pekit test`. Regenerating the declarations uses the host's Go and C
compiler. GitHub's workflow runs the style checks alone; builds and tests
run with pekit.

## Not built with pekit yet

The development source package, `dev.peios.peios-go-devel`, is not yet
built with pekit. The packaging pipeline from the Bazel build is kept
outside this repository until it is.

## Kernel input provenance

`vendor/kernel/ORIGIN.json` records the exact kernel commit and file hashes.
Run `python3 tools/update-kernel-inputs.py check` to verify that snapshot.
Replace it only through the updater, then review generated declarations and
rerun host, differential, and native checks. Do not format vendored inputs.

## Documentation

Set `TRAIL` to the maintained Trail executable and run `tools/check-docs`.
The optional `--context ../learn` check validates publication links
against the complete merged documentation tree.
