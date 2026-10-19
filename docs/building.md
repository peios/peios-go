# Building and Testing peios-go

Run commands from this repository. The `bazel` launcher verifies Bazel 8.4.2;
Bazel pins the language toolchains and dependency graph. Development checks
also use the host C compiler, Python 3.11 or later, and libclang where bindings
are generated. These host dependencies are not a hermetic Peios toolchain.

## Host checks

```sh
./bazel test //...
CGO_ENABLED=0 go test ./...
go test -race ./...
```

Native tests and differential reference tests are separate, explicit targets.
Ordinary host tests skip Peios syscalls. Go runtime users need no C SDK.

## Reference SDK fixture

Build a matched development C SDK from the consolidated repository:

```sh
python3 tools/prepare-dev-sdk.py ../peios-sdk /absolute/path/to/sdk-fixture
export PEIOS_SDK=/absolute/path/to/sdk-fixture
```

The destination must be new. The helper builds the shared library and static
archive with Bazel, copies the matching headers, and records file hashes,
source revision, and checkout changes in `provenance.json`.

For differential checks, set `PEIOS_RUST_SDK` to an absolute Rust SDK source
checkout and run `tools/conformance.sh`. It records reference inputs and
compares Go behavior with the public C and Rust interfaces. Go remains an
independent implementation with no runtime dependency on either reference.

Run native probes only in the disposable VM:

```sh
export PEIOS_RUST_SDK=/absolute/path/to/peios-rs
export PEIOS_TEST_KERNEL=/absolute/path/to/bzImage
tools/native-vm.sh
```

The harness requires an explicitly supplied Peios kernel image and QEMU.
It boots a temporary initramfs without host mounts or networking. Its output
records the kernel digest and reference source inputs; this is a targeted
SDK check, not release-image or hardware qualification.

## Packages

```sh
./bazel build //:packages
```

The output under `bazel-bin/packages/store.store` contains canonical manifests,
compressed content-addressed blobs, and a provenance index. The package holds
SDK source, licenses, build definitions, and maintained documentation. It does
not bundle third-party compiler caches or an installed compiler.

The package is `dev.peios.peios-go-devel`, version
`0.0.0-1`, architecture `noarch`. It installs source under
`/usr/src/go/github.com/peios/peios-go`.
The Go version denotes unreleased development content; it creates no Go release tag.

Provenance marks these packages as development output, not release-qualified
artifacts. Kernel VM tests and release-image qualification remain separate.

## Kernel input provenance

`vendor/kernel/ORIGIN.json` records the exact kernel commit and file hashes.
Run `python3 tools/update-kernel-inputs.py check` to verify that snapshot.
Replace it only through the updater, then review generated declarations and
rerun host, differential, and native checks. Do not format vendored inputs.

## Style and documentation

Use `tools/prepare-style-tools.py` with an output directory outside the repository.
Set `PEIOS_STYLE_BIN` to that directory, then run `tools/check`.
Set `TRAIL` to the maintained Trail executable and run `tools/check-docs`.
The optional `--context ../panorama/docs` check validates publication links
against the complete merged documentation tree.
