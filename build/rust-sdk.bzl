"""Use an explicit Rust SDK source tree for differential conformance tests."""

def _implementation(ctx):
    source = ctx.os.environ.get("PEIOS_RUST_SDK")
    if not source:
        ctx.file("missing.bzl", "def impl(ctx):\n    fail('Set PEIOS_RUST_SDK to the migrated Rust SDK source tree.')\nmissing = rule(implementation = impl)\n")
        ctx.file("BUILD.bazel", 'load(":missing.bzl", "missing")\nmissing(name="peios", visibility=["//visibility:public"])\n')
        return
    if not source.startswith("/"):
        fail("PEIOS_RUST_SDK must be an absolute path")
    for name in ["peios", "peios-sys"]:
        ctx.symlink(source + "/" + name + "/src", name + "/src")
        ctx.symlink(source + "/" + name + "/Cargo.toml", name + "/Cargo.toml")
    ctx.symlink(source + "/peios-sys/build.rs", "peios-sys/build.rs")
    ctx.file("BUILD.bazel", ctx.read(ctx.attr.definition))

rust_sdk_repository = repository_rule(
    implementation = _implementation,
    environ = ["PEIOS_RUST_SDK"],
    attrs = {"definition": attr.label(allow_single_file = True, mandatory = True)},
    local = True,
    configure = True,
)
