"""Run the Go contract corpus against explicit C and Rust reference binaries."""

def _implementation(ctx):
    launcher = ctx.actions.declare_file(ctx.label.name + ".sh")
    script = """#!/bin/bash
set -euo pipefail
root="${RUNFILES_DIR:-$0.runfiles}/%s"
export PEIOS_REQUIRE_CONFORMANCE=1
export PEIOS_C_ORACLE="$root/%s"
export PEIOS_RUST_ORACLE="$root/%s"
export LD_LIBRARY_PATH="$(dirname "$root/%s")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$root/conformance"
exec "$root/%s" "$@"
""" % (ctx.workspace_name, ctx.executable.c_oracle.short_path, ctx.executable.rust_oracle.short_path, ctx.files.libraries[0].short_path, ctx.executable.binary.short_path)
    ctx.actions.write(launcher, script, is_executable = True)
    files = ctx.runfiles(files = ctx.files.libraries)
    for target in [ctx.attr.binary, ctx.attr.c_oracle, ctx.attr.rust_oracle]:
        files = files.merge(target[DefaultInfo].default_runfiles).merge(ctx.runfiles(files = target[DefaultInfo].files.to_list()))
    return [DefaultInfo(executable = launcher, runfiles = files)]

conformance_test = rule(
    implementation = _implementation,
    test = True,
    attrs = {
        "binary": attr.label(executable = True, cfg = "target", mandatory = True),
        "c_oracle": attr.label(executable = True, cfg = "target", mandatory = True),
        "rust_oracle": attr.label(executable = True, cfg = "target", mandatory = True),
        "libraries": attr.label_list(allow_files = True, mandatory = True),
    },
)
