---
title: Using the SDK from Go
type: how-to
description: Use the independent pure-Go peios-go SDK for portable security codecs and native Peios operations, with explicit resource ownership and no cgo dependency.
related:
  - peios/sdk-basics/what-is-the-peios-sdk
  - peios/sdk-access-control/overview
  - peios/sdk-events/naming-and-shaping-events
---

`peios-go` is the independent Go implementation of the Peios SDK. It replaces
`libp-go`, whose kernel ABI had drifted. It calls the current Peios kernel ABI
directly and implements portable security formats in Go. Applications need
neither cgo nor an installed `libpeios` library.

## Development setup

The module is `github.com/peios/peios-go` and currently requires Go 1.26. It is an
unpublished development checkout. To use a sibling checkout, add:

```go
require github.com/peios/peios-go v0.0.0
replace github.com/peios/peios-go => ../peios-go
```

The placeholder version is for local development. Before publishing an
application, switch to a real published module version and remove the local
replacement. Generate the API reference with `go doc` in the module directory.

## Portable security formats

The `security` package works without a Peios kernel:

```go
import "github.com/peios/peios-go/security"

func descriptor() ([]byte, error) {
    d, err := security.ParseSDDL("O:SYG:BAD:(A;;FA;;;BA)(A;;FR;;;BU)")
    if err != nil {
        return nil, err
    }
    return d.MarshalBinary()
}
```

It provides immutable comparable SIDs, GUIDs, ordered ACLs, self-relative
security descriptors, SDDL, conditional ACE bytecode, resource claims and
inheritance. `Reinherit` resolves creator SIDs and generic rights, keeps explicit
entry order, and respects protected lists; `StripInherited` filters selected lists.
Parsers copy their input. Binary encoding preserves ACE order and opaque ACE
bodies while canonicalising layout and padding. An empty DACL denies access;
an absent DACL is a different state. The present-null ACL form is rejected.

`ParseDescriptor` validates structure. Kernel acceptance also depends on the
object class, rights and claim semantics. SDDL does not represent every
control bit or resource-manager byte; retain binary descriptors when those
fields matter. Binary ACL parsing preserves revision bytes and reserved object-ACE
flags accepted by libpeios; parsed ACLs set `ExactRevision` to preserve that revision
on serialization. ACE masks and resource-claim structure are validated. An unknown ACE or unrepresentable payload causes SDDL formatting
to fail instead of silently dropping it.

## Native operations and ownership

Native packages compile for Linux/amd64 and require the Peios kernel ABI:

| Package | Current operations |
| --- | --- |
| `file` | Open/create, file/handle/System V IPC security descriptors and mount policies |
| `token` | Specifications, typed queries, adjustments, defaults, restriction, linking, sessions, installation and scoped impersonation |
| `socket` | Peer identities/pidfds, listener restamping, impersonation levels and message token/FD transfer |
| `process` | Process security-block reads and mitigation activation |
| `access` | Scalar and per-object access checks, with audit outputs |
| `registry` | Keys, values, batch/indexed reads, metadata, descriptors, notifications, transactions, layers and backup/restore |
| `registry/source` | Source registration and bounded concurrent RSI request handling |
| `event` | Emission, policy, per-CPU ring attachment and consumption |

`file.Open` and `file.OpenAt` return ordinary `*os.File` handles. Token, registry
key and transaction handles also own their descriptors and must be closed.
Methods accepting `syscall.Conn` protect the borrowed descriptor against a
concurrent close. Keep a raw `dirfd` open throughout any call that uses it.
Errors support `errors.Is(err, syscall.EACCES)` and other standard Go errnos.
An unsupported kernel call returns `ENOSYS`; the library does not replace
Peios authority with POSIX semantics.

`Token.Impersonate(func() error)` runs the callback on a dedicated locked
thread, restores identity before returning, and retires the thread if restoration
fails. Keep identity-dependent work inside the callback. A panic is rethrown in
the caller after cleanup. Process-wide installation remains a separate explicit
operation. For repeated switches, use `token.WithIdentityThread` and its scope’s
`Impersonate`, `ImpersonatePeer` and `Revert` methods. The scope remains on one
locked thread, expires at callback exit and always attempts final reversion.
Do not retain it or share it with another goroutine.

Registry `Notify` arms the key's existing fd. Read its queue through
`ReadNotifications`; no second notification handle is created. An empty layer
selects the base layer. A nil or zero expected sequence disables value CAS;
delete operations reject a supplied expected sequence.

`event.Policy` reads the current registry hierarchy for every decision. The
deepest valid `Enabled` value wins, missing or unreadable settings retain the
last decision, and essential events bypass policy. `EmitWith` builds its payload
only when enabled. There is no retained cache or watch to close.

## MessagePack and audit contexts

`msgpack.Marshal` accepts scalars, `[]any`, ordered `msgpack.Map` pairs and
`msgpack.Extension`. Decoded binary values own their data. Map order and duplicate
keys are preserved. Nesting defaults to 32, and a failed `Decoder.Decode` leaves
its offset unchanged. These codecs, token specifications, audit contexts and RSI
wire codecs work without a Peios kernel.

`msgpack.Writer` supports incremental, header-first arrays and maps. Its zero
value is ready to use; errors latch until `Reset`. `Bytes` validates a complete
value and returns a borrowed buffer valid until the next mutation. The writer’s
codec limit is 256 levels. `msgpack.Validate` takes an explicit limit in 1..256;
the normal event-emission default remains 32.

`msgpack.Reader` exposes `Peek`, typed reads and header-only `Array`/`Map` reads.
`StringBytes`, `Binary` and `Extension` borrow the input; retain that input and
keep it unchanged. Failed reads leave the cursor untouched, including integer
range failures. `Reader.Skip` walks one complete value without allocations or a
nesting ceiling. The owned `Decoder` remains available for whole-value decoding.

`access.AuditContext("service", []access.Field{{Name: "name", Value: "example"}})`
builds the guarded-object context used by `access.Check`. Audit fields remain
userspace claims. A denied check returns `EACCES` together with the granted subset;
access checks are advisory and do not replace kernel enforcement.

## Identity, processes and messages

Construct a token recipe with `token.Spec`, then serialize it with `MarshalBinary`
or call `Create` on Peios. Claims and LCS scope/private-layer credentials are
encoded directly in Go. Empty claims specify `security.Claim.ValueType` explicitly. The kernel decides whether the caller may mint that
identity. `AdjustDefaults` distinguishes nil (leave DACL unchanged) from a non-nil
empty slice (clear it); owner/group index `0xffff` means unchanged.

Session IDs identify logon sessions; interactivity scope is a separate field.
Closing the last token destroys its dynamic session. `DestroyEmptySession` is for
an unused session. Session listing requires a classified securityfs mount and the
kernel's access checks; the SDK does not change mount policy on behalf of callers.
`OpenSessions` returns a snapshot iterator: `Next` yields owned sessions and
`io.EOF` at the end. A malformed line produces `EPROTO` and is consumed, allowing
the next call to continue. `ListSessions` reads the full result into a slice.

Use standard `os/exec` for process creation and normal kernel inheritance.
`process.ReadSecurityBlock` reads identity protection and committed mitigations.
`SetMitigations` activates protections and cannot clear them. Neither operation
implicitly installs a token or changes authority.

`socket.Send` can convey a token and open handles. A partial send is returned
without resending ancillary data. `Receive` returns close-on-exec handles owned by
its `Message`; call `Message.Close` when done. Truncated control data is an error
and closes every delivered handle. Payload truncation is reported in the flags.
`ReceivePartial` exposes libpeios’s partial-message behavior: it returns the
handles that fit, closes excess handles, and reports Linux `MSG_TRUNC` and
`MSG_CTRUNC`. It is the caller’s choice whether to process a truncated message.
Zero-payload seqpacket messages can transfer handles without a dummy byte.

## Registry sources and event readers

`registry` exposes effective-value batches, indexed enumeration, layers,
tombstones, notifications, and subtree backup/restore in addition to ordinary
reads and writes. Layer metadata changes remain subject to kernel authority.
`QueryInto`, `ValueAtInto` and `ValuesInto` use caller-owned buffers; nil buffers
probe the required lengths and return `ERANGE`. They permit allocations beyond
the ordinary helpers’ 16 MiB ceiling. Batch counts are meaningful on success;
a size probe may report zero count. `TakeFile` and `TakeTransactionFile` transfer
received fd ownership into Go registry handles.

`registry/source.Open` registers global or private hives. `Source.Serve` handles
message-oriented RSI requests with bounded concurrency and serialized response
writes. It closes the source on cancellation or return, waits for handlers, and
returns transport failures. Handlers must observe cancellation and supply their
storage and transaction semantics. The package includes request decoders and
response encoders; decoders tolerate trailing extension fields, so handlers can
choose their protocol-version policy.

`event.AttachAll` walks the kernel's complete CPU slot range and skips offline
holes. Each reader starts at the oldest surviving record, follows ring resizes,
and reports observed sequence gaps through `Lost`. Call `Next` until no record is
available, then `Wait(ctx)` before draining again. Cancellation and concurrent close
can take up to 50ms to interrupt a futex wait. Returned events own their data; they
survive the next read and closing the reader. Per-CPU readers do not impose a
single ordering across CPUs or count losses before attachment.

For a custom drain loop, call `AttachFile(cpu)` and `MapRing(fd, capacity)`.
The attachment and mapping have independent lifetimes; close both. `Metadata`
reports capacity, absolute write/tail positions and generation. `EventAt(position)`
returns an owned event plus wire size, or `EAGAIN` when the position is empty,
lapped or changed during the copy. The caller advances the position and handles
resizes by opening a fresh attachment/mapping when generation changes.
`SetNeedWake` exposes the advisory flag; `Ring.Wait(ctx, position)` manages it
while waiting. Context deadlines supply timeouts; a canceled context polls
readiness, with available data taking precedence over cancellation.

## Coverage and compatibility

The Go SDK covers the functionality of all 218 public functions and exported
mapping objects in libpeios’s eight concept headers at the checked baseline.
`peios-go/conformance/parity.json` maps each symbol to its Go equivalent and
records header hashes. `tools/check-parity.py` rejects unreviewed header changes,
unmapped declarations and missing Go equivalents. The Go API uses owned values,
contexts and standard Go process creation, rather than mirroring every C function
name. The conformance harness builds the public `libpeios` C API and `peios-rs`
Rust API separately and compares bytes, canonical text and rejection outcomes.
It never uses `libp-go` as the behavior oracle. Independent layout, malformed-input
and ownership tests supplement comparisons because both references share libpeios.

RSI source hosting has no public C/Rust SDK equivalent. Its codec comes from the
maintained, MIT-licensed loregd source and is checked against the kernel UAPI and
native request/reply behavior.

Host conformance, fuzzing and race tests are separate from the disposable kernel
VM tests. Native coverage includes token/session operations, file descriptors,
access decisions against both references, socket identity/FD transfer, process
security, ring consumption and source-backed registry operations including
transactions, notifications, layers and backup/restore. Additional native tests
cover System V IPC descriptors, mount-policy templates, low-level rings, repeated
thread identity changes and isolated primary-token installation. The reference
build includes fixes for resource-ACE padding, event lost-wakeup ordering and
missing ancillary truncation flags. Finite tests do not prove every possible input
or error path. These checks are not
release-image or real-hardware qualification. The repository README records the
commands and source revisions.
