# peios-go

An independent, pure-Go Peios SDK. Module: `github.com/peios/peios-go`.
No cgo, libpeios shared library, or libp-go dependency is required at runtime.
Development source is hosted at https://github.com/peios/peios-go.
No versioned Go module release has been tagged yet.

## Packages

| Package | Implemented surface |
| --- | --- |
| `security` | Portable SIDs, GUIDs, ACLs, descriptors, SDDL, conditions, resource claims, inheritance and stripping inherited entries. |
| `msgpack` | Portable whole-value/incremental encoding, typed borrowed cursors, allocation-free skipping and bounded validation, including extension types and ordered maps. |
| `access` | Portable audit contexts; native scalar and per-object access checks with audit outputs. |
| `file` | Native open/create, file/handle/System V IPC descriptors, mount-policy query/update. Returns `*os.File`. |
| `token` | Portable specifications, claims and LCS credentials; native opens/queries, adjustments, defaults, restriction, duplication, linking, sessions, installation and scoped impersonation. |
| `socket` | Peer token/pidfd, impersonation level, listener restamping, automatic/explicit message identity and descriptor transfer. |
| `process` | Process security-block reads and one-way mitigation activation. Ordinary process creation uses Go's `os/exec`. |
| `registry` | Keys, effective/batch/indexed values, metadata, descriptors, notifications, transactions, tombstones, layers and backup/restore. |
| `registry/source` | Portable RSI codecs and native source registration/hosting, including private hives. |
| `event` | Single/batch emission, tier policy, owned record decoding, low-level rings and per-CPU readers with resize recovery, loss accounting and cancellable waits. |

Native packages target **Linux/amd64 with the Peios kernel ABI**. They can be
compiled on ordinary Linux; unsupported syscalls return `syscall.ENOSYS`.
They do not substitute POSIX authority for Peios operations. The portable
`security` package can be used by cross-platform image and package tooling.

Functional equivalents cover all **218 public functions and exported mapping
objects across libpeios’s eight concept headers**, at the checked source baseline.
The per-symbol inventory is [conformance/parity.json](conformance/parity.json);
`tools/check-parity.py` rejects new/changed headers, unmapped symbols and missing
Go declarations. The API uses Go-owned values,
`syscall.Conn`, `context.Context` and standard Go process creation rather than a
one-function-per-C-symbol facade. `security`, `msgpack`, token construction, audit
contexts and RSI codecs also compile on other operating systems.

## Use in a checkout

Until a version is published, a consumer needs a sibling checkout and:

```go
require github.com/peios/peios-go v0.0.0
replace github.com/peios/peios-go => ../peios-go
```

The `v0.0.0` entry is a local development placeholder. Replace it and remove the
local replacement before publishing a consumer. The current workspace migrations
also point pekit and peiso at the migrated sibling peipkg.

```go
d, err := security.ParseSDDL("O:SYG:BAD:(A;;FA;;;BA)(A;;FR;;;BU)")
if err != nil { return err }
wire, err := d.MarshalBinary()
```

`SID.Bytes`, binary parsers and event decoding return owned data. ACL entry order
and opaque ACE bodies are retained; encoding may canonicalise layout and padding.
`ParseDescriptor` checks binary structure; it is not an access-check engine or a
promise that every mask/claim will be accepted by the kernel for every object type.
An absent DACL and an empty DACL are distinct. Peios' present-null ACL encoding is
rejected. Unknown ACEs survive binary rewrites, and SDDL formatting refuses an
ACE or payload it cannot represent. SDDL cannot represent every descriptor control
bit or resource-manager control byte; use binary descriptors when preserving them.

Native errors use Go's `syscall.Errno` and support `errors.Is`. Owned handles must
be closed. Operations accepting `syscall.Conn` protect against concurrent close
and descriptor reuse. Raw `dirfd` arguments are borrowed: keep them open during
the call. Objects are not copied to duplicate authority; use token duplication or
an OS descriptor duplication explicitly.

`Token.Impersonate` runs its callback on a dedicated locked goroutine and reverts
before returning. Keep identity-dependent work within that callback. A failed
revert retires the OS thread; a callback panic is rethrown after cleanup. `Install`
changes process identity and is intentionally a separate explicit operation.
`WithIdentityThread` permits repeated `Impersonate`, `ImpersonatePeer` and `Revert`
within one callback on a locked thread. The scope rejects use after the callback
or from another thread, and always attempts final reversion. Neither callback
API transfers identity to goroutines launched by the callback.

Registry writes target the base layer when `Layer` is empty. A nil expected
sequence, or zero, disables compare-and-set. Delete operations reject a supplied
expected sequence because their kernel ABI has no CAS field. `Notify` arms the
existing key fd; read that same key's notification queue.
`QueryInto`, `ValuesInto` and `ValueAtInto` expose caller-buffer probes/`ERANGE`
and permit values beyond the allocating conveniences’ 16 MiB ceiling. Batch
record counts are meaningful on success; a size probe may return zero count.
`registry.TakeFile` and `TakeTransactionFile` adopt transferred descriptors.

Event policy is evaluated afresh per call, without retaining watch handles or a
cache. It implements the tier defaults and deepest valid `Enabled` value;
essential events bypass the registry. This favors a small concurrency-safe API
at the cost of extra registry operations on hot emission paths.

## Additional ownership and behavior contracts

- `security.Reinherit` resolves creator SIDs and generic rights for the receiving
  object, preserving explicit entry order and respecting DACL/SACL protection.
  `StripInherited` preserves descriptor metadata and ACL revision floors.
- `msgpack.Map` is an ordered list of pairs, so arbitrary keys and duplicate keys
  survive decoding. `Decoder` advances only on success; nesting defaults to 32.
  `Writer` supports header-first construction and sticky errors. `Reader` supports
  typed reads, header-only array/map reads and borrowed string/bin/ext slices.
  Its allocation-free iterative `Skip` has no depth ceiling. `Validate` accepts
  explicit depth limits 1..256; `Writer.Bytes` uses 256, while emit defaults to 32.
- `access.Check` returns the granted subset on `EACCES`. Access checks are advisory;
  the kernel still enforces the operation. Audit-context fields are caller claims.
- `Token.AdjustDefaults(nil, ...)` leaves the DACL unchanged; a non-nil empty slice
  clears it. Index `0xffff` leaves owner/group unchanged. Last-token release destroys
  a used dynamic session; `DestroyEmptySession` cleans up unused sessions.
- `socket.ReceivePartial` matches the C partial-message capability: it retains
  delivered handles and reports Linux `MSG_TRUNC`/`MSG_CTRUNC` flags. Excess
  handles close. `Receive` is the stricter convenience that closes all delivered
  handles on control truncation and returns `EMSGSIZE`. `Message.Close` releases
  owned handles. `Send` supports zero-payload seqpackets and returns partial writes
  without resending identity or handles.
- `process.SetMitigations` can only activate bits. `os/exec` launches children using
  the kernel's normal inheritance; no implicit token installation occurs.
- `registry/source.Source.Serve` owns and closes the source on return/cancellation,
  bounds handler concurrency, drains workers and reports transport failures.
  Handlers must observe cancellation and implement their storage/transaction policy.
  RSI decoders allow future trailing fields; callers decide their version policy.
- `event.AttachAll` enumerates the kernel's slot count, skipping offline holes.
  Reader events own their data and remain valid after the next read or close.
  `Next` is nonblocking; drain after `Wait(ctx)`. Cancellation/Close is checked at
  most every 50ms during a futex wait. `Lost` counts observed per-CPU sequence gaps,
  not events that disappeared before attachment. No global CPU ordering is invented.

`event.AttachFile` returns an owned ring fd and capacity; `MapRing` borrows it
only during mapping and owns its mmap independently. `Ring.Metadata`, `EventAt`,
`SetNeedWake` and `Wait` let callers drive absolute cursors and detect generation
changes. `EventAt` returns owned bytes and `EAGAIN` for empty/lapped/changed slots.
Unmapping never invalidates a returned event. Close the mapping separately from
the fd. A context deadline supplies a wait timeout; a canceled context permits a
nonblocking readiness check (readiness wins for `Ring.Wait`).

`token.OpenSessions` snapshots the listing; `SessionReader.Next` returns `io.EOF`
at the end and can continue after a malformed line. `ListSessions` is the
all-at-once convenience. Empty token claims specify `security.Claim.ValueType`.
Binary ACL parsers retain arbitrary revision bytes and object flags accepted by
the reference; `ACL.ExactRevision` preserves that byte on serialization. Typed
builders infer a normal revision unless exact preservation was requested.

## Verification

```sh
CGO_ENABLED=0 go test ./...
go test -race ./...
tools/conformance.sh
PEIOS_TEST_KERNEL=/path/to/bzImage tools/native-vm.sh
```

`tools/conformance.sh` requires sibling `pkm`, `libpeios` and `peios-rs` checkouts,
C/Rust toolchains and cached locked Rust dependencies. It rebuilds libpeios and
both drivers, invokes **the public C API and public Rust API separately**, and
compares exact wire bytes, canonical text and rejection outcomes. It never uses
libp-go as an oracle. Both references share libpeios internally, so independent
wire-layout, bounds, ownership and cleanup tests remain necessary.

The source baseline is in `conformance/references.json`; the run records actual
reference revisions and diffs in `build/conformance/sources.json`. The current
resource-attribute cases require the accompanying libpeios SDDL ACE-padding fix.
The unmodified baseline emits invalid unaligned ACEs for some variable payloads.
The copied corpus is canonical libpeios test data; its historical header mentions
the retired Go implementation, which is not executed by this harness.

`tools/check-uapi.py` checks vendored generated declarations and licenses against
the exact recorded PKM commit. For an ABI update, regenerate in PKM, copy its
`uapi/generated/go` declarations and licenses, change the recorded revision, and
rerun both host and native checks. Vocabulary tables are maintained from the
public libpeios SDDL vocabulary and checked against its canonical corpus.

The native runner builds a fresh initramfs, uses QEMU TCG without a network or
host mount, and records the kernel SHA-256 and serial log in `build/native`.
It checks token/file/access behavior against both reference APIs, token construction,
adjustment and session lifecycle, peer/message identity and descriptor transfer,
process security, ring consumption, and source-backed registry reads/writes,
transactions, notifications, backup/restore and layer management. The source fixture
has no persistent storage. The runner seeds only disposable tmpfs descriptors and
classifies its securityfs mount with the ephemeral synthesis policy used by the
integration suite; it does not change host policy or grant privileges. These tests
are not composed-release or real-hardware qualification.

The C/Rust conformance cases include full token recipes (all claim families and
LCS credentials), MessagePack encoding/acceptance, audit contexts and inheritance
combinations. RSI hosting has no public C/Rust counterpart: its maintained loregd
codec origin is recorded in `conformance/rsi-origin.json`, and native coverage uses
the real kernel request/reply protocol. No legacy Go binding is a reference.

The accompanying libpeios changes fix SDDL resource-ACE padding, a KMES
lost-wakeup window, and missing control-truncation flags when receive discards
excess handles. The unmodified baseline has those defects; conformance records
the exact local reference diff. A reproducible copy of those fixes is included in
`conformance/reference-patches/libpeios.patch`. From the SDK directory, apply it
once to a clean libpeios checkout at the revision in `conformance/references.json`
before running conformance:

```sh
git -C ../libpeios apply --check ../peios-go/conformance/reference-patches/libpeios.patch
git -C ../libpeios apply ../peios-go/conformance/reference-patches/libpeios.patch
```

This patch is for the test reference; the Go SDK has no runtime dependency on it.
Both event readers capture the futex counter
before the final write-position check.

Fuzz targets:

```sh
go test ./security -run '^$' -fuzz FuzzSDDL -fuzztime 30s
go test ./security -run '^$' -fuzz FuzzBinaryParsers -fuzztime 30s
go test ./msgpack -run '^$' -fuzz FuzzMessagePack -fuzztime 30s
go test ./msgpack -run '^$' -fuzz FuzzCursor -fuzztime 30s
go test ./event -run '^$' -fuzz FuzzRingEventAt -fuzztime 30s
go test ./access -run '^$' -fuzz FuzzAudit -fuzztime 30s
go test ./registry/source -run '^$' -fuzz FuzzRequest -fuzztime 30s
go test ./token -run '^$' -fuzz FuzzGroups -fuzztime 30s
```

MIT-licensed; the vendored kernel declarations retain their GPL-2.0-only WITH
Linux-syscall-note notices under `internal/uapi`.

The parity inventory is a capability audit, not a claim of exhaustive input or
error-path proof. Differential tests exercise the public C and Rust APIs, with
independent Go bounds/ownership/race checks. Native acceptance is Linux/amd64 on
the recorded Peios kernel, not a release image or hardware certification. The
Go runtime owns allocation failure behavior; C malloc/free and borrowed-view
lifecycles are represented by Go values, slices, GC and explicit fd/mmap Close.
