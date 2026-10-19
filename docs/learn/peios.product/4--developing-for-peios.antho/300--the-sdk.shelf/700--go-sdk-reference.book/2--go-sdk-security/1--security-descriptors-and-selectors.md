---
title: Security Descriptors and Selectors
description: Read and update selected descriptor components, including mandatory-integrity labels, through the Go SDK.
---

`security.SecurityInformation` is the bitmask that selects components of a
security descriptor. Use its named constants with file and registry descriptor
operations:

| Constant | Value | Selected component |
| --- | --- | --- |
| `security.InfoOwner` | `0x01` | Owner SID. |
| `security.InfoGroup` | `0x02` | Group SID. |
| `security.InfoDACL` | `0x04` | Discretionary ACL. |
| `security.InfoSACL` | `0x08` | Full system ACL. |
| `security.InfoLabel` | `0x10` | Mandatory-integrity label within the SACL. |

Combine selectors with `|`, for example `security.InfoOwner |
security.InfoDACL`. `InfoLabel` can accompany owner, group, or DACL selection,
but **must not be combined with `InfoSACL`**; the kernel rejects that
combination with `EINVAL`.

`InfoLabel` reads or writes a descriptor containing the label ACE in its SACL.
Its payload is not a raw integrity SID. Reading the label requires
`READ_CONTROL`; writing it requires `WRITE_OWNER`. Raising a label above the
caller's integrity also requires `SeRelabelPrivilege`. Selecting the full SACL
instead requires `ACCESS_SYSTEM_SECURITY`, gated by `SeSecurityPrivilege`.

Updates preserve components that were not selected. In particular, selecting
only `InfoLabel` changes the mandatory label without replacing the other SACL
entries. All selected components must pass their applicable authorization
checks.

## File descriptors

`file.GetDescriptor(f, info)` returns owned descriptor bytes;
`file.SetDescriptor(f, info, sd)` applies selected components from binary
descriptor bytes. Both accept `syscall.Conn`, including `*os.File`. The
path-relative variants are `file.GetDescriptorAt(dirfd, path, info, flags)`
and `file.SetDescriptorAt(dirfd, path, info, sd, flags)`.

For example, read and parse the mandatory label:

```go
package example

import (
    "os"

    "github.com/peios/peios-go/file"
    "github.com/peios/peios-go/security"
)

func readLabel(f *os.File) (security.Descriptor, error) {
    wire, err := file.GetDescriptor(f, security.InfoLabel)
    if err != nil {
        return security.Descriptor{}, err
    }
    return security.ParseDescriptor(wire)
}
```

To request a medium-integrity, no-write-up label, build the descriptor and
select only its label:

```go
func setMediumLabel(f *os.File) error {
    sd, err := security.ParseSDDL("S:(ML;;NW;;;ME)")
    if err != nil {
        return err
    }
    wire, err := sd.MarshalBinary()
    if err != nil {
        return err
    }
    return file.SetDescriptor(f, security.InfoLabel, wire)
}
```

The second example uses the first example's imports. These functions perform
native Peios operations and still depend on the caller's authority;
constructing valid SDDL does not grant permission to set it.

## Registry keys

`(*registry.Key).GetDescriptor(info)` returns binary descriptor bytes, and
`(*registry.Key).SetDescriptor(info, sd, tx)` writes selected components. They
use the same `security.Info*` selectors, including `InfoLabel`, and the same
prohibition on combining label and full-SACL selection. Pass a
`*registry.Transaction` for a transactional update, or `nil` for an update
without an explicit transaction.

Use `security.ParseDescriptor` to decode returned bytes and
`Descriptor.MarshalBinary` to encode a descriptor for an update.
`security.ParseSDDL` is available when constructing a descriptor from text. An
absent DACL and an empty DACL are different: preserve that distinction when
building or rewriting descriptors.
