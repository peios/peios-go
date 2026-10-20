---
title: Audit Contexts in Go
type: concept
description: Use the maintained access package to encode object descriptions and interpret access-check results.
---

The `github.com/peios/peios-go/access` package provides portable audit-context
encoding and native access checks. Attach the encoded object description to
`access.Request` so the kernel can identify the object in an audit record.
The context does not grant authority or replace the security descriptor.

[The Audit Context](~peios/sdk-access/the-audit-context) defines the common
encoding. [Access Decisions](~specifications/pgss/events/access-decisions)
explains when a daemon supplies it and how its claims are marked.

## Encode and check

This helper checks an illustrative service using an existing token handle and
security descriptor. Native checks require a Peios kernel on Linux/amd64.

```go
package example

import (
	"syscall"

	"github.com/peios/peios-go/access"
	"github.com/peios/peios-go/security"
)

func CheckService(
	caller syscall.Conn,
	descriptor []byte,
	desired security.AccessMask,
	mapping security.GenericMapping,
) (access.Result, error) {
	context, err := access.AuditContext("service", []access.Field{
		{Name: "name", Value: "jellyfin"},
	})
	if err != nil {
		return access.Result{}, err
	}
	return access.Check(access.Request{
		Token:        caller,
		Descriptor:   descriptor,
		Desired:      desired,
		Mapping:      mapping,
		AuditContext: context,
	})
}
```

Use the actual service name and its object-specific mapping. Define the
asserted fields in the owning event catalog fragment. A nil `Token` selects
the calling thread's effective token; it does not mean an anonymous client.
Pass the intended caller explicitly when checking another principal's access.

`access.Check` returns `syscall.EACCES` for denial, retaining the granted
subset and audit outputs in its result. Other errors mean the check could not
complete. This differs from the Rust wrapper, which represents denial in
`AccessDecision.allowed`. Do not ignore a Go error because a result was
returned.

`CheckList` returns per-node decisions for an object tree. Inspect each node's
`Status`; a successful call does not mean every node grants the requested
access.

## Encode values deliberately

Each `access.Field` pairs a name with a value. The encoder accepts strings,
booleans, byte slices, and signed or unsigned integer types. Pass a SID's
`Bytes()` result for a binary security identifier, not the SID object or its
text form. Floating-point values, nested objects, and nil are not constructor
field values.

Names are single kebab-case segments, repeated keys are rejected, and the
encoded context is limited to 4096 bytes. An empty field list emits only the
object kind. The encoder returns `access.ErrAuditContext` for invalid context
structure and can also return an encoding error.

The returned byte slice owns its encoding. Keep its contents unchanged until
the check completes. Do not reuse it concurrently as a mutable work buffer.

## Validate an existing map

Call `access.ValidateAuditContext` when another encoder built the bytes.
Its structural validation is broader than the scalar-field constructor; it
is not proof that the values match the catalog or describe the real object.

Both native check variants validate a non-nil `Request.AuditContext` before
calling the kernel. Nil omits the context; a non-nil empty slice is invalid.
For a daemon-owned object that requires an audit context, omission is not a
substitute for handling an encoding error.

The historical `libp-go/sd` constructors and `CheckRequest` examples do not
apply to this API. Use `access.AuditContext`, `access.Field`, and
`access.Request` from the maintained module.
