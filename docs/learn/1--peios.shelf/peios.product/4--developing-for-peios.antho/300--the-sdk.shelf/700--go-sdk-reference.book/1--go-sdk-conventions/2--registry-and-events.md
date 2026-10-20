---
title: Registry and Event Lifetimes
description: Resource ownership and progress when reading registry values and events.
---

Registry keys and event rings expose state that can change while your
application reads it. The Go SDK gives returned data an explicit lifetime
and reports changes that prevent a complete read.

## Registry values and sources

Registry writes use the base layer when `Layer` is empty. A nil or zero
expected sequence disables compare-and-set. Delete operations reject an
expected sequence because their kernel operation has no comparison field.
Notifications are armed and read on the same key handle.

Allocating value helpers have a 16 MiB limit. `QueryInto`, `ValuesInto`,
and `ValueAtInto` accept caller buffers; a nil buffer probes the required
size and returns `ERANGE`. Batch counts are meaningful on success, and a
size probe can report zero records.

`TakeFile` and `TakeTransactionFile` transfer descriptor ownership into
registry handles. Close the resulting handle rather than closing its
adopted descriptor separately.

`registry/source.Source.Serve` bounds concurrent handlers and serializes
response writes. It closes the source on return or cancellation, waits
for workers, and reports transport errors. Handlers must observe
cancellation and provide storage and transaction semantics. Decoders
permit trailing extension fields; the handler chooses its version policy.

## Events and waits

`AttachAll` visits the complete CPU slot range and skips empty slots.
Each reader begins at its oldest surviving record and follows resizes.
Returned events own their data and survive subsequent reads or closure.

Drain `Next` until no event is available, then wait with `Wait(ctx)`.
Cancellation or close can take up to 50 ms to interrupt a futex wait.
`Lost` counts observed sequence gaps, not losses before attachment.
Readers do not establish an ordering between different CPUs.

Low-level attachments and mappings have separate lifetimes: close both.
`EventAt` returns owned data and a wire size, or `EAGAIN` for an empty,
overwritten, or changed slot. Advance the absolute cursor by the wire
size. A generation change requires a fresh attachment and mapping.

A context deadline bounds `Ring.Wait`. A canceled context permits a
nonblocking readiness check; available data takes precedence over
cancellation in that low-level method.

Emission policy is read afresh for each call. Essential events bypass
registry policy; other tiers use defaults and the deepest valid `Enabled`
value. This avoids retained watch handles at the cost of registry work
on each policy check.

## Messages and sessions

A received socket message owns its delivered handles. Call `Message.Close`
when finished. `Receive` closes all delivered handles if control data is
truncated. `ReceivePartial` keeps handles that fit, closes excess handles,
and reports truncation flags for the caller to assess.

A partial send does not resend ancillary data. Zero-length sequence-packet
messages can transfer handles without an extra payload byte.

`OpenSessions` returns a snapshot reader. `Next` returns `io.EOF` at the
end; a malformed line returns `EPROTO` and is consumed so reading can
continue. Closing the last token destroys a used dynamic session.
`DestroyEmptySession` handles an unused session. Session enumeration
requires the appropriate classified securityfs mount and access rights.
