---
title: Overview
description: How the Go SDK owns data, reports errors, and uses native authority.
---

The Go SDK uses Go values and interfaces for portable formats and native
Peios operations. Its package documentation describes each public API;
this chapter explains the ownership and authority rules shared by them.

## Packages and authority

Security formats and MessagePack codecs run without a Peios kernel.
Native file, token, socket, process, registry, and event operations target
Linux on x86-64 with the Peios kernel interface. Compiling on another Linux
system does not supply those operations.

Native errors use `syscall.Errno` and support `errors.Is`. An access check
reports a decision; the kernel still checks authority when you perform
the operation. Process creation uses Go's `os/exec` and normal kernel
inheritance. Activating process mitigations cannot clear existing bits.

## Handles and buffers

Close owned token, key, transaction, and file handles. Operations accepting
`syscall.Conn` protect a descriptor from concurrent close and reuse during
the call. A raw directory descriptor remains your responsibility: keep it
open throughout the operation.

Descriptor parsers and event readers return owned data. Borrowed
MessagePack cursor views remain tied to the caller's input buffer.
MessagePack maps preserve pair order and duplicate keys. Decoder position
advances only after a successful decode.

## Identity scopes

`Token.Impersonate` runs its callback on a dedicated, locked thread.
The scope restores identity before returning and retires the thread if
restoration fails. A callback panic is rethrown after cleanup.

`WithIdentityThread` supports repeated identity changes within one locked
thread. The scope rejects calls after the callback or from another thread.
Neither API transfers its identity to goroutines created by the callback.
Installing a process token is a separate operation.

## Security formats

Binary descriptors retain entry order, unknown entry bodies, and metadata
that text cannot express. Text formatting rejects unsupported entries
rather than discarding them. An absent discretionary access control list
(DACL) differs from an empty one. The present-null form is rejected.

Conditions have a 128-level expression limit, including long AND or OR
chains. Parsing rejects deeper expressions with `EINVAL`, matching the
formatter. Nested operands also have a depth bound.

Inheritance resolves creator identities and generic rights for the
receiving object. It preserves explicit entries and protected lists.
Stripping inherited entries preserves descriptor metadata and revision
floors. Parsed lists can retain exact revision bytes during serialization.
