---
title: Overview
description: Where peios-go fits, what its packages expose, and how native calls report errors and own resources.
---

`github.com/peios/peios-go` is the independent, pure-Go Peios SDK. Applications do not need cgo, libpeios, or libp-go at runtime. The API uses Go values and standard interfaces rather than reproducing each C function's calling convention.

This book documents the Go API. The [source repository](https://github.com/peios/peios-go) contains package documentation and a per-symbol conformance inventory. Start with [security descriptors and selectors](~peios/go-sdk-security/security-descriptors-and-selectors) for reading or changing an object's security metadata.

## Packages

| Package | Purpose |
| --- | --- |
| `security` | Portable SIDs, GUIDs, ACLs, descriptors, SDDL, conditions, claims, and inheritance. |
| `msgpack` | Portable MessagePack encoding, decoding, cursors, and validation. |
| `access` | Audit contexts and native access checks. |
| `file` | Native file creation/opening, security descriptors, System V IPC descriptors, and mount policy. |
| `token` | Token specifications and native identity, sessions, adjustments, and impersonation. |
| `socket` | Peer identity, message identity, and descriptor transfer. |
| `process` | Process security-block queries and mitigation activation; ordinary process creation uses Go's `os/exec`. |
| `registry` | Keys, values, descriptors, notifications, transactions, layers, and backup/restore. |
| `registry/source` | Portable registry-source codecs and native source hosting. |
| `event` | Event emission, policy, record decoding, rings, and readers. |

Native operations target Linux/amd64 with the Peios kernel ABI. Compiling an application on ordinary Linux does not supply that ABI: unsupported system calls return `syscall.ENOSYS`. Portable functionality, including `security` and `msgpack`, can also run on other operating systems.

## Errors and ownership

Native errors use `syscall.Errno` and support `errors.Is`. Check the error before using a result; parsing a descriptor verifies its binary structure, not whether the caller may install it on a particular object. The kernel still enforces authorization on native operations.

Descriptor parsers and encoders return Go-owned values and bytes. Close owned native handles when finished. File operations accepting `syscall.Conn`, including an `*os.File`, protect the descriptor against concurrent close and reuse during the call. Raw `dirfd` arguments are borrowed: the caller must keep them open for the entire operation.

Binary descriptors preserve information that SDDL cannot always express. Use binary parsing and encoding when preserving unknown ACEs or descriptor control metadata matters; SDDL formatting can reject an ACE or payload it cannot represent.
