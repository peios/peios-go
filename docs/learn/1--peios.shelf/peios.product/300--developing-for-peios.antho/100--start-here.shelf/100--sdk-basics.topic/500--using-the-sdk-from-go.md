---
title: Using the SDK from Go
type: how-to
description: Add the Go SDK to an application and parse a security descriptor.
---

Use `peios-go` to read Peios security formats and call native Peios
operations. The module uses Go directly; applications do not need a C
compiler or an installed C SDK library at runtime.

## Before you start

- Install Go 1.26 or later.
- Place the SDK checkout beside your application for this local example.
- Run native operations on a Peios kernel. Portable format parsers also
  work on other systems.

## Add the dependency

1. Add these entries to your application's `go.mod`:

   ```go
   require github.com/peios/peios-go v0.0.0
   replace github.com/peios/peios-go => ../peios-go
   ```

   The version is a local placeholder. Before publishing your application,
   use a published commit or release and remove the local replacement.

2. Create `main.go`:

   ```go
   package main

   import (
       "fmt"

       "github.com/peios/peios-go/security"
   )

   func main() {
       descriptor, err := security.ParseSDDL("O:SYG:BAD:(A;;FA;;;BA)")
       if err != nil {
           panic(err)
       }
       wire, err := descriptor.MarshalBinary()
       if err != nil {
           panic(err)
       }
       fmt.Printf("descriptor size: %d bytes\n", len(wire))
   }
   ```

3. Run `go run .` from your application directory.

## Check the result

The program prints the descriptor size. This example parses Security
Descriptor Definition Language (SDDL) without changing a system object.
Parsing validates structure; the kernel separately checks your authority
when you apply a descriptor.

Use `go doc github.com/peios/peios-go/security` for the package reference.
The repository's `docs/building.md` describes SDK development and tests.

## Audited access checks

[Audit Contexts in Go](~peios/sdk-basics/audit-contexts-in-go) uses the
maintained `access` package and explains how to handle denial separately from
an unsuccessful check.
