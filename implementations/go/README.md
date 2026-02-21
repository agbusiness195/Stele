# Grith Go Implementation

A complete Go implementation of the Grith protocol for cryptographic accountability of AI agents.

## Overview

This package implements the core Grith protocol primitives:

- **Crypto** (`crypto.go`) -- Ed25519 signing/verification, SHA-256 hashing, JCS (RFC 8785) JSON canonicalization
- **CCL** (`ccl.go`) -- Covenant Constraint Language parser and evaluator with wildcard matching, rate limits, and narrowing validation
- **Covenant** (`covenant.go`) -- Covenant document building, signing, verification (11 checks), countersigning, chaining, and serialization
- **Identity** (`identity.go`) -- Agent identity creation, evolution with lineage chains, and reputation carry-forward
- **Store** (`store.go`) -- Thread-safe in-memory covenant storage

## Requirements

- Go 1.21 or later
- No external dependencies (standard library only)

## Installation

```bash
go get github.com/agbusiness195/grith/implementations/go
```

## Quick Start

```go
package main

import (
    "fmt"
    grith "github.com/agbusiness195/grith/implementations/go"
)

func main() {
    // Generate key pairs
    issuerKP, _ := grith.GenerateKeyPair()
    beneficiaryKP, _ := grith.GenerateKeyPair()

    // Build a covenant
    doc, _ := grith.BuildCovenant(&grith.CovenantBuilderOptions{
        Issuer: grith.Party{
            ID:        "alice",
            PublicKey: issuerKP.PublicKeyHex,
            Role:      "issuer",
        },
        Beneficiary: grith.Party{
            ID:        "bob",
            PublicKey: beneficiaryKP.PublicKeyHex,
            Role:      "beneficiary",
        },
        Constraints: "permit read on '/data/**'\ndeny read on '/data/secret'",
        PrivateKey:  issuerKP.PrivateKey,
    })

    // Verify the covenant
    result, _ := grith.VerifyCovenant(doc)
    fmt.Println("Valid:", result.Valid)

    // Evaluate CCL constraints
    ccl, _ := grith.Parse(doc.Constraints)
    eval := grith.Evaluate(ccl, "read", "/data/users", nil)
    fmt.Println("Permitted:", eval.Permitted)
}
```

## Testing

```bash
go test -v ./...
```

## Protocol Version

This implementation targets Grith protocol version 1.0.

## Architecture

### Crypto

| Function | Description |
|---|---|
| `GenerateKeyPair()` | Generate Ed25519 key pair |
| `Sign(message, privateKey)` | Sign bytes with Ed25519 |
| `Verify(message, signature, publicKey)` | Verify Ed25519 signature |
| `SHA256Hex(data)` | SHA-256 hash as hex string |
| `SHA256Object(obj)` | Canonicalize then hash |
| `CanonicalizeJSON(obj)` | JCS (RFC 8785) serialization |
| `GenerateNonce()` | 32 random bytes |
| `ConstantTimeEqual(a, b)` | Timing-safe comparison |
| `Timestamp()` | ISO 8601 UTC timestamp |

### CCL

| Function | Description |
|---|---|
| `Parse(source)` | Parse CCL source to document |
| `Evaluate(doc, action, resource, ctx)` | Evaluate access control decision |
| `MatchAction(pattern, action)` | Dot-separated wildcard matching |
| `MatchResource(pattern, resource)` | Slash-separated wildcard matching |
| `CheckRateLimit(doc, metric, count, start, now)` | Rate limit checking |
| `ValidateNarrowing(parent, child)` | Constraint narrowing validation |
| `Merge(parent, child)` | Merge two CCL documents |
| `Serialize(doc)` | Serialize back to CCL source |

### Covenant

| Function | Description |
|---|---|
| `BuildCovenant(opts)` | Build and sign a new covenant |
| `VerifyCovenant(doc)` | Run all 11 verification checks |
| `CountersignCovenant(doc, kp, role)` | Add countersignature |
| `SerializeCovenant(doc)` | Serialize to JSON |
| `DeserializeCovenant(json)` | Deserialize from JSON |
| `CanonicalForm(doc)` | Compute canonical form |
| `ComputeID(doc)` | Compute document ID |
| `ValidateChainNarrowing(child, parent)` | Validate chain constraints |

### Identity

| Function | Description |
|---|---|
| `CreateIdentity(opts)` | Create new agent identity |
| `EvolveIdentity(current, opts)` | Evolve existing identity |
| `VerifyIdentity(identity)` | Verify identity signature |
| `ComputeEffectiveCarryForward(identity)` | Compute reputation carry-forward |

### Store

| Type | Description |
|---|---|
| `Store` | Interface for covenant storage |
| `MemoryStore` | Thread-safe in-memory implementation |

## License

See the repository root LICENSE file.
