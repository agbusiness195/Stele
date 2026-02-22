# Kervyx Protocol - Python Implementation

A complete Python implementation of the Kervyx protocol core primitives for AI covenant management.

## Overview

This package implements the Kervyx protocol, providing:

- **Crypto** (`kervyx.crypto`) -- Ed25519 signing/verification, SHA-256 hashing, JCS canonicalization (RFC 8785)
- **CCL** (`kervyx.ccl`) -- Constraint Commitment Language parser and evaluator
- **Covenant** (`kervyx.covenant`) -- Covenant document build, verify, chain, serialize/deserialize
- **Identity** (`kervyx.identity`) -- Agent identity creation, evolution, verification
- **Store** (`kervyx.store`) -- In-memory covenant document storage

## Installation

```bash
pip install -e ".[dev]"
```

## Requirements

- Python >= 3.10
- cryptography >= 42.0

## Quick Start

```python
from kervyx import crypto, covenant

# Generate key pairs
issuer_kp = crypto.generate_key_pair()
beneficiary_kp = crypto.generate_key_pair()

# Build a covenant
doc = covenant.build_covenant({
    "issuer": {
        "id": "alice",
        "publicKey": issuer_kp["public_key_hex"],
        "role": "issuer",
    },
    "beneficiary": {
        "id": "bob",
        "publicKey": beneficiary_kp["public_key_hex"],
        "role": "beneficiary",
    },
    "constraints": "permit read on '/data/**'",
    "privateKey": issuer_kp["private_key"],
})

# Verify the covenant
result = covenant.verify_covenant(doc)
assert result["valid"]
```

## Running Tests

```bash
pytest
```

## Interoperability

This implementation produces output that is byte-compatible with the TypeScript
reference implementation. Key interoperability points:

- Ed25519 signatures use the same RFC 8032 encoding
- JSON canonicalization follows RFC 8785 (JCS)
- Document IDs are SHA-256 hashes of the canonical form
- All hex encoding uses lowercase
- Timestamps use ISO 8601 format with millisecond precision and Z suffix

## Protocol Version

This implementation targets Kervyx protocol version 1.0.
