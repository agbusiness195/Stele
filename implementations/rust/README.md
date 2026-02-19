# Stele - Rust Implementation

The accountability primitive for AI agents, implemented in Rust.

## Overview

This crate provides a complete Rust implementation of the Stele protocol, covering
all core primitives needed for interoperability with the reference TypeScript
implementation.

### Modules

- **`crypto`** - Ed25519 signing/verification, SHA-256 hashing, JCS (RFC 8785) JSON
  canonicalization, nonce generation, timestamps, and constant-time comparison.
- **`ccl`** - Covenant Constraint Language parser and evaluator. Supports `permit`,
  `deny`, `require`, and `limit` statements with wildcard matching (`*`, `**`),
  conditions, specificity-based conflict resolution, rate limiting, narrowing
  validation, and merging.
- **`covenant`** - Covenant document building, 11-check verification, countersigning,
  chain references, serialization/deserialization, and chain narrowing validation.
- **`identity`** - Agent identity creation, evolution with hash-linked lineage chains,
  verification, and serialization.
- **`store`** - `Store` trait and `MemoryStore` implementation for covenant storage.

## Building

```bash
cargo build
```

## Testing

```bash
cargo test
```

## Usage

```rust
use stele::crypto;
use stele::covenant::{self, CovenantBuilderOptions, Party};
use stele::ccl;
use stele::identity::{self, CreateIdentityOptions, ModelInfo, DeploymentInfo};
use stele::store::{MemoryStore, Store};

// Generate key pairs
let issuer_kp = crypto::generate_key_pair().unwrap();
let beneficiary_kp = crypto::generate_key_pair().unwrap();

// Build a covenant
let doc = covenant::build_covenant(CovenantBuilderOptions {
    issuer: Party {
        id: "operator".to_string(),
        public_key: issuer_kp.public_key_hex.clone(),
        role: "issuer".to_string(),
    },
    beneficiary: Party {
        id: "agent".to_string(),
        public_key: beneficiary_kp.public_key_hex.clone(),
        role: "beneficiary".to_string(),
    },
    constraints: "permit read on '/data/**'".to_string(),
    signing_key: issuer_kp.signing_key,
    chain: None,
    expires_at: None,
    activates_at: None,
    metadata: None,
}).unwrap();

// Verify the covenant (11 checks)
let result = covenant::verify_covenant(&doc).unwrap();
assert!(result.valid);

// Evaluate CCL constraints
let ccl_doc = ccl::parse("permit read on '/data/**'").unwrap();
let ctx = std::collections::HashMap::new();
let eval = ccl::evaluate(&ccl_doc, "read", "/data/users", &ctx);
assert!(eval.permitted);
```

## Protocol Version

This implementation targets Stele Protocol v1.0.

## License

MIT
