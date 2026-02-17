# Roadmap

This document tracks planned work for the Stele project. Items are grouped by
release milestone and ordered roughly by priority within each group.

## v0.2.1 -- Polish & Publish

- [ ] Publish all stable-tier packages to npm under the `@stele` scope
- [ ] Generate and host TypeDoc API documentation site
- [x] Add production deployment guide (HSM/KMS integration patterns)
- [x] Add performance tuning guide
- [x] Add encrypted-at-rest storage backend (`EncryptedStore`)
- [x] Add key rotation ceremony with revocation list (`KeyManager`)
- [x] Add health check / readiness probe utilities
- [x] Fix example imports, placeholder comments, badge counts
- [x] Add ROADMAP.md and update CHANGELOG

## v1.0.0 -- Stable Release

### Security

- [ ] Engage a third-party firm to audit `@stele/crypto`, `@stele/ccl`, and
      `@stele/core` (scope defined in THREAT_MODEL.md)

### Protocol

- [ ] Formalize the covenant document schema, CCL grammar, and verification
      algorithm as a versioned specification independent of the TypeScript
      implementation
- [ ] Expand `runConformanceSuite()` to cover all 11 verification checks and
      all CCL edge cases for cross-implementation validation

### Adapters

- [ ] Promote Express, Vercel AI SDK, and LangChain adapters from beta to
      stable based on production usage feedback

## v2.0.0 -- Multi-Language & Ecosystem

- [ ] Implement the protocol in Python
- [ ] Implement the protocol in Go
- [ ] Implement the protocol in Rust
- [ ] Design a decentralized key discovery and attestation mechanism
- [ ] Deploy an on-chain verification smart contract for `@stele/evm`
- [ ] Explore standardization of the covenant document format and CCL through
      an appropriate standards body

## Non-Goals

These items are explicitly out of scope for the foreseeable future:

- **Transport-layer security**: Stele is a document-level protocol. TLS and
  network security are the responsibility of the transport layer.
- **Built-in key storage**: Stele handles key _use_, not key _storage_.
  Integrators should use HSMs, KMS, or encrypted keyrings.
- **GUI applications**: The CLI and reactive primitives are the primary
  interfaces. A standalone GUI is not planned.
