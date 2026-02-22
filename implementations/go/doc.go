// Package kervyx provides a Go implementation of the Kervyx protocol for
// cryptographic accountability of AI agents.
//
// Kervyx introduces behavioral commitments as a first-class primitive for
// AI agents. Before acting, an agent inscribes a covenant -- a signed,
// content-addressed document specifying its intended behavior, constraints,
// and scope. During operation, every action is logged against this covenant
// in a tamper-evident structure. After execution, any party can independently
// verify compliance without access to the agent, its operator, or any
// privileged system.
//
// This package implements the core protocol primitives:
//
//   - Cryptographic operations (Ed25519 signing, SHA-256 hashing, JCS canonicalization)
//   - Covenant Constraint Language (CCL) parsing and evaluation
//   - Covenant document building, signing, verification, and chaining
//   - Agent identity creation and evolution
//   - In-memory covenant storage
//
// All cryptographic operations use Go's standard library. No external
// dependencies are required.
//
// # Protocol Version
//
// This implementation targets Kervyx protocol version 1.0.
//
// # CCL Grammar
//
// The Covenant Constraint Language supports four statement types:
//
//   - permit/deny ACTION on RESOURCE [when CONDITION]
//   - require ACTION on RESOURCE [when CONDITION]
//   - limit ACTION COUNT per PERIOD TIME_UNIT
//
// Actions use dot-separated segments with * and ** wildcards.
// Resources use slash-separated segments with * and ** wildcards.
// Evaluation follows default-deny semantics where deny wins over permit.
//
// # Covenant Documents
//
// A covenant document contains issuer and beneficiary parties, CCL
// constraints, a cryptographic nonce, timestamps, and an Ed25519
// signature. Documents are content-addressed via SHA-256 of their
// canonical (JCS) form.
//
// # Verification
//
// Covenant verification performs 11 checks: id_match, signature_valid,
// not_expired, active, ccl_parses, enforcement_valid, proof_valid,
// chain_depth, document_size, countersignatures, and nonce_present.
package kervyx
