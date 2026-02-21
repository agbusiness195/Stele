# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-12

### Added

#### Interop Layer
- **@usekova/discovery**: `.well-known/kova/` discovery protocol with `DiscoveryServer`,
  `DiscoveryClient`, agent key registry, and capability negotiation.
- **@usekova/schema**: JSON Schema (Draft 2020-12) for `CovenantDocument`,
  `DiscoveryDocument`, and `AgentKeyEntry` with `validateCovenantDocument()`,
  `validateDiscoveryDocument()`, and `validateAgentKeyEntry()`.

#### Testing & Verification
- **Conformance Suite**: 5th category `securityConformance` covering nonce uniqueness,
  ID uniqueness, empty/zero signature rejection, private key length, and public key
  hex consistency. Total conformance checks now 40+.
- **Test Vectors**: 56 canonical test vectors in `test-vectors/canonical-vectors.json`
  for cross-implementation verification.
- **Benchmarks**: `runBenchmarkSuite()` with 13 operations, p99 SLA targets, and
  histogram reporting.

#### Developer Experience
- **@usekova/cli**: Shell completions for Bash, Zsh, and Fish; `kova doctor`
  environment diagnostics; JSON/table output formatting; config file management.

### Changed
- Raised coverage thresholds from 80/75/80/80 to 99/97/99/99.
- Updated all error constructors to use `KovaErrorCode` enum consistently.
- Added `@types/node` for proper TypeScript type coverage of Node.js globals.
- Fixed 224 TypeScript strict-mode errors across the entire codebase.
- Updated README badges to reflect actual counts (5,158+ tests, 85 suites, 34 packages).

### Fixed
- TypeScript `TextEncoder`, `btoa`, `atob`, `process`, `console` references now
  properly resolved via `@types/node`.
- Strict null check errors in test and source files (TS2532, TS18048).
- `KovaErrorCode` type mismatches in negotiation, consensus, and temporal packages.
- Removed `as any` casts from conformance suite in favour of proper type assertions.

## [0.1.0] - 2025-02-07

### Added

#### Foundation Layer
- **@usekova/types**: Shared error classes (`KovaError`, `ValidationError`, `CryptoError`,
  `CCLError`, `ChainError`, `StorageError`), validation utilities (`validateNonEmpty`,
  `validateRange`, `validateHex`, `validateProbability`), `Result<T, E>` type,
  runtime type guards, input sanitization, and structured logging with levels and
  child loggers.
- **@usekova/crypto**: Ed25519 key generation, signing, and verification via
  `@noble/ed25519`; SHA-256 hashing; canonical JSON (JCS / RFC 8785);
  hex and base64url encoding; constant-time comparison; nonce generation.
- **@usekova/ccl**: Covenant Constraint Language (CCL) with `permit`, `deny`,
  `require`, and `limit` statements; `when` conditional clauses; glob-based
  resource matching; deny-wins merge semantics; narrowing validation; serialization.
- **@usekova/core**: Covenant document lifecycle -- `buildCovenant`, `verifyCovenant`
  (11 specification checks), `countersignCovenant`, `resignCovenant`, chain
  resolution, effective constraint computation, narrowing validation, and
  JSON serialization/deserialization.
- **@usekova/store**: Pluggable `CovenantStore` interface with `MemoryStore` (in-memory)
  and `FileStore` (persistent, atomic writes) implementations; event system for
  put/delete notifications; batch operations; filtered listing.
- **@usekova/verifier**: Standalone `Verifier` class with single, chain, action, and
  batch verification; history tracking; strict mode with warning escalation.
- **@usekova/sdk**: Unified `KovaClient` entry point combining key management,
  covenant lifecycle, identity management, chain operations, and CCL utilities;
  `QuickCovenant` convenience builders; typed event system with 8 event types.
- **@usekova/identity**: Agent identity with model attestation, capabilities, deployment
  context, lineage tracking, evolution with carry-forward rates, and cryptographic
  verification.

#### Enforcement Layer
- **@usekova/enforcement**: Runtime `Monitor` with CCL evaluation, rate limiting,
  hash-chained audit logging, and capability manifests.
- **@usekova/proof**: Poseidon-based compliance proofs -- audit commitment, constraint
  commitment, proof generation, and verification.
- **@usekova/breach**: Breach attestation with severity-based trust status mapping,
  trust graph management, and cryptographic verification.
- **@usekova/reputation**: Reputation scoring with recency decay, breach penalties,
  staking, delegation, and endorsements.
- **@usekova/mcp**: MCP guard wrapping MCP servers with Kova enforcement, audit
  logging, identity creation, and compliance proof generation; named presets.

#### Protocol Layer
- **@usekova/attestation**: External attestation creation, reconciliation, chain
  linking, and coverage analysis.
- **@usekova/canary**: Canary testing with challenge generation from CCL constraints,
  scheduled execution, and result correlation.
- **@usekova/gametheory**: Game-theoretic honesty proofs with minimum stake computation.
- **@usekova/composition**: Formal constraint composition with system-property checking,
  decomposition, and complexity analysis.
- **@usekova/antifragile**: Breach-to-antibody generation, network health assessment,
  stress testing, governance proposals, and antifragility indexing.
- **@usekova/negotiation**: Multi-party negotiation sessions with proposal workflows,
  Nash bargaining solutions, and Pareto optimality.
- **@usekova/consensus**: Accountability-score-based tier classification and access
  decisions with configurable component weights.
- **@usekova/robustness**: Input bound verification, vulnerability scanning, formal
  verification, contradiction detection, and robustness scoring.
- **@usekova/temporal**: Trigger-based constraint evolution, trust decay modeling,
  violation tracking, and expiration forecasting.
- **@usekova/recursive**: Meta-covenants, recursive verification, termination proofs,
  transitive trust computation, and minimal verification sets.
- **@usekova/alignment**: HHH (Helpful, Honest, Harmless) alignment properties,
  alignment verification, drift detection, and decomposition.
- **@usekova/norms**: Emergent norm discovery, clustering, governance proposals,
  template creation, conflict detection, and precedence resolution.
- **@usekova/substrate**: Cross-substrate adapters for AI agents, robots, IoT devices,
  autonomous vehicles, smart contracts, and drones; constraint translation and
  safety bounds.
- **@usekova/derivatives**: Trust futures, agent insurance policies, risk assessment
  with configurable weights, and settlement.
- **@usekova/legal**: Legal identity packages, compliance checking, jurisdictional
  mapping, cross-jurisdiction analysis, audit trail export, and regulatory gap analysis.

#### Platform Layer
- **@usekova/react**: Framework-agnostic reactive primitives (`Observable`,
  `CovenantState`, `IdentityState`, `StoreState`).
- **@usekova/evm**: EVM anchoring utilities -- ABI encoding/decoding, function
  selector computation, covenant anchoring, and anchor verification.
- **@usekova/mcp-server**: JSON-RPC 2.0 MCP server with 6 tools (`create_covenant`,
  `verify_covenant`, `evaluate_action`, `create_identity`, `parse_ccl`,
  `list_covenants`).
- **@usekova/cli**: Command-line interface for key generation, covenant build/verify/
  inspect/resign, CCL parsing, and identity create/evolve.

#### Infrastructure
- CI/CD pipeline with matrix testing across Node.js 18, 20, and 22.
- 3,251 tests across 41 test suites, all passing.
- 7 runnable examples in the `examples/` directory.
- Full API documentation in `docs/api/README.md`.
- Architecture documentation in `docs/architecture.md`.
