# Stele Architecture

This document describes the architecture of the Stele SDK monorepo.

## Design Principles

1. **Layered dependencies** — Packages form strict layers. Lower layers never import from higher layers.
2. **Zero-dependency enterprise** — Enterprise features have no internal dependencies, making them safe to extract or replace.
3. **Three entry points** — Users choose their level of engagement: `@stele/sdk` (core), `@stele/protocols` (extensions), `@stele/enterprise` (business features).
4. **Default deny** — CCL evaluation returns `{ permitted: false }` when no rules match.
5. **Bring your own X** — SQLite driver, OpenTelemetry tracer, and framework adapters accept user-provided implementations rather than bundling heavy dependencies.

## Package Layers

```
Layer 6  react, mcp-server              ← Framework bindings
Layer 5  sdk, cli                        ← High-level API
Layer 4  verifier, mcp, protocols        ← Integration & aggregation
Layer 3  breach, enforcement, discovery,
         store, reputation, evm          ← Protocol services
Layer 2  core, alignment, canary,
         composition, norms, proof,
         robustness                      ← Core protocols
Layer 1  ccl, identity, attestation,
         gametheory, legal, derivatives,
         negotiation, recursive,
         substrate, temporal, schema,
         antifragile, consensus          ← Primitives
Layer 0  types, crypto                   ← Foundation (mutual dependency)
         enterprise                      ← Zero-dependency (standalone)
```

## Dependency Flow

```
                    ┌─────────┐
                    │  react  │
                    │mcp-server│
                    └────┬────┘
                         │
                    ┌────┴────┐
                    │   sdk   │
                    │   cli   │
                    └────┬────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
         ┌────┴──┐  ┌───┴───┐  ┌──┴────┐
         │verify-│  │enforce-│  │ store │
         │  er   │  │  ment  │  │       │
         └───┬───┘  └───┬───┘  └───┬───┘
             │          │          │
         ┌───┴──────────┴──────────┴───┐
         │            core             │
         └─────────────┬───────────────┘
                       │
           ┌───────────┼───────────┐
           │           │           │
        ┌──┴──┐    ┌───┴───┐   ┌──┴──┐
        │ ccl │    │identity│   │ ... │  (20 protocol packages)
        └──┬──┘    └───┬───┘   └──┬──┘
           │           │          │
        ┌──┴───────────┴──────────┴──┐
        │       types + crypto       │
        └────────────────────────────┘
```

## Package Categories

### Foundation (Layer 0)

| Package | Purpose |
|---------|---------|
| `@stele/types` | Shared types, errors, utilities, logging |
| `@stele/crypto` | Ed25519 signing, SHA-256, key management |

### Core SDK (Layer 1-5, via `@stele/sdk`)

| Package | Purpose |
|---------|---------|
| `@stele/ccl` | Covenant Constraint Language parser and evaluator |
| `@stele/core` | Covenant lifecycle (build, verify, countersign, chain) |
| `@stele/identity` | Agent identity with lineage tracking |
| `@stele/store` | Pluggable storage (Memory, File, SQLite) |
| `@stele/verifier` | Standalone verification engine |
| `@stele/enforcement` | Runtime enforcement (Monitor, CapabilityGate, AuditChain) |
| `@stele/sdk` | SteleClient, middleware, adapters, conformance |

### Protocols (Layer 1-3, via `@stele/protocols`)

20 protocol packages covering breach detection, reputation, game theory,
consensus, attestation, canary, proof, composition, alignment, negotiation,
temporal, robustness, recursive, discovery, schema, antifragile, norms,
substrate, derivatives, and legal.

### Enterprise (Layer 0, via `@stele/enterprise`)

10 zero-dependency modules: trust-gate, certification, dashboard, analytics,
gateway, governance, i18n, payments, rail, fees.

### Platform (Layer 6)

| Package | Purpose |
|---------|---------|
| `@stele/react` | React hooks (`useCovenant`, `useSteleClient`) |
| `@stele/mcp-server` | Model Context Protocol server implementation |
| `@stele/cli` | Command-line interface (`stele verify`, `stele audit`) |

## Key Architectural Decisions

### Why three packages instead of one?

The SDK was originally a single 2,117-line barrel file re-exporting 431 symbols from 28 dependencies. This caused:
- Large bundle sizes for users who only needed `SteleClient`
- Confusing API surface with protocol-specific and enterprise functions mixed together
- Slow IDE autocomplete from hundreds of irrelevant exports

The split into `sdk` (126 exports, 8 deps), `protocols` (facade over 20 packages), and `enterprise` (10 standalone modules) gives users a clear decision tree:
- "I want to build with Stele" → `@stele/sdk`
- "I need breach detection / reputation / game theory" → `@stele/protocols`
- "I need analytics / payments / governance" → `@stele/enterprise`

### Why zero-dependency enterprise modules?

Enterprise features (trust-gate, payments, fees, etc.) are pure business logic with no cryptographic or protocol dependencies. Keeping them dependency-free means:
- They can be extracted into a separate repo if needed
- They don't pull in the crypto stack for simple fee calculations
- They serve as templates for custom business logic

### Why Bring-Your-Own-SQLite?

The `SqliteStore` accepts a `SQLiteDriver` interface rather than depending on `better-sqlite3` or `sql.js`. This lets users bring whichever SQLite binding works in their runtime (Node.js, Bun, Cloudflare D1, etc.) without bundling a native addon.

### Why Noop telemetry?

The telemetry system provides `NoopTracer`, `NoopMeter`, etc. that get used when no real OpenTelemetry provider is configured. This means:
- Zero overhead when telemetry is disabled
- No dependency on `@opentelemetry/*` packages
- Users can wire in their existing OTel setup with one line

## Testing Strategy

- **Unit tests**: Each package has co-located `*.test.ts` files
- **Integration tests**: `tests/integration/` covers cross-package behavior
- **API surface snapshots**: `tests/api-surface/` asserts exact export lists per package
- **Conformance suite**: W3C-style 5-category acid test for any Stele implementation
- **Canonical test vectors**: 56 vectors in `test-vectors/` for cross-implementation verification
- **Benchmarks**: 13 operations with p99 SLA targets in `benchmarks/`
- **Coverage thresholds**: 99% statements, 97% branches, 99% functions, 99% lines
