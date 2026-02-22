# Kervyx Adoption Strategy

## 1. The Problem in Plain English

AI agents are being deployed into production with no standardized way to make verifiable commitments about their behavior. Today, when an AI system promises "I will not delete your data," that promise exists only as a prompt string -- unsigned, unverifiable, and silently changeable. As agents gain access to real infrastructure (databases, APIs, financial systems), the gap between what they claim they will do and what they can provably commit to becomes a liability. Kervyx closes this gap with cryptographic covenants: signed, content-addressed constraint documents that any party can independently verify.

## 2. Adoption Tiers

### Solo Developer

**Goal**: Add verifiable constraints to your AI agent in under 10 minutes.

- Install `@kervyx/sdk` (single dependency, zero native modules)
- Generate an Ed25519 key pair
- Write CCL constraints for your agent's permitted actions
- Build and sign a covenant with `KervyxClient.createCovenant()`
- Evaluate actions at runtime with `KervyxClient.evaluateAction()`

**What you get**: Your agent's permissions are cryptographically signed and auditable. You can prove to yourself (or a user) exactly what the agent is allowed to do. Default-deny semantics mean an uncovered action is never silently permitted.

### Team / Startup

**Goal**: Enforce covenants across your HTTP services and share covenant state across team members.

- Use `kervyxMiddleware()` to enforce covenants on Express/Fastify routes
- Store covenants in `SqliteStore` or `FileStore` for persistence
- Use `Verifier` for batch verification in CI pipelines
- Use chain delegation to grant sub-agents narrower permissions than the parent
- Add countersignatures from team leads or compliance reviewers

**What you get**: Every API request is evaluated against the covenant before execution. Chain narrowing ensures that delegated agents never exceed the parent's permissions. The audit log provides hash-chained, Merkle-rooted proof of every action evaluated.

### Enterprise

**Goal**: Compliance-grade covenant infrastructure with key lifecycle management, audit trails, and integration with existing security tooling.

- Enable `keyRotation` on `KervyxClient` for automatic key lifecycle management
- Use the `Monitor` class in enforce mode with `onViolation` callbacks wired to your SIEM
- Generate capability manifests (`CapabilityGate.generateManifest()`) as compliance artifacts
- Use `telemetryMiddleware()` with your existing OpenTelemetry collector
- Anchor covenant hashes on-chain via `@kervyx/evm` for tamper-evident timestamping
- Run `runConformanceSuite()` against your integration to validate protocol compliance

**What you get**: Cryptographic proof that constraints were defined before execution, keys are rotated on schedule, every action is audited, and the audit log has not been tampered with. Covenant documents are portable across systems because they are self-verifying.

## 3. Competitive Landscape

### What exists today

There is no direct competitor to Kervyx. The concept of cryptographically signed, pre-operative constraint commitments for AI agents does not exist as a shipping product or open standard. This is a new category.

The closest conceptual precedent is X.509 certificate chains (binding an identity to a public key with constraints), but X.509 was designed for TLS endpoints, not for governing AI agent behavior with a domain-specific constraint language.

### Adjacent solutions and how Kervyx differs

| Approach | What it does | How Kervyx differs |
|---|---|---|
| **Guardrails (Guardrails AI, NeMo)** | Runtime input/output filtering on LLM calls | Kervyx governs actions, not text. Constraints are signed commitments, not runtime filters. A guardrail can be silently disabled; a covenant cannot be silently modified. |
| **RBAC / ACL systems** | Post-hoc policy enforcement by an authority | The authority can change rules at any time without the subject's knowledge. Kervyx's covenants are pre-operative commitments: the issuer signs before execution, and modification requires a new signature. |
| **Sandboxing (gVisor, Firecracker)** | OS-level isolation of processes | Sandboxing restricts what a process *can* do at the kernel level. Kervyx restricts what an agent *is committed* to doing at the application level. They are complementary: a sandbox enforces; a covenant commits. |
| **Policy engines (OPA, Cedar)** | Centralized policy evaluation | OPA evaluates policies but does not sign them. There is no cryptographic binding between the policy author and the policy content. Kervyx adds non-repudiation and content-addressing on top of policy evaluation. |

### Why "just use ACLs" is not enough

ACLs answer the question "is this principal allowed to do this?" at the moment of the request. They do not answer:
- **Who committed to these permissions, and when?** (Non-repudiation)
- **Have these permissions been modified since they were agreed upon?** (Tamper evidence)
- **Can a third party verify these permissions without access to the authority?** (Independent verifiability)
- **Can the subject prove what it was committed to?** (Beneficiary-verifiable commitments)

Kervyx answers all four. The covenant is the commitment; the signature is the proof; the CCL document is the constraint.

## 4. Integration Paths

### Express / Fastify

```typescript
import { kervyxMiddleware } from '@kervyx/sdk';

app.use(kervyxMiddleware({ covenant, client }));
// Every request is evaluated against the covenant's CCL constraints.
// Denied requests receive a 403 with the denial reason.
```

### Vercel AI SDK

```typescript
import { withKervyx, withKervyxTools } from '@kervyx/sdk';

// Wrap a single tool
const guardedTool = withKervyx(myTool, { covenant, client });

// Or wrap all tools in a tool set
const guardedTools = withKervyxTools(toolSet, { covenant, client });
```

### LangChain

```typescript
import { KervyxCallbackHandler, withKervyxTool } from '@kervyx/sdk';

// Callback handler for chain-level enforcement
const handler = new KervyxCallbackHandler({ covenant, client });
const chain = myChain.withConfig({ callbacks: [handler] });

// Or wrap individual tools
const guardedTool = withKervyxTool(myTool, { covenant, client });
```

### Direct SDK Usage

```typescript
import { KervyxClient } from '@kervyx/sdk';

const client = new KervyxClient();
await client.generateKeyPair();

const covenant = await client.createCovenant({ /* ... */ });
const result = await client.evaluateAction(covenant, 'read', '/data/users');

if (!result.permitted) {
  throw new Error(`Denied: ${result.reason}`);
}
```

### MCP Server

The `@kervyx/mcp-server` package exposes Kervyx operations as MCP tools, allowing AI agents to create, verify, and evaluate covenants through the Model Context Protocol.

## 5. Stability Tiers

### Stable

These packages have comprehensive test coverage, stable APIs, and are safe for production use.

| Package | Purpose |
|---|---|
| `@kervyx/crypto` | Ed25519 key generation, signing, verification, hashing |
| `@kervyx/ccl` | Constraint Commitment Language parser and evaluator |
| `@kervyx/core` | Covenant build, verify, countersign, chain operations |
| `@kervyx/sdk` | High-level KervyxClient unifying all operations |
| `@kervyx/store` | MemoryStore, FileStore, SqliteStore |
| `@kervyx/identity` | Agent identity creation, evolution, verification |
| `@kervyx/verifier` | Standalone verification engine with history and batch support |
| `@kervyx/enforcement` | Monitor (runtime enforcement), CapabilityGate, audit logs |

### Beta

APIs may change in minor versions. Functional and tested, but integration patterns are still being refined.

| Package | Purpose |
|---|---|
| `@kervyx/react` | React hooks and components for covenant UI |
| `@kervyx/evm` | Ethereum/EVM covenant anchoring |
| `@kervyx/mcp-server` | Model Context Protocol server for AI agent access |
| Express middleware | `kervyxMiddleware()` in `@kervyx/sdk` adapters |
| Vercel AI adapter | `withKervyx()` / `withKervyxTools()` in `@kervyx/sdk` adapters |
| LangChain adapter | `KervyxCallbackHandler` / `withKervyxTool()` in `@kervyx/sdk` adapters |

### Experimental

These packages explore advanced protocol concepts. APIs will change. Not recommended for production.

| Package | Purpose |
|---|---|
| `@kervyx/gametheory` | Game-theoretic analysis of covenant incentives |
| `@kervyx/alignment` | AI alignment verification primitives |
| `@kervyx/antifragile` | Antifragility patterns for covenant systems |
| `@kervyx/negotiation` | Multi-party covenant negotiation protocol |
| `@kervyx/consensus` | Distributed covenant consensus |
| `@kervyx/robustness` | Fault tolerance and degradation patterns |
| `@kervyx/temporal` | Time-varying constraint semantics |
| `@kervyx/recursive` | Self-referential covenant structures |
| `@kervyx/composition` | Covenant composition algebra |
| `@kervyx/attestation` | External attestation integration |
| `@kervyx/norms` | Social norm modeling |
| `@kervyx/substrate` | Cross-chain substrate layer |
| `@kervyx/derivatives` | Covenant derivatives and hedging |
| `@kervyx/legal` | Legal document mapping |
| `@kervyx/canary` | Canary/warrant canary primitives |
| `@kervyx/reputation` | Reputation scoring for agents |
| `@kervyx/breach` | Breach detection and response |

## 6. Roadmap Priorities

### Near-term (next release)

1. **npm publish**: Publish all stable-tier packages to npm under the `@kervyx` scope.
2. **Security audit**: Engage an external firm to audit `@kervyx/crypto`, `@kervyx/ccl`, and `@kervyx/core`. The threat model (THREAT_MODEL.md) defines the scope.
3. **API documentation site**: Generate and host TypeDoc output for all stable packages.

### Medium-term (v1.0 criteria)

4. **Protocol specification**: Formalize the covenant document schema, CCL grammar, and verification algorithm as a versioned specification document, independent of the TypeScript implementation.
5. **Conformance test suite expansion**: Expand `runConformanceSuite()` to cover all 11 verification checks and all CCL edge cases, enabling alternative implementations to validate compliance.
6. **Key management guidance**: Publish a reference architecture for key storage (HSM integration, cloud KMS wrappers, encrypted-at-rest patterns).
7. **Adapter stabilization**: Promote Express, Vercel AI, and LangChain adapters from beta to stable based on production usage feedback.

### Long-term

8. **Multi-language SDKs**: Implement the protocol in Python, Go, and Rust to enable cross-language covenant interoperability.
9. **Decentralized key registry**: Design a key discovery and attestation mechanism that does not depend on a central authority.
10. **Standard body engagement**: Explore standardization of the covenant document format and CCL through an appropriate standards body.
