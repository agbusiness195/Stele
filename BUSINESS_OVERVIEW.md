# Nobulex SDK - Business & Product Overview

**Company**: Nobulex Labs, Inc. (2026)
**Product**: Open-source accountability framework for AI agents
**License**: MIT

---

## Executive Summary

Nobulex is an open-source **accountability framework for AI agents** that uses cryptographic behavioral commitments (called "Covenants") to solve the trust and compliance problem in AI deployment: how do you prove an AI agent is actually following its stated policies?

Traditional solutions (firewalls, API rate limits, audit logs) are insufficient because they're reactive, centralized, and forgeable. Nobulex inverts the trust model: agents publish cryptographic behavioral commitments signed with their private keys, which anyone can verify without a trusted third party.

---

## The Problem

As AI systems become more autonomous, organizations face a critical question: "How can I be sure this AI will do what I told it to do -- and only that?"

### Business Pain Points

| Problem | Impact |
|---------|--------|
| **Compliance Documentation** | Regulators demand provable AI governance (EU AI Act, HIPAA, SOX) |
| **Cross-Organization Trust** | No way to verify a vendor's AI agent behavior without trusting their infrastructure |
| **Liability & Risk** | No defensible evidence of policy compliance (or violation) in disputes |
| **Audit Trails** | Existing logs are mutable, forgeable, and reactive |
| **Real-time Enforcement** | Current tools check periodically, not on every action |

### Why Existing Solutions Fall Short

- **API Gateways** (Kong, Traefik): Network-layer only, no semantic policy understanding
- **RBAC/IAM** (Okta, Auth0): Designed for human users, not AI agents
- **Audit/Logging** (Datadog, Splunk): Post-hoc analysis, logs can be tampered with
- **Policy Engines** (OPA, Kyverno): General-purpose, not AI-specific or cryptographic
- **AI Safety Tools** (Constitutional AI, fine-tuning): Model-level, not deployment-level

---

## How It Works

### Three-Phase Protocol

#### Phase 1: Inscribe (Create & Publish Covenant)
- Agent creates a covenant declaring what it will/won't do using CCL (Covenant Constraint Language)
- Covenant is signed with Ed25519 (tamper-proof, non-repudiable)
- Document is content-addressed (ID = SHA-256 hash of canonical form)
- Published to network, discovery service, or stored locally

#### Phase 2: Operate (Enforce Constraints in Real-Time)
- Every action is evaluated against the constraint set before execution
- Deny-wins semantics: if both permit and deny match, deny takes precedence
- Default deny: unmatched actions are rejected
- Hash-chained audit trail: each log entry includes hash of previous entry (immutable)
- Rate limits, conditional logic, and obligations checked in real-time

#### Phase 3: Verify (Cryptographic Proof)
- Anyone can verify compliance using only the public key and document
- 11 cryptographic checks run (signature validity, expiration, CCL parsing, chain depth, document size, countersignatures, nonce, etc.)
- No trusted third party required

### CCL (Covenant Constraint Language)

Purpose-built domain-specific language for AI agent constraints:

```
# Allow read access to data directory
permit read on '/data/**'

# Block writes to system paths
deny write on '/system/**'

# Conditional: allow API calls if token count is low
permit api.call on 'openai.com/**' when request.token_count < 10000

# Mandatory: log all resource access
require audit.log on '**'

# Rate limiting: max 500 API calls per hour
limit api.call 500 per 3600 seconds
```

### Cryptographic Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Signing | Ed25519 | NIST-recommended, non-malleable, deterministic |
| Hashing | SHA-256 | Content addressing, document ID, audit trail |
| Canonicalization | JCS (RFC 8785) | Deterministic JSON for consistent hashing |
| Nonce | CSPRNG (32 bytes) | Prevents replay attacks |
| Encoding | Hex | Portable across JSON/text boundaries |

---

## Product Architecture

### 34 npm Packages Across 5 Layers

```
+---------------------------------------------+
|  Platform (React, EVM, MCP Server, CLI)      |
+---------------------------------------------+
|  Interop (Discovery, Schema)                 |
+---------------------------------------------+
|  SDK (NobulexClient - Unified API)             |
+---------------------------------------------+
|  Protocol (17 advanced modules)              |
+---------------------------------------------+
|  Foundation (Types, Crypto, CCL, Core,       |
|  Store, Verifier, Identity)                  |
+---------------------------------------------+
```

### Foundation Layer (7 packages)
- **@nobulex/types**: Error codes, validation, Result type, type guards
- **@nobulex/crypto**: Ed25519, SHA-256, JCS canonicalization, hex encoding
- **@nobulex/ccl**: CCL parser & evaluator (deny-wins, resource globs, rate limits)
- **@nobulex/core**: Covenant build/sign/verify/chain/serialize (11-check verification)
- **@nobulex/store**: MemoryStore + FileStore + SQLite (pluggable, queryable, event system)
- **@nobulex/verifier**: Stateful verification with caching
- **@nobulex/identity**: Agent identity lifecycle & lineage tracking

### Enforcement Layer (5 packages)
- **@nobulex/enforcement**: Real-time constraint evaluation + audit trail
- **@nobulex/proof**: ZK proof generation (compliance proof)
- **@nobulex/breach**: Breach detection, attestation, trust graph propagation
- **@nobulex/reputation**: Trust scoring, decay curves, stake-weighted reputation
- **@nobulex/mcp**: MCP middleware guard for tool-call enforcement

### Protocol Layer (17 packages)
Advanced features for enterprise use:
- Attestation, Canary testing, Game theory proofs, Formal composition
- Antifragility engine, Multi-party negotiation, Consensus protocol
- Robustness analysis, Temporal evolution, Recursive verification
- AI alignment verification, Norm discovery, Cross-substrate translation
- Trust derivatives, Legal compliance mapping

### SDK & Interop (4 packages)
- **@nobulex/sdk**: Unified NobulexClient API, QuickCovenant builders, event system
- **@nobulex/discovery**: `.well-known/nobulex/` protocol, key registry, cross-platform negotiation
- **@nobulex/schema**: JSON Schema (Draft 2020-12) for all document types
- **@nobulex/mcp-server**: JSON-RPC 2.0 MCP server exposing Nobulex as tools

### Platform Integrations (4 packages)
- **@nobulex/react**: Reactive UI primitives
- **@nobulex/evm**: Ethereum/blockchain anchoring
- **@nobulex/cli**: Command-line interface
- **@nobulex/mcp-server**: MCP server integration

---

## Framework Integrations (Pre-Built Adapters)

| Framework | Adapter | Description |
|-----------|---------|-------------|
| **Vercel AI SDK** | `withNobulex()` / `withNobulexTools()` | Wraps AI SDK tool calls for enforcement |
| **LangChain** | `NobulexCallbackHandler` / `withNobulexTool()` | Enforces tool constraints in chains |
| **Express/Node.js** | `nobulexMiddleware()` | Zero-config HTTP covenant enforcement |
| **OpenTelemetry** | `telemetryMiddleware()` | Bring-your-own-tracer integration |
| **Ethereum/EVM** | `@nobulex/evm` | On-chain covenant registry |
| **MCP (Claude)** | `@nobulex/mcp-server` | Model Context Protocol integration |

---

## Technical Maturity Metrics

| Metric | Value |
|--------|-------|
| Test Count | 5,158 passing tests |
| Test Suites | 85 suites |
| Language | TypeScript (strict mode, no `any` types) |
| External Dependencies | Minimal (Node.js stdlib for foundation) |
| Build System | tsup (ESM + CJS), tsc --build, Vitest |
| Max Chain Depth | 16 (DoS prevention) |
| Max Document Size | 256 KB |
| Nonce Entropy | 128-bit (32 bytes) |
| Benchmark Operations | 13 with p99 SLA targets |
| Conformance Suite | 5-category acid test |
| Test Vectors | 56 canonical cross-implementation vectors |

---

## Target Markets

### Primary Markets

#### 1. Enterprise AI Deployment (Highest TAM)
- Companies running Claude/GPT/Gemini in production need provable policy enforcement
- 50,000+ enterprises globally deploying AI agents
- Revenue: B2B SaaS ($50K-$500K/year per customer)

#### 2. Regulatory Compliance (Growing Fast)
- EU AI Act, proposed US Executive Orders, state-level AI governance
- Financial services, healthcare, government agencies
- Revenue: Compliance platform + consulting

#### 3. Multi-Agent Systems (Emerging)
- Multiple AI agents coordinating need cryptographic trust boundaries
- Agent orchestration platforms, multi-agent frameworks
- Revenue: Platform fees, agent registry

#### 4. AI Safety & Alignment (R&D)
- Research labs need verifiable constraint enforcement
- Academic AI labs, safety institutions, government initiatives
- Revenue: Grants, enterprise contracts with AI labs

#### 5. Healthcare & Finance (Regulated)
- HIPAA-compliant AI with verifiable guardrails
- Algorithmic trading agents with hard policy boundaries
- Revenue: Enterprise contracts, compliance SaaS

---

## Revenue Model

### Current State: Pre-Revenue (Open Source)

### Projected Revenue Streams

| Stream | % of Revenue | Description |
|--------|-------------|-------------|
| **B2B SaaS** | 60% | Compliance management platform, monitoring, reporting ($50K-$500K/customer) |
| **Enterprise Support** | 20% | Custom integrations, on-prem deployment, priority patches ($100K-$1M+/year) |
| **Professional Services** | 10% | Compliance consulting, policy design, integration services |
| **Marketplace/Ecosystem** | 10% | Agent registry fees, policy template library, third-party integrations |

### Pricing Tiers

| Tier | Price | Target |
|------|-------|--------|
| Developer (Open Source) | Free | Individual developers, startups |
| Business | $5K-$50K/year | SMBs needing compliance |
| Enterprise | $100K-$1M+/year | Large orgs, custom SLA |
| Hosted Compliance-as-a-Service | $10K-$100K/year | Orgs wanting managed solution |

### Unit Economics (Projected)
- **CAC** (Customer Acquisition Cost): $5K-$50K (enterprise sales cycle)
- **LTV** (Lifetime Value): $150K-$2M+ (multi-year contracts)
- **Gross Margin**: 70-85% (software)
- **Break-even**: 12-24 months post-enterprise launch

---

## Competitive Landscape

### Direct Competitors
**None.** No existing product combines all four:
1. Cryptographic behavioral commitments (not just audit logs)
2. Decentralized verification (no central authority)
3. Purpose-built DSL for AI constraints (CCL)
4. Open-source foundation

### Indirect Competitors

| Category | Players | Nobulex's Advantage |
|----------|---------|-------------------|
| API Gateways | Kong, Traefik | Nobulex is agent-centric, semantic, cryptographic |
| Identity/IAM | Okta, Auth0 | Nobulex covers AI agent policy, not just human users |
| Audit/Logging | Datadog, Splunk | Nobulex is real-time + non-repudiable + immutable |
| Policy Engines | OPA, Kyverno | Nobulex is AI-specific + cryptographic + decentralized |
| AI Safety | Constitutional AI, RLHF | Nobulex is deployment-layer; complements model safety |
| Container Security | Docker, K8s | Nobulex is policy-layer; orthogonal |

### Competitive Moats

1. **First-mover** in decentralized AI accountability
2. **Cryptographic foundation** (unforgeable, content-addressable)
3. **AI-specific DSL** (CCL designed for agent constraints)
4. **Open-source network effects** (hard to displace once adopted)
5. **Formal verification** (composition proofs, game theory)
6. **Production-ready** (5,158 tests, strict TypeScript)

---

## Regulatory Alignment

| Regulation | How Nobulex Helps |
|------------|-----------------|
| **EU AI Act** | Verifiable compliance trail (Article 6 requirements) |
| **US Executive Orders on AI** | Aligns with "algorithmic accountability" requirements |
| **HIPAA** (Healthcare) | Non-repudiation + immutable audit trails |
| **SOX** (Financial) | Immutable action logs satisfy Section 302 attestation |
| **GDPR** | Compatible with right-to-be-forgotten (chain termination) |
| **NIST AI Framework** | Provides measurable governance infrastructure |

---

## Go-to-Market Strategy

### Phase 1: Developer Adoption (Current)
- Open-source on GitHub, npm packages, free tier
- Messaging: "The accountability primitive for AI agents"
- Channels: Dev communities, AI safety forums, academic conferences
- Milestones: 10K+ GitHub stars, 1K weekly npm downloads

### Phase 2: Enterprise Pilots (12-18 months)
- Enterprise support contracts, compliance consulting
- Messaging: "Satisfy AI governance regulations without custom tooling"
- Channels: Enterprise security conferences, RegTech networks
- Milestones: 10-20 enterprise pilot customers

### Phase 3: Market Acceleration (18-36 months)
- SaaS platform (compliance-as-a-service), marketplace (agent registry)
- Messaging: "Verifiable AI accountability, by default"
- Channels: Direct sales to Fortune 500, government contracts
- Milestones: $5M+ ARR, market leadership in AI compliance

---

## Valuation Analysis

### Comparable Public Companies

| Company | Focus | Market Cap | Revenue Multiple |
|---------|-------|-----------|-----------------|
| Okta | Identity/IAM | ~$10B | 8-12x ARR |
| CrowdStrike | Security/Compliance | ~$30B | 15-25x ARR |
| HashiCorp | Infrastructure/Policy | ~$5B | 10-15x ARR |
| SentinelOne | EDR/Security | ~$15B | 12-20x ARR |

### Valuation Scenarios

| Scenario | Timeline | Projected ARR | Multiple | Estimated Valuation |
|----------|----------|--------------|----------|-------------------|
| **Conservative** | 2-3 years | $5M | 8x | **$40M** |
| **Base Case** | 3-5 years | $20M | 12x | **$240M** |
| **Optimistic** | 5+ years | $50M+ | 15x | **$750M+** |

### Key Value Drivers
- AI compliance market TAM ($10B+ globally)
- First-mover advantage in decentralized AI accountability
- Open-source adoption creating network effects
- Regulatory tailwinds (EU AI Act, US AI governance mandates)

---

## Risk Assessment

### Market Risks
| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| AI compliance market slow to form | Medium | High | Focus on early-adopter enterprises |
| Regulatory mandates favor centralized solutions | Medium | Medium | Engage with regulators (NIST, EU) |
| Hyperscalers build in-house alternatives | High | Medium | Emphasize open-source + vendor neutrality |

### Technical Risks
| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Cryptographic breaks (SHA-256, Ed25519) | Low | High | Migration path to post-quantum crypto |
| Scalability challenges | Low | Medium | Tested at 5x contention, 13 benchmarked ops |
| Integration friction | Medium | Medium | Pre-built adapters for major frameworks |

### Financial Risks
| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Open-source to enterprise conversion | High | High | Strong developer experience + partnerships |
| Long enterprise sales cycles | Medium | Medium | Land-and-expand with free tier |
| TAM uncertainty | Medium | Medium | Multi-market strategy (enterprise + compliance + safety) |

---

## Why Nobulex Could Be Big

Nobulex sits at the intersection of four accelerating mega-trends:

1. **AI Adoption**: Enterprise AI deployments growing exponentially
2. **Regulatory Tightening**: Governments moving from principles to requirements
3. **Zero-Trust Security**: Shift from perimeter defense to continuous verification
4. **Cryptographic Verification**: Blockchain-era trust primitives going mainstream

The AI governance crisis is coming. As AI agents become more autonomous, the cost of unaccountable AI grows exponentially. Nobulex is the missing infrastructure layer -- the cryptographic accountability primitive that the entire ecosystem will need.

---

## Summary

| Dimension | Assessment |
|-----------|-----------|
| Product-Market Fit | Early (AI compliance market still forming) |
| Technical Maturity | High (5,158 tests, strict TypeScript, 34 packages) |
| Market Opportunity | Large ($10B+ TAM in AI compliance) |
| Competitive Position | Strong (first-mover, no direct competitors) |
| Go-to-Market Readiness | Medium (needs enterprise sales infrastructure) |
| Revenue Model | Unproven (open-source + enterprise hybrid) |
| 2-Year Valuation Range | $40M - $240M (depending on ARR and adoption) |
| Key Success Factor | Developer adoption leading to network effects leading to enterprise capture |

---

*Prepared for financial analysis and valuation purposes.*
*Product: Nobulex SDK by Nobulex Labs, Inc.*
*Date: February 2026*
