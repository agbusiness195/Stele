# Getting Started with Stele

Create, sign, and verify AI agent covenants in under 5 minutes.

## Install

```bash
npm install @stele/sdk
```

That's it. The SDK includes everything you need for the core protocol:
cryptographic signing, covenant lifecycle, constraint evaluation, and verification.

## Quick Start

```typescript
import { SteleClient } from '@stele/sdk';

// 1. Create a client and generate a key pair
const client = new SteleClient();
await client.generateKeyPair();

// 2. Define the parties
const issuer = {
  id: 'acme-corp',
  publicKey: client.keyPair!.publicKeyHex,
  role: 'issuer' as const,
};

const beneficiary = {
  id: 'agent-007',
  publicKey: client.keyPair!.publicKeyHex, // in practice, the agent's own key
  role: 'beneficiary' as const,
};

// 3. Create a covenant with constraints
const covenant = await client.createCovenant({
  issuer,
  beneficiary,
  constraints: `
    permit read on '/data/**'
    deny delete on '/system/**'
    limit api.call 1000 per 1 hours
  `,
});

// 4. Verify it
const result = await client.verifyCovenant(covenant);
console.log(result.valid); // true

// 5. Evaluate an action
const decision = await client.evaluateAction(covenant, 'read', '/data/users');
console.log(decision.permitted); // true

const blocked = await client.evaluateAction(covenant, 'delete', '/system/config');
console.log(blocked.permitted); // false
```

## What is a Covenant?

A **covenant** is a signed, cryptographically verifiable agreement between an
operator (issuer) and an AI agent (beneficiary). It defines what the agent is
permitted, denied, or limited to do -- written in **CCL** (Covenant Constraint
Language).

```
permit read on '/data/**'          -- Allow reading any data path
deny write on '/secrets/**'        -- Block writing to secrets
limit api.call 100 per 1 hours     -- Rate limit API calls
```

## Package Architecture

Stele is modular. Install only what you need:

| Package | What it does |
|---------|-------------|
| `@stele/sdk` | **Start here.** Client, covenants, keys, CCL, verification, enforcement, store. |
| `@stele/protocols` | Protocol extensions: breach detection, reputation, game theory, consensus, and 17 more. |
| `@stele/enterprise` | Enterprise features: analytics, dashboards, payments, governance, certification, i18n. |
| `@stele/react` | Reactive state management for Stele-powered UIs. |
| `@stele/mcp-server` | Model Context Protocol server for tool-calling agents. |
| `@stele/cli` | Command-line interface for covenant management and auditing. |
| `@stele/evm` | Ethereum/EVM blockchain anchoring. |

### Direct package access

Every feature is also available as a standalone package if you want granular control:

```typescript
// Just the crypto layer
import { generateKeyPair, sign, verify } from '@stele/crypto';

// Just constraint evaluation
import { parse, evaluate } from '@stele/ccl';

// Just covenant building
import { buildCovenant, verifyCovenant } from '@stele/core';
```

## Common Patterns

### Express middleware (zero-config HTTP enforcement)

```typescript
import { steleMiddleware } from '@stele/sdk';

app.use(steleMiddleware({
  covenantId: 'cov_abc123',
  store: myStore,
}));
```

### Vercel AI SDK adapter

```typescript
import { withStele } from '@stele/sdk';

const protectedTool = withStele(myTool, {
  covenant,
  action: 'tool.execute',
});
```

### Covenant chains (delegation)

```typescript
// Parent covenant: broad permissions
const parent = await client.createCovenant({
  issuer: operator,
  beneficiary: teamLead,
  constraints: "permit read on '**'\npermit write on '/team/**'",
});

// Child covenant: narrowed permissions (must be subset of parent)
const child = await client.createCovenant({
  issuer: teamLead,
  beneficiary: agent,
  constraints: "permit read on '/team/reports/**'",
  chain: { parentId: parent.id, relation: 'narrows' },
});

// Validate the chain
const validation = await client.validateChain([parent, child]);
console.log(validation.valid); // true -- child only narrows parent
```

### Protocol extensions

```typescript
import { computeReputationScore, createBreachAttestation } from '@stele/protocols';
import { createTrustGate, evaluateAccess } from '@stele/enterprise';

// Compute agent reputation from execution receipts
const score = computeReputationScore(receipts);

// Gate access based on trust score
const gate = createTrustGate({ thresholds: { basic: 0.5, premium: 0.8 } });
const access = evaluateAccess(gate, score.overall);
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Covenant** | Signed agreement defining agent permissions. Immutable once signed. |
| **CCL** | Constraint language: `permit`, `deny`, `limit`, `require` statements with conditions. |
| **Chain** | Parent-child covenant hierarchy. Children can only _narrow_ (restrict) parent permissions. |
| **Identity** | Cryptographic agent identity with lineage tracking across model updates. |
| **Verification** | Multi-check validation: signature, ID integrity, expiry, constraint syntax. |
| **Enforcement** | Runtime monitoring that blocks actions violating covenant constraints. |

## Next Steps

- Browse the [API reference](https://stele.dev/docs) for detailed type information
- Run the conformance suite to validate your integration:
  ```typescript
  import { runConformanceSuite } from '@stele/sdk';
  const result = await runConformanceSuite(myImplementation);
  ```
- Check the `test-vectors/canonical-vectors.json` file for cross-implementation test data
