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

## QuickCovenant Shortcuts

For common patterns, skip the ceremony:

```typescript
import { QuickCovenant } from '@stele/sdk';

// One-liner: permit read on a resource
const doc = await QuickCovenant.permit('read', '/data/**', issuer, beneficiary, kp.privateKey);

// One-liner: deny delete on system paths
const deny = await QuickCovenant.deny('delete', '/system/**', issuer, beneficiary, kp.privateKey);

// Standard template: read all, block system writes, rate limit API calls
const standard = await QuickCovenant.standard(issuer, beneficiary, kp.privateKey);
```

## What is a Covenant?

A **covenant** is a signed, cryptographically verifiable agreement between an
operator (issuer) and an AI agent (beneficiary). It defines what the agent is
permitted, denied, or limited to do — written in **CCL** (Covenant Constraint
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
| `@stele/protocols` | Protocol extensions: breach detection, reputation, game theory, consensus, and 16 more. |
| `@stele/enterprise` | Enterprise features: analytics, dashboards, payments, governance, certification, i18n. |
| `@stele/react` | React hooks for Stele-powered UIs. |
| `@stele/mcp-server` | Model Context Protocol server for tool-calling agents. |
| `@stele/cli` | CLI for covenant management and auditing. |

### Direct package access

Every feature is also available as a standalone package for granular control:

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
import { withStele, withSteleTools } from '@stele/sdk';

// Single tool
const protectedTool = withStele(myTool, { client, covenant });

// All tools at once
const protectedTools = withSteleTools(allTools, { client, covenant });
```

### LangChain adapter

```typescript
import { withSteleTool, SteleCallbackHandler } from '@stele/sdk';

const safeTool = withSteleTool(myLangChainTool, { client, covenant });

// Full audit trail via callback handler
const handler = new SteleCallbackHandler({ client, covenant });
const result = await chain.invoke(input, { callbacks: [handler] });
console.log(handler.events); // tool starts, ends, errors
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

### Key rotation

```typescript
const client = new SteleClient({
  keyRotation: { maxAgeMs: 86_400_000, overlapPeriodMs: 3_600_000 },
});
await client.initializeKeyRotation();

// Keys auto-rotate when needed
await client.rotateKeyIfNeeded();

// Events fire on rotation
client.on('key:rotated', (e) => {
  console.log('Rotated from', e.previousPublicKey, 'to', e.currentPublicKey);
});
```

### Protocol extensions

```typescript
import { computeReputationScore, proveHonesty, BreachStateMachine } from '@stele/protocols';
import { createTrustGate, evaluateAccess } from '@stele/enterprise';

// Compute agent reputation from execution receipts
const score = computeReputationScore(receipts);

// Prove honest behavior is the dominant strategy
const proof = proveHonesty({ stake: 1000, reward: 50, penalty: 500, detection: 0.95 });

// Gate access based on trust score
const gate = createTrustGate({ minimumTrustScore: 0.5, premiumThreshold: 0.9 });
const access = evaluateAccess(gate, { agentId: 'agent-1', trustScore: score.overall });
```

### Middleware pipeline

```typescript
import {
  MiddlewarePipeline,
  loggingMiddleware,
  rateLimitMiddleware,
  telemetryMiddleware,
} from '@stele/sdk';

const pipeline = new MiddlewarePipeline();
pipeline
  .use(loggingMiddleware())
  .use(rateLimitMiddleware({ maxPerSecond: 100 }))
  .use(telemetryMiddleware({ tracer: myOtelTracer }));

client.usePipeline(pipeline);
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Covenant** | Signed agreement defining agent permissions. Immutable once signed. |
| **CCL** | Constraint language: `permit`, `deny`, `limit`, `require` statements with conditions. |
| **Chain** | Parent-child covenant hierarchy. Children can only *narrow* (restrict) parent permissions. |
| **Identity** | Cryptographic agent identity with lineage tracking across model updates. |
| **Verification** | Multi-check validation: signature, ID integrity, expiry, constraint syntax. |
| **Enforcement** | Runtime monitoring that blocks actions violating covenant constraints. |

## CCL Cheat Sheet

```
permit <action> on '<resource>'                    -- Allow
deny <action> on '<resource>'                      -- Block
limit <action> <count> per <n> <hours|minutes>     -- Rate limit
require <action> on '<resource>' when <condition>   -- Conditional

-- Wildcards
permit read on '/data/**'        -- All paths under /data/
permit read on '/files/*.json'   -- JSON files in /files/

-- Conditions
require write on '/api/**' when role = 'admin'
deny delete on '/logs/**' when risk_level > 0.8
```

**Note:** `severity` is a reserved keyword in `when` conditions — use `risk_level` instead.

## Troubleshooting

**"No private key available"** — Call `client.generateKeyPair()` before `createCovenant()`.

**Evaluation returns `{ permitted: false }` unexpectedly** — CCL uses default-deny. If no rule matches the action/resource pair, access is denied. Check that your resource path matches (exact match — `/secrets` does NOT match `/secrets/key` without `/**`).

**Chain validation fails** — Child covenants can only *narrow* parent permissions. A child that permits something the parent denies will fail narrowing validation.

## Next Steps

- Read the [Architecture guide](./ARCHITECTURE.md) for the full layer diagram
- See the [Migration guide](./MIGRATION.md) if upgrading from the old all-in-one SDK
- Browse package READMEs: [sdk](./packages/sdk/), [protocols](./packages/protocols/), [enterprise](./packages/enterprise/)
- Run the conformance suite:
  ```typescript
  import { runConformanceSuite } from '@stele/sdk';
  const result = await runConformanceSuite(myImplementation);
  ```
- Check `test-vectors/canonical-vectors.json` for cross-implementation test data
