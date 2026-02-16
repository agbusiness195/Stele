# @stele/sdk

The core TypeScript SDK for the [Stele](https://stele.dev) protocol — cryptographic covenants for AI agent accountability.

## Install

```bash
npm install @stele/sdk
```

## Quick Start

```typescript
import { SteleClient } from '@stele/sdk';

const client = new SteleClient();
const kp = await client.generateKeyPair();

// Create a covenant
const doc = await client.createCovenant({
  issuer: { id: 'alice', publicKey: kp.publicKeyHex, role: 'issuer' },
  beneficiary: { id: 'bob', publicKey: bobPubHex, role: 'beneficiary' },
  constraints: "permit read on '/data/**'\ndeny delete on '/system/**'",
});

// Verify it
const result = await client.verifyCovenant(doc);
console.log(result.valid); // true

// Evaluate an action
const access = await client.evaluateAction(doc, 'read', '/data/users');
console.log(access.permitted); // true
```

## What's in the Box

| Area | Exports |
|------|---------|
| **Client** | `SteleClient`, `QuickCovenant` |
| **Crypto** | `generateKeyPair`, `sign`, `verify`, `sha256`, `KeyManager` |
| **Core** | `buildCovenant`, `verifyCovenant_core`, `countersignCovenant`, `resolveChain_core` |
| **CCL** | `parseCCL`, `evaluateCCL`, `matchAction`, `matchResource`, `mergeCCL` |
| **Identity** | `createIdentity_core`, `evolveIdentity_core`, `verifyIdentity` |
| **Store** | `MemoryStore`, `FileStore`, `SqliteStore`, `QueryBuilder` |
| **Verifier** | `Verifier`, `verifyBatch` |
| **Enforcement** | `Monitor`, `CapabilityGate`, `AuditChain`, `verifyProvenance` |
| **Middleware** | `MiddlewarePipeline`, `loggingMiddleware`, `rateLimitMiddleware` |
| **Adapters** | `steleMiddleware` (Express), `withStele` (Vercel AI), `withSteleTool` (LangChain) |
| **Telemetry** | `telemetryMiddleware`, `SteleMetrics`, `createTelemetry` |
| **Conformance** | `runConformanceSuite` (5-category W3C-style acid test) |

## SteleClient API

### Key Management

```typescript
const client = new SteleClient();
await client.generateKeyPair();

// With key rotation
const rotatingClient = new SteleClient({
  keyRotation: { maxAgeMs: 86_400_000, overlapPeriodMs: 3_600_000 },
});
await rotatingClient.initializeKeyRotation();
await rotatingClient.rotateKeyIfNeeded(); // true if rotated
```

### Covenant Lifecycle

```typescript
// Create
const doc = await client.createCovenant({ issuer, beneficiary, constraints });

// Verify
const result = await client.verifyCovenant(doc);

// Countersign
const audited = await client.countersign(doc, 'auditor');

// Evaluate
const access = await client.evaluateAction(doc, 'read', '/data/users');
```

### Identity

```typescript
const identity = await client.createIdentity({
  model: { provider: 'anthropic', modelId: 'claude-4' },
  capabilities: ['read', 'write'],
  deployment: { runtime: 'container' },
});

const evolved = await client.evolveIdentity(identity, {
  changeType: 'model_update',
  description: 'Upgraded model',
  updates: { model: { provider: 'anthropic', modelId: 'claude-5' } },
});
```

### Chain Validation

```typescript
const ancestors = await client.resolveChain(childDoc, [parentDoc]);
const result = await client.validateChain([rootDoc, childDoc, grandchildDoc]);
console.log(result.valid); // true if all docs valid + narrowing holds
```

### Events

```typescript
const off = client.on('covenant:created', (e) => {
  console.log('Created:', e.document.id);
});
// Events: covenant:created, covenant:verified, covenant:countersigned,
//         identity:created, identity:evolved, evaluation:completed,
//         chain:resolved, chain:validated, key:rotated
```

## QuickCovenant

One-liner covenant builders for common patterns:

```typescript
import { QuickCovenant } from '@stele/sdk';

const permit = await QuickCovenant.permit('read', '/data/**', issuer, beneficiary, privateKey);
const deny   = await QuickCovenant.deny('delete', '/system/**', issuer, beneficiary, privateKey);
const std    = await QuickCovenant.standard(issuer, beneficiary, privateKey);
// standard = permit read on '**' + deny write on '/system/**' + limit api.call 1000/hr
```

## Framework Adapters

### Express / HTTP

```typescript
import { steleMiddleware, createCovenantRouter } from '@stele/sdk';

// Zero-config middleware
app.use(steleMiddleware({ client, covenant }));

// Or route-level guards
const router = createCovenantRouter({ client, covenant });
app.get('/data', router.protect('read', '/data'), handler);
```

### Vercel AI SDK

```typescript
import { withStele, withSteleTools } from '@stele/sdk';

// Wrap a single tool
const safeTool = withStele(myTool, { client, covenant });

// Wrap all tools at once
const safeTools = withSteleTools(tools, { client, covenant });
```

### LangChain

```typescript
import { withSteleTool, SteleCallbackHandler } from '@stele/sdk';

const safeTool = withSteleTool(myTool, { client, covenant });
const handler = new SteleCallbackHandler({ client, covenant });
// handler.events gives you the full audit trail
```

## Middleware Pipeline

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

## Conformance Suite

Verify any Stele implementation against the spec:

```typescript
import { runConformanceSuite } from '@stele/sdk';

const result = await runConformanceSuite({
  generateKeyPair, sign, verify, sha256,
  parse, evaluate, buildCovenant, verifyCovenant,
});
console.log(result.passed); // true
console.log(result.categories); // crypto, ccl, covenant, interop, security
```

## Related Packages

| Package | Use case |
|---------|----------|
| [`@stele/protocols`](../protocols) | Protocol extensions (breach detection, reputation, game theory, consensus, etc.) |
| [`@stele/enterprise`](../enterprise) | Enterprise features (analytics, payments, governance, certification) |

## License

MIT
