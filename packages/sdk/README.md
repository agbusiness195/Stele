# @usekova/sdk

High-level unified SDK for the Stele protocol. This is the **main entry point** -- it re-exports everything from `@usekova/core`, `@usekova/crypto`, `@usekova/ccl`, `@usekova/identity`, `@usekova/store`, `@usekova/verifier`, and more.

## Installation

```bash
npm install @usekova/sdk
```

## Usage

### SteleClient

```typescript
import { SteleClient } from '@usekova/sdk';

const client = new SteleClient();
await client.generateKeyPair();

// Create a covenant
const doc = await client.createCovenant({
  issuer: { id: 'alice', publicKey: client.keyPair!.publicKeyHex, role: 'issuer' },
  beneficiary: { id: 'bob', publicKey: bobPubHex, role: 'beneficiary' },
  constraints: "permit read on '/data/**'",
});

// Verify
const result = await client.verifyCovenant(doc);
console.log(result.valid); // true

// Evaluate access
const access = await client.evaluateAction(doc, 'read', '/data/users');
console.log(access.permitted); // true

// Countersign
const audited = await client.countersign(doc, 'auditor');

// Identity management
const identity = await client.createIdentity({
  model: { provider: 'anthropic', modelId: 'claude-3' },
  capabilities: ['read', 'write'],
  deployment: { runtime: 'container' },
});
```

### Quick Covenants

```typescript
import { QuickCovenant } from '@usekova/sdk';

const doc = await QuickCovenant.permit('read', '/data/**', issuer, beneficiary, kp.privateKey);
const standard = await QuickCovenant.standard(issuer, beneficiary, kp.privateKey);
```

### Key Rotation and Events

```typescript
const client = new SteleClient({
  keyRotation: { maxAgeMs: 86_400_000, overlapPeriodMs: 3_600_000 },
});
await client.initializeKeyRotation();

const off = client.on('covenant:created', (e) => console.log('Created:', e.document.id));
```

## Key APIs

- **SteleClient**: `createCovenant()`, `verifyCovenant()`, `countersign()`, `evaluateAction()`, `createIdentity()`, `evolveIdentity()`, `resolveChain()`, `validateChain()`
- **QuickCovenant**: `permit()`, `deny()`, `standard()`
- **CCL utilities**: `parseCCL()`, `mergeCCL()`, `serializeCCL()`
- **Events**: `on()`, `off()`, `removeAllListeners()`
- **Re-exports**: All APIs from `@usekova/core`, `@usekova/crypto`, `@usekova/ccl`, `@usekova/identity`, `@usekova/store`, `@usekova/verifier`, `@usekova/breach`, `@usekova/reputation`, `@usekova/attestation`, `@usekova/proof`
- **Adapters**: Vercel AI, LangChain, Express middleware, OpenTelemetry
- **Testing**: `runConformanceSuite()`, middleware pipeline

## Docs

See the [Stele SDK root documentation](../../README.md) for the full API reference and architecture guide.
