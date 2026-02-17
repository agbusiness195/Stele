# Production Deployment Guide

This document covers best practices for deploying Stele in production.

## Prerequisites

- Node.js 18+ (LTS recommended)
- npm 9+

## Key Management

Private keys are the most sensitive component in any Stele deployment.
Never store private keys in plaintext files, environment variables, or
source code.

### Hardware Security Modules (HSM)

For production deployments, use an HSM or cloud KMS:

```ts
// Example: load key from AWS KMS (pseudo-code)
import { KMSClient, DecryptCommand } from '@aws-sdk/client-kms';
import { keyPairFromPrivateKey } from '@stele/crypto';

const kms = new KMSClient({ region: 'us-east-1' });
const result = await kms.send(new DecryptCommand({
  CiphertextBlob: encryptedKeyBlob,
}));
const keyPair = await keyPairFromPrivateKey(new Uint8Array(result.Plaintext!));
```

### Key Rotation

Use the `KeyManager` class for automated key rotation with overlap periods:

```ts
import { KeyManager } from '@stele/crypto';

const manager = new KeyManager({
  maxAgeMs: 90 * 24 * 60 * 60 * 1000, // 90 days
  overlapPeriodMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  onRotation: (oldKey, newKey) => {
    logger.info('Key rotated', { oldKey, newKey });
    // Re-sign active covenants with the new key
  },
});

await manager.initialize();

// Check periodically
if (manager.needsRotation()) {
  await manager.rotate();
}
manager.retireExpired();
```

### Key Revocation

If a key is compromised, revoke it immediately:

```ts
manager.revoke(compromisedPublicKeyHex, 'Key compromised via incident #1234');

// Revoked keys are excluded from verification
const result = await manager.verifyWithAnyKey(message, signature);
// result.valid === false for signatures from revoked keys

// Export the revocation list for distribution
const revocationList = manager.getRevocationList();
```

## Encrypted Storage

Use `EncryptedStore` to encrypt covenant documents at rest:

```ts
import { MemoryStore, EncryptedStore } from '@stele/store';
import { randomBytes } from 'crypto';

const encryptionKey = randomBytes(32); // Store this securely!
const store = new EncryptedStore({
  store: new MemoryStore(), // or FileStore, SqliteStore
  encryptionKey,
});

// Documents are transparently encrypted/decrypted
await store.put(covenant);
const doc = await store.get(covenant.id); // decrypted automatically
```

For production, derive the encryption key from a KMS:

```ts
// Derive from AWS KMS data key
const { Plaintext } = await kms.send(new GenerateDataKeyCommand({
  KeyId: 'alias/stele-store-key',
  KeySpec: 'AES_256',
}));
const store = new EncryptedStore({
  store: new FileStore('/var/lib/stele/covenants'),
  encryptionKey: new Uint8Array(Plaintext!),
});
```

## Health Checks

Wire up health endpoints for monitoring and orchestration:

```ts
import { liveness, readiness, deepHealth } from '@stele/sdk';

// Kubernetes liveness probe -- GET /healthz
app.get('/healthz', (req, res) => {
  res.json(liveness());
});

// Kubernetes readiness probe -- GET /readyz
app.get('/readyz', async (req, res) => {
  const result = await readiness(store);
  res.status(result.ready ? 200 : 503).json(result);
});

// Deep health for dashboards -- GET /health
app.get('/health', async (req, res) => {
  const report = await deepHealth({
    store,
    version: process.env.APP_VERSION,
    storeLatencyThresholdMs: 200,
  });
  res.status(report.status === 'unhealthy' ? 503 : 200).json(report);
});
```

## Framework Integration

### Express / Connect

```ts
import { steleMiddleware } from '@stele/sdk/adapters';

app.use(steleMiddleware({ covenant, store }));
```

### Vercel AI SDK

```ts
import { withStele } from '@stele/sdk/adapters';

const guardedTool = withStele(myTool, { covenant, store });
```

### LangChain

```ts
import { withSteleTool, SteleCallbackHandler } from '@stele/sdk/adapters';

const guardedTool = withSteleTool(myTool, { covenant, store });
const handler = new SteleCallbackHandler(monitor);
```

## Monitoring

### Metrics to Track

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `stele.covenant.verify.latency_ms` | Verification latency | P99 > 100ms |
| `stele.ccl.evaluate.latency_ms` | CCL evaluation latency | P99 > 50ms |
| `stele.store.read.latency_ms` | Store read latency | P99 > 200ms |
| `stele.enforcement.deny.count` | Actions denied by enforcement | Spike > 10x baseline |
| `stele.key.rotation.age_days` | Days since last key rotation | > 90 days |

### Logging

Stele uses structured logging via `@stele/types`. Configure log levels
per environment:

```ts
import { createLogger } from '@stele/types';

const logger = createLogger({
  level: process.env.NODE_ENV === 'production' ? 'warn' : 'debug',
  prefix: 'stele',
});
```

## Scaling

- **MemoryStore**: Single-process only. Use for development and testing.
- **FileStore**: Single-node with atomic writes. Suitable for low-throughput
  deployments. Back the directory with network storage for durability.
- **SqliteStore**: Single-node with transactions. Good for moderate
  throughput (thousands of documents).
- **Custom store**: Implement the `CovenantStore` interface for Redis,
  PostgreSQL, DynamoDB, or any other backend.

All stores are wrapped identically by `EncryptedStore`, so encryption
works regardless of the backend choice.

## Security Checklist

- [ ] Private keys stored in HSM or cloud KMS (never plaintext)
- [ ] `EncryptedStore` wrapping the storage backend
- [ ] Key rotation policy configured (90-day max recommended)
- [ ] Health check endpoints wired up
- [ ] Structured logging with appropriate levels
- [ ] TLS on all network transport
- [ ] Access control on store backend
- [ ] Monitoring and alerting configured
- [ ] Incident response plan for key compromise (revocation)
