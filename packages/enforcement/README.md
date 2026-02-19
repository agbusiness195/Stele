# @usekova/enforcement

Runtime covenant enforcement with tamper-evident audit logging and capability-based access control.

## Installation

```bash
npm install @usekova/enforcement
```

## Key APIs

- **Monitor**: Runtime constraint monitor that evaluates actions against CCL constraints, maintains a hash-chained audit log with Merkle trees, and enforces rate limits. Supports `enforce` and `log_only` modes.
- **CapabilityGate**: Pre-computes permitted capabilities from CCL permit statements and restricts handler registration and execution to only allowed actions. Generates signed capability manifests.
- **AuditChain**: Standalone hash-chained audit log for append-only tamper-evident event recording.
- **MonitorDeniedError**: Thrown when an action is denied in enforce mode.
- **CapabilityError**: Thrown when a capability is missing or invalid.
- **verifyMerkleProof()**: Verifies a Merkle inclusion proof for a specific audit entry.

## Usage

```typescript
import { Monitor, CapabilityGate } from '@usekova/enforcement';

// Runtime enforcement with audit logging
const monitor = new Monitor(covenantId, `
  permit read on '**'
  deny delete on '/system/**'
`);

const result = await monitor.evaluate('read', '/data/users');
console.log(result.permitted); // true

const log = monitor.getAuditLog();
console.log(log.merkleRoot); // tamper-evident root hash

// Capability-based enforcement
const gate = await CapabilityGate.fromConstraints(
  covenantId,
  `permit read on '**'`,
  runtimeKeyPair,
);

gate.register('read', async (resource) => fetchData(resource));
const data = await gate.execute('read', '/data/users');

const manifest = await gate.generateManifest();
const valid = await CapabilityGate.verifyManifest(manifest);
```

## Docs

See the [Kova SDK root documentation](../../README.md) for the full API reference.
