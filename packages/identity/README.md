# @usekova/identity

Agent identity management with cryptographic lineage tracking. Create, evolve, and verify AI agent identities with reputation carry-forward across identity changes.

## Installation

```bash
npm install @usekova/identity
```

## Usage

### Create an Identity

```typescript
import { generateKeyPair } from '@usekova/crypto';
import { createIdentity } from '@usekova/identity';

const kp = await generateKeyPair();

const identity = await createIdentity({
  operatorKeyPair: kp,
  model: { provider: 'anthropic', modelId: 'claude-3' },
  capabilities: ['read', 'write'],
  deployment: { runtime: 'container' },
});

console.log(identity.id);      // hex composite hash
console.log(identity.version); // 1
```

### Evolve an Identity

```typescript
import { evolveIdentity } from '@usekova/identity';

const evolved = await evolveIdentity(identity, {
  operatorKeyPair: kp,
  changeType: 'capability_change',
  description: 'Added admin capability',
  updates: { capabilities: ['read', 'write', 'admin'] },
});

console.log(evolved.version);          // 2
console.log(evolved.lineage.length);   // 2
```

### Verify, Lineage, and Serialization

```typescript
import { verifyIdentity, getLineage, shareAncestor, serializeIdentity } from '@usekova/identity';

const result = await verifyIdentity(identity);
console.log(result.valid); // true

const lineage = getLineage(identity);
const related = shareAncestor(agent1, agent2);
const json = serializeIdentity(identity);
```

## Key APIs

- **Lifecycle**: `createIdentity()`, `evolveIdentity()`, `verifyIdentity()`
- **Hashing**: `computeCapabilityManifestHash()`, `computeIdentityHash()`
- **Lineage**: `getLineage()`, `shareAncestor()`, `computeCarryForward()`
- **Serialization**: `serializeIdentity()`, `deserializeIdentity()`
- **Advanced**: `AdaptiveCarryForward`, `LineageCompactor`, `SemanticVersion`, `IdentitySimilarity`
- **Constants**: `DEFAULT_EVOLUTION_POLICY`
- **Types**: `AgentIdentity`, `LineageEntry`, `ModelAttestation`, `DeploymentContext`, `EvolutionPolicy`

## Docs

See the [Kova SDK root documentation](../../README.md) for the full API reference and architecture guide.
