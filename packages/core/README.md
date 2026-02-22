# @kervyx/core

Covenant document lifecycle: build, sign, verify, countersign, chain, and serialize. This is the protocol engine that ties `@kervyx/crypto` and `@kervyx/ccl` together.

## Installation

```bash
npm install @kervyx/core
```

## Usage

### Build and Verify a Covenant

```typescript
import { generateKeyPair } from '@kervyx/crypto';
import { buildCovenant, verifyCovenant } from '@kervyx/core';

const issuerKp = await generateKeyPair();
const beneficiaryKp = await generateKeyPair();

const doc = await buildCovenant({
  issuer: { id: 'alice', publicKey: issuerKp.publicKeyHex, role: 'issuer' },
  beneficiary: { id: 'bob', publicKey: beneficiaryKp.publicKeyHex, role: 'beneficiary' },
  constraints: "permit read on '/data/**'",
  privateKey: issuerKp.privateKey,
});

const result = await verifyCovenant(doc);
console.log(result.valid); // true
console.log(result.checks.map(c => `${c.name}: ${c.passed}`));
```

### Countersign

```typescript
import { countersignCovenant } from '@kervyx/core';

const auditorKp = await generateKeyPair();
const audited = await countersignCovenant(doc, auditorKp, 'auditor');
console.log(audited.countersignatures?.length); // 1
```

### Delegation Chains

```typescript
import { resolveChain, validateChainNarrowing, MemoryChainResolver } from '@kervyx/core';

const resolver = new MemoryChainResolver();
resolver.add(parentDoc);

const ancestors = await resolveChain(childDoc, resolver);
const narrowing = await validateChainNarrowing(childDoc, parentDoc);
console.log(narrowing.valid); // true if child only restricts parent
```

### Serialization

```typescript
import { serializeCovenant, deserializeCovenant } from '@kervyx/core';

const json = serializeCovenant(doc);
const restored = deserializeCovenant(json);
```

## Key APIs

- **Build**: `buildCovenant()`, `resignCovenant()`
- **Verify**: `verifyCovenant()` (11 specification checks)
- **Countersign**: `countersignCovenant()`
- **Chain**: `resolveChain()`, `computeEffectiveConstraints()`, `validateChainNarrowing()`, `MemoryChainResolver`
- **Canonical**: `canonicalForm()`, `computeId()`
- **Serialization**: `serializeCovenant()`, `deserializeCovenant()`
- **Schema**: `validateDocumentSchema()`, `validatePartySchema()`
- **Migration**: `DocumentMigrator`, `defaultMigrator`
- **Constants**: `PROTOCOL_VERSION`, `MAX_CONSTRAINTS`, `MAX_CHAIN_DEPTH`, `MAX_DOCUMENT_SIZE`

## Docs

See the [Kervyx SDK root documentation](../../README.md) for the full API reference and architecture guide.
