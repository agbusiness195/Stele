# @kervyx/crypto

Ed25519 cryptography, SHA-256 hashing, and encoding utilities for the Kervyx protocol. Built on [@noble/ed25519](https://github.com/paulmillr/noble-ed25519) and [@noble/hashes](https://github.com/paulmillr/noble-hashes).

## Installation

```bash
npm install @kervyx/crypto
```

## Usage

### Key Generation and Signing

```typescript
import { generateKeyPair, sign, verify, toHex } from '@kervyx/crypto';

const kp = await generateKeyPair();
console.log(kp.publicKeyHex); // 64-char hex string

const message = new TextEncoder().encode('hello');
const signature = await sign(message, kp.privateKey);

const valid = await verify(message, signature, kp.publicKey);
console.log(valid); // true
```

### Hashing

```typescript
import { sha256, sha256String, sha256Object } from '@kervyx/crypto';

const hash = sha256(new TextEncoder().encode('hello'));
const strHash = sha256String('hello world');
const objHash = sha256Object({ b: 2, a: 1 }); // deterministic, key-order independent
```

### Canonical JSON

```typescript
import { canonicalizeJson } from '@kervyx/crypto';

canonicalizeJson({ z: 1, a: 2 }); // '{"a":2,"z":1}' -- RFC 8785 (JCS)
```

### Hex and Base64url Encoding

```typescript
import { toHex, fromHex, base64urlEncode, base64urlDecode } from '@kervyx/crypto';

toHex(new Uint8Array([255, 0]));  // 'ff00'
fromHex('ff00');                   // Uint8Array [255, 0]

const encoded = base64urlEncode(new Uint8Array([72, 101, 108]));
const decoded = base64urlDecode(encoded);
```

### Key Rotation

```typescript
import { KeyManager } from '@kervyx/crypto';

const manager = new KeyManager({ maxAgeMs: 86_400_000 }); // 24h rotation
const managed = await manager.initialize();
console.log(managed.keyPair.publicKeyHex);
```

## Key APIs

- **Key management**: `generateKeyPair()`, `keyPairFromPrivateKey()`, `keyPairFromPrivateKeyHex()`, `KeyManager`
- **Signing**: `sign()`, `signString()`, `verify()`
- **Hashing**: `sha256()`, `sha256String()`, `sha256Object()`, `canonicalizeJson()`
- **Encoding**: `toHex()`, `fromHex()`, `base64urlEncode()`, `base64urlDecode()`
- **Utilities**: `generateNonce()`, `generateId()`, `constantTimeEqual()`, `timestamp()`

## Docs

See the [Kervyx SDK root documentation](../../README.md) for the full API reference and architecture guide.
