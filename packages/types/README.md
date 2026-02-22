# @kervyx/types

Shared type definitions, error classes, validation utilities, and protocol constants for the Kervyx SDK.

## Installation

```bash
npm install @kervyx/types
```

## Usage

### Error Classes

```typescript
import { KervyxError, KervyxErrorCode, ValidationError } from '@kervyx/types';

try {
  throw new KervyxError('Something went wrong', KervyxErrorCode.INVALID_INPUT);
} catch (err) {
  if (err instanceof KervyxError) {
    console.log(err.code); // 'INVALID_INPUT'
  }
}
```

### Result Type

```typescript
import { ok, err, type Result } from '@kervyx/types';

function divide(a: number, b: number): Result<number> {
  if (b === 0) return err(new Error('Division by zero'));
  return ok(a / b);
}

const result = divide(10, 2);
if (result.ok) {
  console.log(result.value); // 5
}
```

### Validation Utilities

```typescript
import { validateNonEmpty, validateRange, validateHex, validateProbability } from '@kervyx/types';

validateNonEmpty(name, 'issuer.name');       // throws ValidationError if blank
validateRange(depth, 1, 16, 'chain.depth');  // throws if outside [1, 16]
validateHex(pubkey, 'publicKey');             // throws if not valid hex
validateProbability(rate, 'carryForward');    // throws if not in [0, 1]
```

### Type Guards

```typescript
import { isNonEmptyString, isValidHex, isValidPublicKey, sanitizeString } from '@kervyx/types';

if (isValidPublicKey(input)) {
  // input is narrowed to a valid public key string
}

const safe = sanitizeString(userInput, { maxLength: 256 });
```

## Key APIs

- **Error classes**: `KervyxError`, `ValidationError`, `CryptoError`, `CCLError`, `ChainError`, `StorageError`
- **Result type**: `Result<T, E>`, `ok()`, `err()`
- **Validation**: `validateNonEmpty()`, `validateRange()`, `validateHex()`, `validateProbability()`
- **Type guards**: `isNonEmptyString()`, `isValidHex()`, `isValidPublicKey()`, `isPlainObject()`
- **Sanitization**: `sanitizeString()`, `sanitizeJsonInput()`, `freezeDeep()`
- **Observability**: `Logger`, `createLogger()`, `Tracer`, `Counter`, `Gauge`, `Histogram`
- **Resilience**: `withRetry()`, `CircuitBreaker`, `HealthChecker`
- **Constants**: `KERVYX_VERSION`, `DEFAULT_SEVERITY`, `SUPPORTED_HASH_ALGORITHMS`

## Docs

See the [Kervyx SDK root documentation](../../README.md) for the full API reference and architecture guide.
