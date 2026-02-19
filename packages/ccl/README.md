# @usekova/ccl

Covenant Constraint Language (CCL) parser and evaluator. CCL is a domain-specific language for expressing access control policies in Kova covenants.

## Installation

```bash
npm install @usekova/ccl
```

## Usage

### Parse and Evaluate

```typescript
import { parse, evaluate } from '@usekova/ccl';

const doc = parse(`
  permit read on '/data/**'
  deny write on '/system/**'
  limit api.call 1000 per 1 hours
`);

// Permit check
const r1 = evaluate(doc, 'read', '/data/users');
console.log(r1.permitted); // true

// Deny check
const r2 = evaluate(doc, 'write', '/system/config');
console.log(r2.permitted); // false

// Default deny: unmatched actions are denied
const r3 = evaluate(doc, 'delete', '/other');
console.log(r3.permitted); // false
```

### Conditional Rules

```typescript
const doc = parse("permit read on '/data/**' when risk_level = 'low'");
const result = evaluate(doc, 'read', '/data/users', { risk_level: 'low' });
console.log(result.permitted); // true
```

### Merge and Narrowing

```typescript
import { parse, merge, validateNarrowing, serialize } from '@usekova/ccl';

const parent = parse("permit read on '**'");
const child = parse("permit read on '/data/**'\ndeny write on '**'");

// Merge uses deny-wins semantics
const merged = merge(parent, child);

// Validate that child only narrows parent
const result = validateNarrowing(parent, child);
console.log(result.valid); // true if child never broadens parent

// Convert back to CCL text
const text = serialize(merged);
```

## Key APIs

- **Parsing**: `parse()`, `tokenize()`, `parseTokens()`
- **Evaluation**: `evaluate()`, `matchAction()`, `matchResource()`, `checkRateLimit()`
- **Composition**: `merge()`, `validateNarrowing()`, `serialize()`
- **Errors/Types**: `CCLSyntaxError`, `CCLDocument`, `EvaluationResult`, `NarrowingViolation`

## Gotchas

- `severity` is a reserved keyword in `when` conditions -- use `risk_level` or another name.
- Resource matching is exact: `/secrets` does NOT match `/secrets/key` -- use `**` wildcards.
- Default deny: when no rules match, `evaluate()` returns `{ permitted: false }`.

## Docs

See the [Kova SDK root documentation](../../README.md) for the full API reference and architecture guide.
