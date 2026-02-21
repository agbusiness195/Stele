# @grith/verifier

Independent verification engine for third-party auditors. Wraps core verification with history tracking, batch processing, chain integrity validation, and action-level evaluation.

## Installation

```bash
npm install @grith/verifier
```

## Usage

### Single Document Verification

```typescript
import { Verifier } from '@grith/verifier';

const verifier = new Verifier({ strictMode: true });

const report = await verifier.verify(doc);
console.log(report.valid);       // true/false
console.log(report.durationMs);  // timing
console.log(report.warnings);    // non-fatal issues
console.log(report.verifierId);  // unique verifier instance ID
```

### Chain Verification

```typescript
// Documents ordered root-first: [root, child1, child2, ...]
const report = await verifier.verifyChain([rootDoc, childDoc]);

console.log(report.valid);
console.log(report.integrityChecks);   // parent refs, depth, narrowing
console.log(report.narrowingResults);  // per-pair narrowing validation
console.log(report.documentResults);   // per-document verification
```

### Action Verification

```typescript
const report = await verifier.verifyAction(doc, 'read', '/data/users');

console.log(report.permitted);      // access decision
console.log(report.documentValid);  // was the document itself valid?
console.log(report.matchedRule);    // which CCL rule matched
console.log(report.reason);         // human-readable explanation
```

### Batch Verification

```typescript
import { verifyBatch } from '@grith/verifier';

const report = await verifyBatch([doc1, doc2, doc3]);
console.log(`${report.summary.passed}/${report.summary.total} passed`);
console.log(`Total time: ${report.summary.durationMs}ms`);
```

### History Tracking

```typescript
const history = verifier.getHistory();
console.log(history.length);            // number of verifications performed
console.log(history[0].kind);           // 'single' | 'chain' | 'action'
console.log(history[0].documentIds);    // which documents were verified

verifier.clearHistory();
```

## Key APIs

- **Verifier class**: `verify()`, `verifyChain()`, `verifyAction()`, `getHistory()`, `clearHistory()`
- **Standalone**: `verifyBatch()`
- **Options**: `strictMode`, `maxHistorySize`, `maxChainDepth`, `verifierId`
- **Report types**: `VerificationReport`, `ChainVerificationReport`, `ActionVerificationReport`, `BatchVerificationReport`

## Docs

See the [Grith SDK root documentation](../../README.md) for the full API reference and architecture guide.
