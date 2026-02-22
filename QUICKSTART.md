# Kervyx: 5-Minute Quickstart

Go from zero to enforcing your first covenant in under five minutes.

## 1. Install

```bash
npm install @kervyx/sdk
```

The SDK re-exports everything you need from the underlying packages (`@kervyx/crypto`, `@kervyx/ccl`, `@kervyx/core`, `@kervyx/identity`, `@kervyx/enforcement`). One import covers the full API.

## 2. Create Keys

Every party in a covenant needs an Ed25519 key pair. Generate one:

```typescript
import { KervyxClient } from '@kervyx/sdk';

const issuerClient = new KervyxClient();
const issuerKeys = await issuerClient.generateKeyPair();
console.log(issuerKeys.publicKeyHex); // 64-char hex-encoded public key

// The beneficiary also needs keys — typically on a different machine
const beneficiaryClient = new KervyxClient();
const beneficiaryKeys = await beneficiaryClient.generateKeyPair();
```

## 3. Define Constraints

Constraints are written in CCL (Constraint Commitment Language). Each statement is a single line that permits, denies, or limits an action on a resource path.

```typescript
const constraints = [
  "permit read on '/data/**'",           // Allow reading anything under /data
  "permit write on '/data/reports/**'",   // Allow writing to reports
  "deny delete on '/data/**'",           // Never allow deletion
  "limit api.call 1000 per 1 hours",    // Rate-limit API calls
].join('\n');
```

Key CCL rules:
- **Default deny**: if no rule matches, the action is denied.
- **Deny wins**: a deny rule always overrides a permit rule at the same specificity.
- **Resource paths** use glob syntax: `**` matches any depth, `*` matches one segment.

## 4. Build a Covenant

A covenant binds an issuer's commitment to a beneficiary with cryptographic signatures:

```typescript
const covenant = await issuerClient.createCovenant({
  issuer: {
    id: 'acme-corp',
    publicKey: issuerKeys.publicKeyHex,
    role: 'issuer',
  },
  beneficiary: {
    id: 'partner-agent',
    publicKey: beneficiaryKeys.publicKeyHex,
    role: 'beneficiary',
  },
  constraints,
  metadata: {
    name: 'Data Access Covenant',
    description: 'Governs partner agent access to ACME data lake',
    tags: ['data-access', 'production'],
  },
});

console.log(covenant.id);        // SHA-256 content hash (serves as the ID)
console.log(covenant.signature); // Ed25519 signature over canonical form
console.log(covenant.nonce);     // 32-byte nonce for replay protection
```

## 5. Verify

The beneficiary (or any third party) can independently verify the covenant without trusting the issuer's infrastructure:

```typescript
const verification = await beneficiaryClient.verifyCovenant(covenant);

console.log(verification.valid); // true

// Inspect individual checks
for (const check of verification.checks) {
  console.log(`${check.name}: ${check.passed ? 'PASS' : 'FAIL'} — ${check.message}`);
}
// id_match: PASS — Document ID matches canonical hash
// signature_valid: PASS — Issuer signature is valid
// not_expired: PASS — No expiry set
// ccl_parses: PASS — CCL parsed successfully (4 statement(s))
// nonce_present: PASS — Nonce is present and valid (64-char hex)
// ... (11 checks total)
```

## 6. Enforce

Evaluate actions against the covenant at runtime. The CCL engine determines whether each action is permitted:

```typescript
// This should succeed — reading from /data is permitted
const readResult = await issuerClient.evaluateAction(
  covenant,
  'read',
  '/data/users/profile.json',
);
console.log(readResult.permitted); // true
console.log(readResult.matchedRule?.type); // 'permit'

// This should succeed — writing to reports is permitted
const writeResult = await issuerClient.evaluateAction(
  covenant,
  'write',
  '/data/reports/q4-summary.pdf',
);
console.log(writeResult.permitted); // true
```

## 7. React to Violations

When an action is denied, the result tells you exactly why:

```typescript
// This should fail — delete is explicitly denied on /data/**
const deleteResult = await issuerClient.evaluateAction(
  covenant,
  'delete',
  '/data/users/profile.json',
);
console.log(deleteResult.permitted);        // false
console.log(deleteResult.matchedRule?.type); // 'deny'

// This should also fail — no permit rule matches /system paths (default deny)
const systemResult = await issuerClient.evaluateAction(
  covenant,
  'read',
  '/system/config',
);
console.log(systemResult.permitted); // false

// Use the event system for centralized violation handling
issuerClient.on('evaluation:completed', (event) => {
  if (!event.result.permitted) {
    console.warn(
      `DENIED: ${event.action} on ${event.resource}`,
      event.result.reason,
    );
  }
});
```

## 8. Next Steps

You now have a working covenant pipeline: create, sign, verify, enforce. Here is where to go next.

**Express Middleware** -- Enforce covenants on every HTTP request:
```typescript
import { kervyxMiddleware } from '@kervyx/sdk';
app.use(kervyxMiddleware({ covenant, client: issuerClient }));
```

**Vercel AI SDK** -- Wrap AI tools with covenant enforcement:
```typescript
import { withKervyx } from '@kervyx/sdk';
const guardedTool = withKervyx(myTool, { covenant, client });
```

**LangChain** -- Add a callback handler to any chain:
```typescript
import { KervyxCallbackHandler } from '@kervyx/sdk';
const handler = new KervyxCallbackHandler({ covenant, client });
```

**Key Rotation** -- Automatic key lifecycle management:
```typescript
const client = new KervyxClient({
  keyRotation: { maxAgeMs: 86_400_000, overlapPeriodMs: 3_600_000 },
});
await client.initializeKeyRotation();
```

**Chain Delegation** -- Create child covenants that narrow a parent's permissions:
```typescript
const child = await issuerClient.createCovenant({
  issuer: { id: 'acme-corp', publicKey: issuerKeys.publicKeyHex, role: 'issuer' },
  beneficiary: { id: 'sub-agent', publicKey: subAgentPubHex, role: 'beneficiary' },
  constraints: "permit read on '/data/reports/**'", // narrower than parent
  chain: { parentId: covenant.id, relation: 'restricts', depth: 1 },
});
const chainResult = await issuerClient.validateChain([covenant, child]);
console.log(chainResult.valid); // true — child only narrows
```

**Countersignatures** -- Let auditors co-sign covenants:
```typescript
const auditorClient = new KervyxClient();
const auditorKeys = await auditorClient.generateKeyPair();
const audited = await auditorClient.countersign(covenant, 'auditor');
```

Full API reference: see the JSDoc comments in `@kervyx/sdk` or run `npx typedoc`.
