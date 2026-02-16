# Migration Guide

Migrating from the monolithic `@stele/sdk` (v0.0.x) to the split package architecture.

## What Changed

The SDK was split from one package into three:

| Before | After | What moved |
|--------|-------|------------|
| `@stele/sdk` (431 exports) | `@stele/sdk` (126 exports) | Core client, crypto, CCL, middleware, adapters, conformance |
| — | `@stele/protocols` | Breach, reputation, game theory, consensus, and 16 more protocol modules |
| — | `@stele/enterprise` | Analytics, payments, governance, certification, trust-gate, i18n, and more |

## Step-by-Step Migration

### 1. Install new packages

```bash
# If you use protocol features (breach, reputation, game theory, etc.)
npm install @stele/protocols

# If you use enterprise features (analytics, payments, governance, etc.)
npm install @stele/enterprise
```

`@stele/sdk` stays the same — just slimmer.

### 2. Update protocol imports

**Before:**
```typescript
import {
  SteleClient,
  generateCanary,
  proveHonesty,
  computeReputationScore,
  byzantineFaultTolerance,
  BreachStateMachine,
  TrustGraph,
} from '@stele/sdk';
```

**After:**
```typescript
import { SteleClient } from '@stele/sdk';
import {
  generateCanary,
  proveHonesty,
  computeReputationScore,
  byzantineFaultTolerance,
  BreachStateMachine,
  TrustGraph,
} from '@stele/protocols';
```

### 3. Update enterprise imports

**Before:**
```typescript
import {
  createTrustGate,
  evaluateAccess,
  createAuthority,
  issueCertificate,
  createLedger,
  processPayment,
  createGovernancePolicy,
  t,
} from '@stele/sdk';
```

**After:**
```typescript
import {
  createTrustGate,
  evaluateAccess,
  createAuthority,
  issueCertificate,
  createLedger,
  processPayment,
  createGovernancePolicy,
  t,
} from '@stele/enterprise';
```

### 4. What stays in `@stele/sdk`

These imports are unchanged:

```typescript
import {
  // Client
  SteleClient,
  QuickCovenant,

  // Crypto
  generateKeyPair, sign, verify, sha256, KeyManager,

  // Core
  buildCovenant, verifyCovenant_core, countersignCovenant,

  // CCL
  parseCCL, evaluateCCL, matchAction, matchResource,

  // Identity
  createIdentity_core, evolveIdentity_core, verifyIdentity,

  // Store
  MemoryStore, FileStore, SqliteStore,

  // Enforcement
  Monitor, CapabilityGate, AuditChain,

  // Adapters
  steleMiddleware, withStele, withSteleTool,

  // Middleware
  MiddlewarePipeline, loggingMiddleware, rateLimitMiddleware,

  // Telemetry
  telemetryMiddleware, SteleMetrics,

  // Conformance
  runConformanceSuite,
} from '@stele/sdk';
```

## Quick Reference: Where Did It Go?

| Export | New Package |
|--------|-------------|
| `BreachStateMachine`, `TrustGraph`, `createBreachAttestation` | `@stele/protocols` |
| `computeReputationScore`, `createReceipt`, `ReceiptDAG` | `@stele/protocols` |
| `proveHonesty`, `mechanismDesign`, `coalitionStability` | `@stele/protocols` |
| `StreamlinedBFT`, `byzantineFaultTolerance` | `@stele/protocols` |
| `generateCanary`, `evaluateCanary`, `isCanaryExpired` | `@stele/protocols` |
| `generateComplianceProof`, `poseidonHash` | `@stele/protocols` |
| `compose`, `trustCompose`, `defineSafetyEnvelope` | `@stele/protocols` |
| `defineAlignment`, `assessAlignment` | `@stele/protocols` |
| `DiscoveryServer`, `DiscoveryClient` | `@stele/protocols` |
| `validateCovenantSchema`, `COVENANT_SCHEMA` | `@stele/protocols` |
| `createTrustGate`, `evaluateAccess` | `@stele/enterprise` |
| `createAuthority`, `issueCertificate` | `@stele/enterprise` |
| `createDashboard`, `createStandardDashboard` | `@stele/enterprise` |
| `aggregateData`, `computeTrends` | `@stele/enterprise` |
| `createGateway`, `processRequest` | `@stele/enterprise` |
| `createGovernancePolicy`, `quarantineAgent` | `@stele/enterprise` |
| `t`, `setDefaultLocale`, `addTranslation` | `@stele/enterprise` |
| `createLedger`, `processPayment` | `@stele/enterprise` |
| `createRail`, `executeRailTransaction` | `@stele/enterprise` |
| `createFeeSchedule`, `calculateFee` | `@stele/enterprise` |

---
