# @stele/enterprise

Enterprise features for [Stele](https://stele.dev) — analytics, payments, governance, certification, and more.

All modules are **zero-dependency** and work standalone or alongside `@stele/sdk`.

## Install

```bash
npm install @stele/enterprise
```

## Modules

### Trust Gate

Tiered access control based on agent trust scores.

```typescript
import { createTrustGate, evaluateAccess } from '@stele/enterprise';

const gate = createTrustGate({ minimumTrustScore: 0.5, premiumThreshold: 0.9 });
const decision = evaluateAccess(gate, { agentId: 'agent-1', trustScore: 0.75 });
console.log(decision.level); // 'standard'
```

### Certification

UL-style agent certification with tiered requirements (basic / standard / enterprise).

```typescript
import { createAuthority, issueCertificate, verifyCertificate } from '@stele/enterprise';

const authority = createAuthority({ authorityId: 'cert-1', name: 'Acme CA', publicKey });
const { certificate } = issueCertificate(authority, {
  agentId: 'agent-1', tier: 'standard', scope: ['read', 'write'],
  trustScore: 0.85, historyDays: 120, attestationCount: 80,
});
verifyCertificate(certificate); // { valid: true }
```

### Dashboard

Metrics dashboard with aggregation and pruning.

```typescript
import { createStandardDashboard, addMetric } from '@stele/enterprise';

const dashboard = createStandardDashboard();
// Pre-built panels: Trust Overview, Enforcement, Performance, Business
addMetric(dashboard, { panel: 'Trust Overview', metric: 'trust_resolutions_total', value: 42 });
```

### Analytics

Trust data aggregation with privacy-preserving anonymization.

```typescript
import { aggregateData, anonymizeDataset, computeTrends } from '@stele/enterprise';

const insight = aggregateData(trustDataPoints);
const anonymous = anonymizeDataset(insight, { method: 'differential-privacy', privacyBudget: 1.0 });
const trends = computeTrends([insight1, insight2, insight3]);
// trends.trustTrend: 'improving' | 'stable' | 'declining'
```

### Gateway

Trust-gated API gateway with configurable rules.

```typescript
import { createGateway, processRequest } from '@stele/enterprise';

const gateway = createGateway({ requireCovenant: true, minimumTrustScore: 0.5 });
const response = processRequest(gateway, {
  agentId: 'agent-1', resource: '/api/data',
  hasCovenant: true, hasIdentity: true, trustScore: 0.8,
});
```

### Governance

Multi-agent organization governance with quarantine controls.

```typescript
import { createGovernancePolicy, registerGovernanceAgent, quarantineAgent } from '@stele/enterprise';

const policy = createGovernancePolicy({ organizationId: 'org-1', maxAgents: 50 });
const agent = registerGovernanceAgent(policy, 'agent-1');
quarantineAgent(agent, 'Policy violation detected');
```

### i18n

Internationalization for SDK messages (en, de, fr, es, ja).

```typescript
import { t, setDefaultLocale } from '@stele/enterprise';

setDefaultLocale('de');
console.log(t('ACCESS_DENIED')); // "Zugriff verweigert"
```

### Payments

Two-sided query-based payment ledger.

```typescript
import { createLedger, createAccount, processPayment } from '@stele/enterprise';

let ledger = createLedger();
ledger = createAccount(ledger, 'agent-1', 0.0002);
const { ledger: updated } = processPayment(ledger, {
  from: 'agent-1', to: 'agent-2', amount: 1.50, type: 'trust_resolution',
});
```

### Rail

Atomic trust+transaction execution rails.

```typescript
import { createRail, initiateRailTransaction, executeRailTransaction } from '@stele/enterprise';

const rail = createRail({ feeRate: 0.0015, minimumTrustScore: 0.3 });
const tx = initiateRailTransaction(rail, {
  buyerAgentId: 'buyer', sellerAgentId: 'seller',
  action: 'data.access', resource: '/premium', value: 100,
  buyerTrustScore: 0.8, sellerTrustScore: 0.9, covenantCompatible: true,
});
const completed = executeRailTransaction(tx);
```

### Fees

Tiered fee schedules with revenue projection.

```typescript
import { createFeeSchedule, calculateFee, projectRevenue } from '@stele/enterprise';

const schedule = createFeeSchedule();
const fee = calculateFee(schedule, 500);
const projection = projectRevenue({
  schedule, dailyTransactions: 1000, averageValue: 50,
  growthRatePerMonth: 0.1, months: 12,
});
```

## Related Packages

| Package | Use case |
|---------|----------|
| [`@stele/sdk`](../sdk) | Core client, crypto, CCL, middleware, adapters |
| [`@stele/protocols`](../protocols) | Protocol extensions (breach, reputation, game theory, etc.) |

## License

MIT
