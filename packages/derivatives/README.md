# @grith/derivatives

Covenant derivative instruments and transformation calculus. Provides risk assessment, insurance policy pricing, trust futures, Black-Scholes option pricing for behavioral contracts, Value at Risk (VaR), and hedge ratio computation.

## Installation

```bash
npm install @grith/derivatives
```

## Key APIs

- **assessRisk(agentId, reputation, config?)**: Compute breach probability and expected loss from reputation data
- **priceInsurance(risk, coverage, term, config?)**: Compute insurance premium from risk, coverage amount, and term
- **createPolicy(agentId, covenantId, assessment, coverage, term, underwriter, config?)**: Create an `AgentInsurancePolicy` with computed premium
- **claimPolicy(policy, lossAmount)**: File a claim against an active insurance policy
- **createFuture(agentId, metric, targetValue, settlementDate, premium, holder)**: Create a `TrustFuture` contract
- **settleFuture(future, actualValue)**: Settle a future with proportional payout based on metric performance
- **blackScholesPrice(params)**: Black-Scholes option pricing for behavioral contracts (call/put)
- **valueAtRisk(params)**: Parametric VaR computation at a given confidence level
- **hedgeRatio(params)**: Minimum variance hedge ratio for correlated risks

## Usage

```typescript
import {
  assessRisk,
  priceInsurance,
  createPolicy,
  createFuture,
  settleFuture,
  blackScholesPrice,
  valueAtRisk,
} from '@grith/derivatives';

// Assess agent risk from reputation data
const risk = assessRisk('agent-1', {
  trustScore: 0.85,
  complianceRate: 0.92,
  breachCount: 2,
  totalInteractions: 100,
  stakeAmount: 0.5,
  age: 180,
});

// Price and create an insurance policy
const premium = priceInsurance(risk, 10000, 365);
const policy = createPolicy('agent-1', 'cov-1', risk, 10000, 365, 'underwriter-1');

// Create and settle a trust future
const future = createFuture('agent-1', 'trustScore', 0.9, Date.now() + 86400000, 100, 'holder-1');
const settlement = settleFuture(future, 0.95);

// Black-Scholes pricing for a behavioral put option
const bs = blackScholesPrice({
  spotPrice: 0.85,
  strikePrice: 0.7,
  timeToMaturity: 1,
  riskFreeRate: 0.05,
  volatility: 0.2,
  optionType: 'put',
});
console.log(`Price: ${bs.price}`);

// Value at Risk
const var95 = valueAtRisk({
  portfolioValue: 100000,
  expectedReturn: 0.001,
  volatility: 0.02,
  confidenceLevel: 0.95,
});
console.log(`VaR: ${var95.valueAtRisk}`);
```

## Types

- `RiskAssessment` -- Breach probability, expected loss, recommended premium, and risk factors
- `AgentInsurancePolicy` -- Coverage, premium, underwriter, status, and term
- `TrustFuture` -- Futures contract on trustScore, complianceRate, or breachProbability
- `Settlement` -- Settlement result with actual value, target, and payout
- `BlackScholesParams` / `BlackScholesResult` -- Option pricing inputs and outputs
- `VaRParams` / `VaRResult` -- Value at Risk inputs and outputs
- `HedgeRatioParams` / `HedgeRatioResult` -- Hedge ratio inputs and outputs

## Docs

See the [Grith SDK root documentation](../../README.md) for the full API reference.
