/**
 * @stele/enterprise -- Enterprise features for the Stele protocol.
 *
 * Provides analytics, dashboards, trust-gated access, certification,
 * governance, payments, transaction rails, fee schedules, and i18n.
 *
 * These modules are zero-dependency and can be used independently
 * of the core SDK.
 *
 * @packageDocumentation
 */

// ─── Trust Gate ───────────────────────────────────────────────────────────────
export { createTrustGate, evaluateAccess, calculateRevenueLift } from './trust-gate.js';
export type { TrustGateConfig, AccessLevel, GateDecision } from './trust-gate.js';

// ─── Certification ────────────────────────────────────────────────────────────
export {
  CERTIFICATION_REQUIREMENTS,
  createAuthority,
  issueCertificate,
  revokeCertificate,
  verifyCertificate,
} from './certification.js';
export type { Certificate, CertificationAuthority, CertificationRequirements } from './certification.js';

// ─── Dashboard ────────────────────────────────────────────────────────────────
export {
  STANDARD_METRICS,
  createDashboard,
  addMetric,
  createStandardDashboard,
  aggregateMetric,
  pruneOldData,
} from './dashboard.js';
export type { DashboardConfig, MetricPoint, MetricSeries, DashboardPanel, Dashboard } from './dashboard.js';

// ─── Analytics ────────────────────────────────────────────────────────────────
export { aggregateData, anonymizeDataset, computeTrends } from './analytics.js';
export type { TrustDataPoint, AggregatedInsight, AnonymizedDataset } from './analytics.js';

// ─── Gateway ──────────────────────────────────────────────────────────────────
export {
  createGateway,
  isResourceAllowed,
  processRequest,
  aggregateMetrics,
} from './gateway.js';
export type { GatewayConfig, GatewayRequest, GatewayResponse, GatewayMetrics } from './gateway.js';

// ─── Governance ───────────────────────────────────────────────────────────────
export {
  createGovernancePolicy,
  registerAgent,
  updateAgentStatus,
  quarantineAgent,
  unquarantineAgent,
  buildDashboard,
} from './governance.js';
export type { GovernancePolicy, AgentStatus, GovernanceDashboard } from './governance.js';

// ─── i18n ─────────────────────────────────────────────────────────────────────
export {
  TRANSLATION_KEYS,
  CATALOGS,
  t,
  setDefaultLocale,
  getDefaultLocale,
  addTranslation,
  getSupportedLocales,
} from './i18n.js';

// ─── Payments ─────────────────────────────────────────────────────────────────
export {
  createLedger,
  createAccount,
  recordQueryIncome,
  processPayment,
  getAccountSummary,
} from './payments.js';
export type { PaymentAccount, PaymentTransaction, PaymentLedger } from './payments.js';

// ─── Rail ─────────────────────────────────────────────────────────────────────
export {
  createRail,
  initiateRailTransaction,
  executeRailTransaction,
  rollbackRailTransaction,
  computeRailVolume,
} from './rail.js';
export type { RailTransaction, RailConfig } from './rail.js';

// ─── Fees ─────────────────────────────────────────────────────────────────────
export {
  createFeeSchedule,
  calculateFee,
  aggregateFees,
  projectRevenue,
} from './fees.js';
export type { FeeSchedule, FeeCalculation, FeeAggregate } from './fees.js';
