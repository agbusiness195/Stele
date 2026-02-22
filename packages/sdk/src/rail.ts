/**
 * Trust resolution as transaction execution for the Nobulex protocol.
 *
 * Merges trust verification with transaction execution into one atomic
 * operation. Trust resolution IS the transaction -- there is no separate
 * "verify then execute" flow. If trust verification fails, the transaction
 * never starts.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** A rail transaction combining trust verification and execution atomically. */
export interface RailTransaction {
  /** Unique transaction identifier. */
  id: string;
  /** The buyer agent's identifier. */
  buyerAgentId: string;
  /** The seller agent's identifier. */
  sellerAgentId: string;
  /** The action being transacted. */
  action: string;
  /** The resource being transacted. */
  resource: string;
  /** The monetary value of the transaction. */
  value: number;
  /** Trust verification details for both parties. */
  trustVerification: {
    buyerTrustScore: number;
    sellerTrustScore: number;
    covenantCompatible: boolean;
    verifiedAt: number;
  };
  /** Execution status tracking. */
  execution: {
    status: 'pending' | 'verified' | 'executing' | 'completed' | 'failed' | 'rolled_back';
    startedAt: number;
    completedAt?: number;
  };
  /** Fee charged for this transaction (0.15% of value). */
  fee: number;
  /** Whether trust verification and execution are atomic. */
  atomic: boolean;
}

/** Configuration for the rail system. */
export interface RailConfig {
  /** Fee rate as a fraction of transaction value. Default: 0.0015 (0.15%) */
  feeRate: number;
  /** Minimum trust score required for both parties. Default: 0.3 */
  minimumTrustScore: number;
  /** Whether covenant compatibility is required. Default: true */
  requireCovenantMatch: boolean;
  /** Whether trust+transaction are one atomic step. Default: true */
  atomicExecution: boolean;
  /** Timeout for transaction completion in milliseconds. Default: 30000 */
  timeoutMs: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

let _railTxCounter = 0;

function generateRailTransactionId(): string {
  _railTxCounter += 1;
  return `rail-${Date.now()}-${_railTxCounter}`;
}

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Create a rail configuration with sensible defaults.
 *
 * @param config - Optional partial configuration overrides.
 * @returns A complete RailConfig.
 */
export function createRail(config?: Partial<RailConfig>): RailConfig {
  return {
    feeRate: config?.feeRate ?? 0.0015,
    minimumTrustScore: config?.minimumTrustScore ?? 0.3,
    requireCovenantMatch: config?.requireCovenantMatch ?? true,
    atomicExecution: config?.atomicExecution ?? true,
    timeoutMs: config?.timeoutMs ?? 30000,
  };
}

// ─── Transaction Initiation ──────────────────────────────────────────────────

/**
 * Initiate a rail transaction with atomic trust verification.
 *
 * Verifies both parties' trust scores meet the minimum and that
 * covenants are compatible (if required). If ANY verification fails,
 * an error is returned and the transaction never starts. If all
 * verifications pass, returns a transaction with 'verified' status.
 *
 * @param rail - The rail configuration.
 * @param params - Transaction parameters including both parties and trust data.
 * @returns A verified RailTransaction, or an error object.
 */
export function initiateRailTransaction(
  rail: RailConfig,
  params: {
    buyerAgentId: string;
    sellerAgentId: string;
    action: string;
    resource: string;
    value: number;
    buyerTrustScore: number;
    sellerTrustScore: number;
    covenantCompatible: boolean;
  },
): RailTransaction | { error: string } {
  // Verify buyer trust score
  if (params.buyerTrustScore < rail.minimumTrustScore) {
    return {
      error: `Buyer trust score ${params.buyerTrustScore} below minimum ${rail.minimumTrustScore}`,
    };
  }

  // Verify seller trust score
  if (params.sellerTrustScore < rail.minimumTrustScore) {
    return {
      error: `Seller trust score ${params.sellerTrustScore} below minimum ${rail.minimumTrustScore}`,
    };
  }

  // Verify covenant compatibility
  if (rail.requireCovenantMatch && !params.covenantCompatible) {
    return {
      error: 'Covenant compatibility required but not satisfied',
    };
  }

  const now = Date.now();
  const fee = params.value * rail.feeRate;

  return {
    id: generateRailTransactionId(),
    buyerAgentId: params.buyerAgentId,
    sellerAgentId: params.sellerAgentId,
    action: params.action,
    resource: params.resource,
    value: params.value,
    trustVerification: {
      buyerTrustScore: params.buyerTrustScore,
      sellerTrustScore: params.sellerTrustScore,
      covenantCompatible: params.covenantCompatible,
      verifiedAt: now,
    },
    execution: {
      status: 'verified',
      startedAt: now,
    },
    fee,
    atomic: rail.atomicExecution,
  };
}

// ─── Transaction Execution ───────────────────────────────────────────────────

/**
 * Execute a verified rail transaction, moving it to 'completed' status.
 *
 * @param transaction - A transaction in 'verified' status.
 * @returns The transaction with 'completed' status and completedAt timestamp.
 */
export function executeRailTransaction(transaction: RailTransaction): RailTransaction {
  return {
    ...transaction,
    execution: {
      ...transaction.execution,
      status: 'completed',
      completedAt: Date.now(),
    },
  };
}

// ─── Transaction Rollback ────────────────────────────────────────────────────

/**
 * Roll back a rail transaction.
 *
 * @param transaction - The transaction to roll back.
 * @param _reason - Reason for rollback (for audit purposes).
 * @returns The transaction with 'rolled_back' status.
 */
export function rollbackRailTransaction(
  transaction: RailTransaction,
  _reason: string,
): RailTransaction {
  return {
    ...transaction,
    execution: {
      ...transaction.execution,
      status: 'rolled_back',
      completedAt: Date.now(),
    },
  };
}

// ─── Volume Analytics ────────────────────────────────────────────────────────

/**
 * Compute aggregate volume metrics from rail transactions.
 *
 * @param transactions - Array of rail transactions.
 * @returns Volume, fee, count, and average metrics.
 */
export function computeRailVolume(transactions: RailTransaction[]): {
  totalVolume: number;
  totalFees: number;
  completedCount: number;
  failedCount: number;
  averageValue: number;
  feeRevenue: number;
} {
  const completed = transactions.filter(
    (t) => t.execution.status === 'completed',
  );
  const failed = transactions.filter(
    (t) =>
      t.execution.status === 'failed' || t.execution.status === 'rolled_back',
  );

  const totalVolume = completed.reduce((sum, t) => sum + t.value, 0);
  const totalFees = completed.reduce((sum, t) => sum + t.fee, 0);
  const completedCount = completed.length;
  const failedCount = failed.length;
  const averageValue = completedCount === 0 ? 0 : totalVolume / completedCount;

  return {
    totalVolume,
    totalFees,
    completedCount,
    failedCount,
    averageValue,
    feeRevenue: totalFees,
  };
}
