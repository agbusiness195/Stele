/**
 * Fee calculation and revenue projection for the Grith protocol.
 *
 * Implements a trust tax and value-proportional pricing system. Fees are
 * determined by transaction value tiers and clamped to configured minimums
 * and maximums. Supports aggregate analysis and revenue projection over time.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** Fee schedule defining the pricing model. */
export interface FeeSchedule {
  /** Base fee charged per transaction. Default: 0.001 */
  baseFee: number;
  /** Value tiers mapping transaction amounts to fee rates. */
  valueTiers: Array<{ maxValue: number; feeRate: number }>;
  /** Minimum fee that can be charged. Default: 0.0001 */
  minimumFee: number;
  /** Maximum fee that can be charged. Default: 100 */
  maximumFee: number;
}

/** Result of calculating a fee for a single transaction. */
export interface FeeCalculation {
  /** The transaction's value. */
  transactionValue: number;
  /** The tier that was applied. */
  applicableTier: { maxValue: number; feeRate: number };
  /** The raw fee from the tier (before clamping). */
  rawFee: number;
  /** The final fee after clamping to min/max. */
  finalFee: number;
  /** The effective rate (finalFee / transactionValue). */
  effectiveRate: number;
}

/** Aggregate fee statistics across multiple transactions. */
export interface FeeAggregate {
  /** Total number of transactions. */
  totalTransactions: number;
  /** Total volume of all transactions. */
  totalVolume: number;
  /** Total fees collected. */
  totalFees: number;
  /** Average fee per transaction. */
  averageFee: number;
  /** Average effective rate across all transactions. */
  averageEffectiveRate: number;
}

// ─── Default Tiers ───────────────────────────────────────────────────────────

const DEFAULT_VALUE_TIERS: Array<{ maxValue: number; feeRate: number }> = [
  { maxValue: 1, feeRate: 0.001 },
  { maxValue: 100, feeRate: 0.005 },
  { maxValue: 10000, feeRate: 0.01 },
  { maxValue: 1000000, feeRate: 0.1 },
  { maxValue: Infinity, feeRate: 10 },
];

// ─── Factory ─────────────────────────────────────────────────────────────────

/**
 * Create a fee schedule with sensible defaults.
 *
 * @param overrides - Optional partial overrides.
 * @returns A complete FeeSchedule.
 */
export function createFeeSchedule(overrides?: Partial<FeeSchedule>): FeeSchedule {
  return {
    baseFee: overrides?.baseFee ?? 0.001,
    valueTiers: overrides?.valueTiers ?? [...DEFAULT_VALUE_TIERS],
    minimumFee: overrides?.minimumFee ?? 0.0001,
    maximumFee: overrides?.maximumFee ?? 100,
  };
}

// ─── Fee Calculation ─────────────────────────────────────────────────────────

/**
 * Calculate the fee for a transaction of a given value.
 *
 * Finds the first tier where the transaction value is at or below the
 * tier's maxValue. The raw fee is the tier's feeRate, clamped to the
 * schedule's minimumFee and maximumFee.
 *
 * @param schedule - The fee schedule.
 * @param transactionValue - The value of the transaction.
 * @returns A FeeCalculation with raw, final, and effective rate.
 */
export function calculateFee(schedule: FeeSchedule, transactionValue: number): FeeCalculation {
  // Find the applicable tier (first where transactionValue <= maxValue)
  const applicableTier =
    schedule.valueTiers.find((tier) => transactionValue <= tier.maxValue) ??
    schedule.valueTiers[schedule.valueTiers.length - 1]!;

  const rawFee = applicableTier.feeRate;

  // Clamp to min/max
  const finalFee = Math.max(schedule.minimumFee, Math.min(schedule.maximumFee, rawFee));

  // Effective rate
  const effectiveRate = transactionValue === 0 ? 0 : finalFee / transactionValue;

  return {
    transactionValue,
    applicableTier,
    rawFee,
    finalFee,
    effectiveRate,
  };
}

// ─── Aggregation ─────────────────────────────────────────────────────────────

/**
 * Aggregate fee calculations into summary statistics.
 *
 * @param calculations - Array of individual fee calculations.
 * @returns A FeeAggregate with totals and averages.
 */
export function aggregateFees(calculations: FeeCalculation[]): FeeAggregate {
  const totalTransactions = calculations.length;

  if (totalTransactions === 0) {
    return {
      totalTransactions: 0,
      totalVolume: 0,
      totalFees: 0,
      averageFee: 0,
      averageEffectiveRate: 0,
    };
  }

  const totalVolume = calculations.reduce((sum, c) => sum + c.transactionValue, 0);
  const totalFees = calculations.reduce((sum, c) => sum + c.finalFee, 0);
  const averageFee = totalFees / totalTransactions;
  const totalEffectiveRate = calculations.reduce((sum, c) => sum + c.effectiveRate, 0);
  const averageEffectiveRate = totalEffectiveRate / totalTransactions;

  return {
    totalTransactions,
    totalVolume,
    totalFees,
    averageFee,
    averageEffectiveRate,
  };
}

// ─── Revenue Projection ─────────────────────────────────────────────────────

/**
 * Project revenue over time with monthly growth.
 *
 * @param params - Projection parameters including daily transactions,
 *   average value, growth rate, and number of months.
 * @returns Monthly revenue projections with cumulative totals.
 */
export function projectRevenue(params: {
  schedule: FeeSchedule;
  dailyTransactions: number;
  averageValue: number;
  growthRatePerMonth: number;
  months: number;
}): Array<{
  month: number;
  transactions: number;
  volume: number;
  fees: number;
  cumulativeFees: number;
}> {
  const { schedule, dailyTransactions, averageValue, growthRatePerMonth, months } = params;

  const feePerTransaction = calculateFee(schedule, averageValue).finalFee;
  const results: Array<{
    month: number;
    transactions: number;
    volume: number;
    fees: number;
    cumulativeFees: number;
  }> = [];

  let cumulativeFees = 0;

  for (let month = 1; month <= months; month++) {
    const growthMultiplier = Math.pow(1 + growthRatePerMonth, month - 1);
    const monthlyTransactions = Math.round(dailyTransactions * 30 * growthMultiplier);
    const volume = monthlyTransactions * averageValue;
    const fees = monthlyTransactions * feePerTransaction;
    cumulativeFees += fees;

    results.push({
      month,
      transactions: monthlyTransactions,
      volume,
      fees,
      cumulativeFees,
    });
  }

  return results;
}
