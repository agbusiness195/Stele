/**
 * @kervyx/discovery/marketplace — Trust-Gated Marketplace.
 *
 * Agent-to-agent discovery layer with trust-based access tiers,
 * premium placement, escrow, and transaction fees.
 *
 * @packageDocumentation
 */

// ─── Marketplace Types ───────────────────────────────────────────────────────

export interface MarketplaceListing {
  agentId: string;
  capabilities: string[];
  trustScore: number;
  tier: 'standard' | 'verified' | 'premium';
  pricing: { perQuery: number; perTransaction: number };
  listed: boolean;
  listedAt: number;
}

export interface MarketplaceConfig {
  minimumTrustScore: number; // minimum to list (default 0.3)
  premiumThreshold: number;  // trust score for premium tier (default 0.9)
  verifiedThreshold: number; // trust score for verified tier (default 0.7)
  escrowRequired: boolean;
  transactionFeeRate: number; // percentage (default 0.001 = 0.1%)
}

export interface MarketplaceQuery {
  capabilities?: string[];
  minimumTrust?: number;
  tier?: MarketplaceListing['tier'];
  maxResults?: number;
}

export interface MarketplaceTransaction {
  id: string;
  buyerAgentId: string;
  sellerAgentId: string;
  amount: number;
  fee: number;
  escrowHeld: boolean;
  status: 'pending' | 'completed' | 'disputed' | 'refunded';
  timestamp: number;
}

// ─── Marketplace Functions ───────────────────────────────────────────────────

/**
 * Create a marketplace configuration with sensible defaults.
 *
 * @param config - Optional partial configuration overrides.
 * @returns A complete MarketplaceConfig.
 */
export function createMarketplace(config?: Partial<MarketplaceConfig>): MarketplaceConfig {
  return {
    minimumTrustScore: config?.minimumTrustScore ?? 0.3,
    premiumThreshold: config?.premiumThreshold ?? 0.9,
    verifiedThreshold: config?.verifiedThreshold ?? 0.7,
    escrowRequired: config?.escrowRequired ?? true,
    transactionFeeRate: config?.transactionFeeRate ?? 0.001,
  };
}

/**
 * List an agent on the marketplace.
 *
 * Rejects agents whose trust score is below the minimum threshold.
 * Assigns a tier based on trust score thresholds in the config.
 *
 * @param config - The marketplace configuration.
 * @param params - Agent listing parameters.
 * @returns A MarketplaceListing on success, or an error object if rejected.
 */
export function listAgent(
  config: MarketplaceConfig,
  params: {
    agentId: string;
    capabilities: string[];
    trustScore: number;
    pricing: { perQuery: number; perTransaction: number };
  },
): MarketplaceListing | { error: string } {
  if (params.trustScore < config.minimumTrustScore) {
    return {
      error: `Trust score ${params.trustScore} is below minimum threshold ${config.minimumTrustScore}`,
    };
  }

  // Assign tier based on thresholds
  let tier: MarketplaceListing['tier'] = 'standard';
  if (params.trustScore >= config.premiumThreshold) {
    tier = 'premium';
  } else if (params.trustScore >= config.verifiedThreshold) {
    tier = 'verified';
  }

  return {
    agentId: params.agentId,
    capabilities: [...params.capabilities],
    trustScore: params.trustScore,
    tier,
    pricing: { ...params.pricing },
    listed: true,
    listedAt: Date.now(),
  };
}

/**
 * Search the marketplace for agents matching a query.
 *
 * Filters by capability match, minimum trust, and tier.
 * Results are sorted by trust score (descending), then tier (premium first).
 * Limited by maxResults (default 50).
 *
 * @param listings - The current marketplace listings.
 * @param query - The search query.
 * @returns An array of matching listings.
 */
export function searchMarketplace(
  listings: MarketplaceListing[],
  query: MarketplaceQuery,
): MarketplaceListing[] {
  let results = listings.filter((l) => l.listed);

  // Filter by capability match
  if (query.capabilities && query.capabilities.length > 0) {
    results = results.filter((l) =>
      query.capabilities!.some((cap) => l.capabilities.includes(cap)),
    );
  }

  // Filter by minimum trust
  if (query.minimumTrust !== undefined) {
    results = results.filter((l) => l.trustScore >= query.minimumTrust!);
  }

  // Filter by tier
  if (query.tier) {
    results = results.filter((l) => l.tier === query.tier);
  }

  // Sort by tier priority (premium > verified > standard), then trust score descending
  const tierPriority: Record<string, number> = { premium: 0, verified: 1, standard: 2 };
  results.sort((a, b) => {
    const tierDiff = tierPriority[a.tier]! - tierPriority[b.tier]!;
    if (tierDiff !== 0) return tierDiff;
    return b.trustScore - a.trustScore;
  });

  // Limit results
  const maxResults = query.maxResults ?? 50;
  return results.slice(0, maxResults);
}

/**
 * Create a marketplace transaction between a buyer and seller.
 *
 * Computes the fee based on the config's transactionFeeRate.
 * Escrow is held if configured.
 *
 * @param config - The marketplace configuration.
 * @param params - Transaction parameters.
 * @returns A MarketplaceTransaction in 'pending' status.
 */
export function createTransaction(
  config: MarketplaceConfig,
  params: {
    buyerAgentId: string;
    sellerAgentId: string;
    amount: number;
  },
): MarketplaceTransaction {
  const fee = params.amount * config.transactionFeeRate;
  const now = Date.now();

  return {
    id: `tx-${now}-${params.buyerAgentId}-${params.sellerAgentId}`,
    buyerAgentId: params.buyerAgentId,
    sellerAgentId: params.sellerAgentId,
    amount: params.amount,
    fee,
    escrowHeld: config.escrowRequired,
    status: 'pending',
    timestamp: now,
  };
}

/**
 * Complete a marketplace transaction.
 * Sets status to 'completed' and releases escrow.
 *
 * @param tx - The transaction to complete.
 * @returns A new transaction object with updated status.
 */
export function completeTransaction(tx: MarketplaceTransaction): MarketplaceTransaction {
  return {
    ...tx,
    status: 'completed',
    escrowHeld: false,
  };
}

/**
 * Dispute a marketplace transaction.
 * Sets status to 'disputed'.
 *
 * @param tx - The transaction to dispute.
 * @returns A new transaction object with disputed status.
 */
export function disputeTransaction(tx: MarketplaceTransaction): MarketplaceTransaction {
  return {
    ...tx,
    status: 'disputed',
  };
}
