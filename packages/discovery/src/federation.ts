/**
 * @kervyx/discovery/federation — Federated Discovery Protocol.
 *
 * DNS-like resolution with multiple independent resolvers.
 * Any entity can run a resolver. Trust the Ed25519 signature, not the resolver.
 *
 * @packageDocumentation
 */

// ─── Federated Resolver Types ────────────────────────────────────────────────

export interface FederatedResolver {
  resolverId: string;
  endpoint: string;
  publicKey: string; // Ed25519 public key for verification
  region?: string;
  lastSeen: number;
  reliability: number; // 0-1 based on uptime/accuracy
}

export interface FederationConfig {
  resolvers: FederatedResolver[];
  quorum: number; // minimum resolvers that must agree
  maxLatencyMs: number;
  trustSignatures: boolean; // if true, verify Ed25519 signatures regardless of resolver
}

export interface ResolutionResult {
  agentId: string;
  resolved: boolean;
  resolverResponses: Array<{
    resolverId: string;
    found: boolean;
    signatureValid: boolean;
    latencyMs: number;
  }>;
  quorumMet: boolean;
  consensusData: Record<string, unknown> | null;
}

// ─── Federation Functions ────────────────────────────────────────────────────

/**
 * Create a federation configuration from a set of resolver descriptors.
 *
 * @param params - Resolvers and optional quorum/latency settings.
 * @returns A fully initialized FederationConfig.
 */
export function createFederationConfig(params: {
  resolvers: Array<{ resolverId: string; endpoint: string; publicKey: string; region?: string }>;
  quorum?: number; // default: Math.ceil(resolvers.length / 2) + 1 (majority)
  maxLatencyMs?: number; // default: 5000
}): FederationConfig {
  const now = Date.now();
  const resolvers: FederatedResolver[] = params.resolvers.map((r) => ({
    resolverId: r.resolverId,
    endpoint: r.endpoint,
    publicKey: r.publicKey,
    region: r.region,
    lastSeen: now,
    reliability: 1.0, // Start with perfect reliability
  }));

  const quorum = params.quorum ?? Math.ceil(resolvers.length / 2) + 1;

  return {
    resolvers,
    quorum,
    maxLatencyMs: params.maxLatencyMs ?? 5000,
    trustSignatures: true,
  };
}

/**
 * Add a resolver to an existing federation configuration.
 * Returns a new config (immutable).
 *
 * @param config - The existing federation config.
 * @param resolver - The resolver to add.
 * @returns A new FederationConfig with the resolver added.
 */
export function addResolver(config: FederationConfig, resolver: FederatedResolver): FederationConfig {
  // Avoid duplicates by resolverId
  const existing = config.resolvers.find((r) => r.resolverId === resolver.resolverId);
  if (existing) {
    return {
      ...config,
      resolvers: config.resolvers.map((r) =>
        r.resolverId === resolver.resolverId ? resolver : r,
      ),
    };
  }

  return {
    ...config,
    resolvers: [...config.resolvers, resolver],
  };
}

/**
 * Remove a resolver from a federation configuration by ID.
 * Returns a new config (immutable).
 *
 * @param config - The existing federation config.
 * @param resolverId - The ID of the resolver to remove.
 * @returns A new FederationConfig without the specified resolver.
 */
export function removeResolver(config: FederationConfig, resolverId: string): FederationConfig {
  return {
    ...config,
    resolvers: config.resolvers.filter((r) => r.resolverId !== resolverId),
  };
}

/**
 * Resolve an agent using pre-fetched resolver results.
 *
 * This is synchronous — it takes pre-fetched resolver results (we don't do actual HTTP calls).
 * Quorum is met when the number of (found && signatureValid) responses >= config.quorum.
 * consensusData is the data from the first valid resolver response (if quorum met).
 *
 * @param config - The federation config.
 * @param agentId - The agent to resolve.
 * @param resolverResults - Pre-fetched results from each resolver.
 * @returns A ResolutionResult indicating whether the agent was resolved.
 */
export function resolveAgent(
  config: FederationConfig,
  agentId: string,
  resolverResults: Array<{
    resolverId: string;
    found: boolean;
    signatureValid: boolean;
    latencyMs: number;
    data?: Record<string, unknown>;
  }>,
): ResolutionResult {
  const responses = resolverResults.map((r) => ({
    resolverId: r.resolverId,
    found: r.found,
    signatureValid: r.signatureValid,
    latencyMs: r.latencyMs,
  }));

  // Count valid responses: found AND (signatureValid OR signatures not trusted)
  const validResponses = resolverResults.filter((r) => {
    if (!r.found) return false;
    if (config.trustSignatures) return r.signatureValid;
    return true;
  });

  const quorumMet = validResponses.length >= config.quorum;

  // consensusData is the data from the first valid resolver response (if quorum met)
  let consensusData: Record<string, unknown> | null = null;
  if (quorumMet) {
    const firstValid = resolverResults.find((r) => {
      if (!r.found) return false;
      if (config.trustSignatures) return r.signatureValid;
      return true;
    });
    consensusData = firstValid?.data ?? null;
  }

  return {
    agentId,
    resolved: quorumMet,
    resolverResponses: responses,
    quorumMet,
    consensusData,
  };
}

/**
 * Select the top N resolvers by reliability score, preferring diverse regions.
 *
 * The algorithm sorts resolvers by reliability (descending) and then ensures
 * region diversity by preferring resolvers from unique regions when possible.
 *
 * @param config - The federation config.
 * @param count - The number of resolvers to select.
 * @returns An array of the selected resolvers.
 */
export function selectOptimalResolvers(config: FederationConfig, count: number): FederatedResolver[] {
  if (count <= 0) return [];
  if (count >= config.resolvers.length) {
    return [...config.resolvers].sort((a, b) => b.reliability - a.reliability);
  }

  // Sort by reliability descending
  const sorted = [...config.resolvers].sort((a, b) => b.reliability - a.reliability);

  const selected: FederatedResolver[] = [];
  const usedRegions = new Set<string>();

  // First pass: pick one resolver per unique region (highest reliability from each)
  for (const resolver of sorted) {
    if (selected.length >= count) break;
    const region = resolver.region ?? '__default__';
    if (!usedRegions.has(region)) {
      selected.push(resolver);
      usedRegions.add(region);
    }
  }

  // Second pass: fill remaining slots with highest reliability regardless of region
  if (selected.length < count) {
    const selectedIds = new Set(selected.map((r) => r.resolverId));
    for (const resolver of sorted) {
      if (selected.length >= count) break;
      if (!selectedIds.has(resolver.resolverId)) {
        selected.push(resolver);
        selectedIds.add(resolver.resolverId);
      }
    }
  }

  return selected;
}
