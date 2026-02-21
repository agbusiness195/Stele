import { sha256Object, signString, toHex, verify, fromHex } from '@grith/crypto';
import { DocumentedGrithError as GrithError, DocumentedErrorCode as GrithErrorCode } from '@grith/types';

export type {
  ExternalAttestation,
  AttestationReconciliation,
  Discrepancy,
  ReceiptSummary,
  AttestationChainLink,
  ChainVerificationResult,
  AgentAction,
  AttestationCoverageResult,
} from './types';

import type {
  ExternalAttestation,
  AttestationReconciliation,
  Discrepancy,
  ReceiptSummary,
  AttestationChainLink,
  ChainVerificationResult,
  AgentAction,
  AttestationCoverageResult,
} from './types';

/** Default timestamp difference threshold (in ms) for minor discrepancy. */
const TIMESTAMP_THRESHOLD_MS = 5000;

/**
 * Create an ExternalAttestation with a deterministic ID derived from its content.
 * Validates inputs: non-empty agentId, counterpartyId, endpoint, and valid timestamp.
 */
export function createAttestation(
  agentId: string,
  counterpartyId: string,
  endpoint: string,
  inputHash: string,
  outputHash: string,
  interactionHash: string,
  timestamp: number,
): ExternalAttestation {
  if (!agentId || typeof agentId !== 'string') {
    throw new GrithError(GrithErrorCode.ATTESTATION_INVALID, 'agentId must be a non-empty string', { hint: 'Provide a non-empty agentId when creating an attestation.' });
  }
  if (!counterpartyId || typeof counterpartyId !== 'string') {
    throw new GrithError(GrithErrorCode.ATTESTATION_INVALID, 'counterpartyId must be a non-empty string', { hint: 'Provide a non-empty counterpartyId when creating an attestation.' });
  }
  if (!endpoint || typeof endpoint !== 'string') {
    throw new GrithError(GrithErrorCode.ATTESTATION_INVALID, 'endpoint must be a non-empty string', { hint: 'Provide a non-empty endpoint string when creating an attestation.' });
  }
  if (typeof timestamp !== 'number' || timestamp < 0) {
    throw new GrithError(GrithErrorCode.ATTESTATION_INVALID, 'timestamp must be a non-negative number', { hint: 'Provide a non-negative numeric timestamp when creating an attestation.' });
  }

  const content = {
    agentId,
    counterpartyId,
    endpoint,
    inputHash,
    outputHash,
    interactionHash,
    timestamp,
  };
  const id = sha256Object(content);

  return {
    id,
    agentId,
    counterpartyId,
    interactionHash,
    counterpartySignature: '',
    timestamp,
    endpoint,
    inputHash,
    outputHash,
  };
}

/**
 * Check if an attestation has been signed (counterpartySignature is non-empty).
 */
export function isSigned(attestation: ExternalAttestation): boolean {
  return attestation.counterpartySignature.length > 0;
}

/**
 * Sign an attestation with a private key. Returns a copy with the
 * counterpartySignature field set to the hex-encoded Ed25519 signature.
 */
export async function signAttestation(
  attestation: ExternalAttestation,
  privateKey: Uint8Array,
): Promise<ExternalAttestation> {
  const payload = sha256Object({
    id: attestation.id,
    agentId: attestation.agentId,
    counterpartyId: attestation.counterpartyId,
    interactionHash: attestation.interactionHash,
    timestamp: attestation.timestamp,
    endpoint: attestation.endpoint,
    inputHash: attestation.inputHash,
    outputHash: attestation.outputHash,
  });
  const signature = await signString(payload, privateKey);

  return {
    ...attestation,
    counterpartySignature: toHex(signature),
  };
}

/**
 * Verify an attestation's counterpartySignature is a valid Ed25519 signature
 * against the attestation's content, using the provided public key.
 * Returns true if valid, false otherwise.
 */
export async function verifyAttestation(
  attestation: ExternalAttestation,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (!attestation.counterpartySignature || attestation.counterpartySignature.length === 0) {
    return false;
  }

  const payload = sha256Object({
    id: attestation.id,
    agentId: attestation.agentId,
    counterpartyId: attestation.counterpartyId,
    interactionHash: attestation.interactionHash,
    timestamp: attestation.timestamp,
    endpoint: attestation.endpoint,
    inputHash: attestation.inputHash,
    outputHash: attestation.outputHash,
  });

  try {
    const signatureBytes = fromHex(attestation.counterpartySignature);
    const messageBytes = new TextEncoder().encode(payload);
    return await verify(messageBytes, signatureBytes, publicKey);
  } catch {
    return false;
  }
}

/**
 * Reconcile an agent receipt against a counterparty attestation.
 * Compares interactionHash, inputHash, outputHash, endpoint, and timestamp fields.
 */
export function reconcile(
  receipt: ReceiptSummary,
  attestation: ExternalAttestation,
): AttestationReconciliation {
  const discrepancies = getDiscrepancies(receipt, attestation);

  return {
    agentReceiptId: receipt.id,
    attestationId: attestation.id,
    match: discrepancies.length === 0,
    discrepancies,
  };
}

/**
 * Compare interactionHash, inputHash, outputHash, endpoint, and timestamp
 * between a receipt and an attestation, returning an array of discrepancies found.
 *
 * Severity levels:
 *   - interactionHash mismatch: critical
 *   - inputHash mismatch: major
 *   - outputHash mismatch: major
 *   - endpoint mismatch: minor
 *   - timestamp difference > threshold: minor
 */
export function getDiscrepancies(
  receipt: ReceiptSummary,
  attestation: ExternalAttestation,
): Discrepancy[] {
  const discrepancies: Discrepancy[] = [];

  if (receipt.interactionHash !== attestation.interactionHash) {
    discrepancies.push({
      field: 'interactionHash',
      agentClaimed: receipt.interactionHash,
      counterpartyClaimed: attestation.interactionHash,
      severity: 'critical',
    });
  }

  if (receipt.inputHash !== attestation.inputHash) {
    discrepancies.push({
      field: 'inputHash',
      agentClaimed: receipt.inputHash,
      counterpartyClaimed: attestation.inputHash,
      severity: 'major',
    });
  }

  if (receipt.outputHash !== attestation.outputHash) {
    discrepancies.push({
      field: 'outputHash',
      agentClaimed: receipt.outputHash,
      counterpartyClaimed: attestation.outputHash,
      severity: 'major',
    });
  }

  if (receipt.endpoint !== attestation.endpoint) {
    discrepancies.push({
      field: 'endpoint',
      agentClaimed: receipt.endpoint,
      counterpartyClaimed: attestation.endpoint,
      severity: 'minor',
    });
  }

  if (Math.abs(receipt.timestamp - attestation.timestamp) > TIMESTAMP_THRESHOLD_MS) {
    discrepancies.push({
      field: 'timestamp',
      agentClaimed: String(receipt.timestamp),
      counterpartyClaimed: String(attestation.timestamp),
      severity: 'minor',
    });
  }

  return discrepancies;
}

/**
 * Verify a chain of attestations where each attester attests the previous one.
 *
 * The chain is ordered from the first attestation to the last. Each link
 * contains an attestation and the public key of the attester who signed it.
 * Verification proceeds sequentially: if any link fails verification,
 * the chain is considered broken at that link.
 *
 * Additionally checks that the chain is temporally ordered (each attestation's
 * timestamp is >= the previous one's timestamp).
 *
 * @param chain - Array of attestation chain links in order
 * @returns ChainVerificationResult with the verification outcome
 */
export async function attestationChainVerify(
  chain: AttestationChainLink[],
): Promise<ChainVerificationResult> {
  if (chain.length === 0) {
    return {
      valid: true,
      verifiedLinks: 0,
      totalLinks: 0,
    };
  }

  let verifiedLinks = 0;

  for (let i = 0; i < chain.length; i++) {
    const link = chain[i]!;

    // Check that the attestation is signed
    if (!isSigned(link.attestation)) {
      return {
        valid: false,
        verifiedLinks,
        totalLinks: chain.length,
        brokenAt: i,
        reason: `Link ${i}: attestation is not signed`,
      };
    }

    // Verify the signature
    const signatureValid = await verifyAttestation(link.attestation, link.attesterPublicKey);
    if (!signatureValid) {
      return {
        valid: false,
        verifiedLinks,
        totalLinks: chain.length,
        brokenAt: i,
        reason: `Link ${i}: signature verification failed`,
      };
    }

    // Check temporal ordering (each attestation should be at or after the previous)
    if (i > 0) {
      const prevTimestamp = chain[i - 1]!.attestation.timestamp;
      if (link.attestation.timestamp < prevTimestamp) {
        return {
          valid: false,
          verifiedLinks,
          totalLinks: chain.length,
          brokenAt: i,
          reason: `Link ${i}: timestamp ${link.attestation.timestamp} is before previous link's timestamp ${prevTimestamp}`,
        };
      }
    }

    // Check chain continuity: the attester of the current link should be
    // the counterparty of the previous link's attestation (if applicable)
    if (i > 0) {
      const prevAttestation = chain[i - 1]!.attestation;
      if (link.attestation.agentId !== prevAttestation.counterpartyId) {
        return {
          valid: false,
          verifiedLinks,
          totalLinks: chain.length,
          brokenAt: i,
          reason: `Link ${i}: agentId "${link.attestation.agentId}" does not match previous link's counterpartyId "${prevAttestation.counterpartyId}"`,
        };
      }
    }

    verifiedLinks++;
  }

  return {
    valid: true,
    verifiedLinks,
    totalLinks: chain.length,
  };
}

/**
 * Compute what percentage of an agent's actions are covered by attestations.
 *
 * An action is considered "covered" if there exists an attestation where:
 * - The attestation's agentId matches the action's agentId
 * - The attestation's timestamp is within the given time window of the action's timestamp
 *
 * @param actions - Array of agent actions to check coverage for
 * @param attestations - Array of attestations that may cover the actions
 * @param timeWindowMs - Maximum time difference (in ms) for an attestation to cover an action (default 5000)
 * @returns AttestationCoverageResult with coverage statistics
 */
export function computeAttestationCoverage(
  actions: AgentAction[],
  attestations: ExternalAttestation[],
  timeWindowMs: number = 5000,
): AttestationCoverageResult {
  if (timeWindowMs < 0) {
    throw new GrithError(GrithErrorCode.ATTESTATION_INVALID, 'timeWindowMs must be non-negative', { hint: 'Provide a non-negative value for timeWindowMs.' });
  }

  if (actions.length === 0) {
    return {
      totalActions: 0,
      coveredActions: 0,
      coveragePercentage: 100,
      uncoveredActionIds: [],
    };
  }

  const uncoveredActionIds: string[] = [];
  let coveredCount = 0;

  for (const action of actions) {
    const isCovered = attestations.some(att =>
      att.agentId === action.agentId &&
      Math.abs(att.timestamp - action.timestamp) <= timeWindowMs,
    );

    if (isCovered) {
      coveredCount++;
    } else {
      uncoveredActionIds.push(action.id);
    }
  }

  return {
    totalActions: actions.length,
    coveredActions: coveredCount,
    coveragePercentage: (coveredCount / actions.length) * 100,
    uncoveredActionIds,
  };
}

// ---------------------------------------------------------------------------
// Trust Entanglement
// ---------------------------------------------------------------------------

/**
 * A cryptographically linked trust relationship between two agents.
 * Verifying one agent partially verifies its entangled partners.
 */
export interface EntanglementLink {
  sourceAgentId: string;
  targetAgentId: string;
  entanglementStrength: number; // 0-1, how strongly linked
  mutualObligations: string[];  // shared covenant commitments
  conditionalDependencies: string[]; // if source fails, what happens to target
  createdAt: number;
  linkHash: string; // hash binding both agents
}

/**
 * A network of entangled trust relationships enabling sublinear verification cost.
 */
export interface EntanglementNetwork {
  links: EntanglementLink[];
  agents: Set<string>;
  verificationCoverage: number; // 0-1, fraction of network verified by verifying subset
  sublinearCostRatio: number; // actual_cost / full_cost
}

/**
 * Create an entanglement link between two agents.
 *
 * The link is cryptographically bound via a hash of the sorted agent IDs,
 * strength, and mutual obligations. This produces a deterministic identifier
 * for the relationship regardless of which agent is considered source or target.
 *
 * @param params - Entanglement parameters including agent IDs, strength, and obligations.
 * @returns An EntanglementLink with a computed linkHash.
 *
 * @example
 * ```typescript
 * const link = createEntanglement({
 *   sourceAgentId: 'agent-a',
 *   targetAgentId: 'agent-b',
 *   strength: 0.8,
 *   mutualObligations: ['data-privacy', 'response-time'],
 * });
 * ```
 */
export function createEntanglement(params: {
  sourceAgentId: string;
  targetAgentId: string;
  strength: number;
  mutualObligations?: string[];
  conditionalDependencies?: string[];
}): EntanglementLink {
  if (!params.sourceAgentId || typeof params.sourceAgentId !== 'string') {
    throw new GrithError(GrithErrorCode.ATTESTATION_INVALID, 'sourceAgentId must be a non-empty string', { hint: 'Provide a non-empty sourceAgentId when creating an entanglement link.' });
  }
  if (!params.targetAgentId || typeof params.targetAgentId !== 'string') {
    throw new GrithError(GrithErrorCode.ATTESTATION_INVALID, 'targetAgentId must be a non-empty string', { hint: 'Provide a non-empty targetAgentId when creating an entanglement link.' });
  }
  if (typeof params.strength !== 'number' || params.strength < 0 || params.strength > 1) {
    throw new GrithError(GrithErrorCode.ATTESTATION_INVALID, 'strength must be a number between 0 and 1', { hint: 'Set the entanglement strength to a number in the range [0, 1].' });
  }

  const mutualObligations = params.mutualObligations ?? [];
  const conditionalDependencies = params.conditionalDependencies ?? [];
  const createdAt = Date.now();

  // linkHash = hash of sorted(sourceAgentId, targetAgentId) + strength + obligations
  const sortedAgents = [params.sourceAgentId, params.targetAgentId].sort();
  const linkHash = sha256Object({
    agents: sortedAgents,
    strength: params.strength,
    obligations: mutualObligations,
  });

  return {
    sourceAgentId: params.sourceAgentId,
    targetAgentId: params.targetAgentId,
    entanglementStrength: params.strength,
    mutualObligations,
    conditionalDependencies,
    createdAt,
    linkHash,
  };
}

/**
 * Build an entanglement network from a collection of links.
 *
 * Collects all unique agents, computes the verification coverage based on
 * network-effect strength propagation, and calculates the sublinear cost ratio.
 *
 * The verification coverage formula accounts for transitive trust:
 *   coverage = 1 - (1 - avgStrength)^avgLinksPerAgent
 *
 * The sublinear cost ratio is: sqrt(agents.size) / agents.size
 *
 * @param links - Array of entanglement links to form the network.
 * @returns An EntanglementNetwork with computed coverage and cost metrics.
 *
 * @example
 * ```typescript
 * const network = buildEntanglementNetwork([link1, link2, link3]);
 * console.log(network.verificationCoverage); // e.g. 0.75
 * console.log(network.sublinearCostRatio);   // e.g. 0.577 for 3 agents
 * ```
 */
export function buildEntanglementNetwork(links: EntanglementLink[]): EntanglementNetwork {
  const agents = new Set<string>();

  for (const link of links) {
    agents.add(link.sourceAgentId);
    agents.add(link.targetAgentId);
  }

  if (agents.size === 0) {
    return {
      links: [...links],
      agents,
      verificationCoverage: 0,
      sublinearCostRatio: 1,
    };
  }

  // Compute average strength across all links
  const avgStrength = links.length > 0
    ? links.reduce((sum, l) => sum + l.entanglementStrength, 0) / links.length
    : 0;

  // Compute average links per agent
  const avgLinksPerAgent = links.length > 0
    ? (links.length * 2) / agents.size // each link connects 2 agents
    : 0;

  // verificationCoverage = 1 - (1 - avgStrength)^avgLinksPerAgent (network effect)
  const verificationCoverage = 1 - Math.pow(1 - avgStrength, avgLinksPerAgent);

  // sublinearCostRatio = sqrt(agents.size) / agents.size
  const sublinearCostRatio = Math.sqrt(agents.size) / agents.size;

  return {
    links: [...links],
    agents,
    verificationCoverage,
    sublinearCostRatio,
  };
}

/**
 * Verify an agent and determine which other agents are transitively verified
 * through entanglement links.
 *
 * Walks the entanglement graph from the verified agent using breadth-first search.
 * Confidence decays multiplicatively with each hop (multiplied by link strength).
 * Only agents with confidence > 0.1 are considered transitively verified.
 *
 * @param network - The entanglement network to search.
 * @param verifiedAgentId - The agent that has been directly verified.
 * @returns Verification results including transitively verified agents and cost savings.
 *
 * @example
 * ```typescript
 * const result = verifyEntangled(network, 'agent-a');
 * console.log(result.transitivelyVerified); // ['agent-b', 'agent-c']
 * console.log(result.costSavings);          // 0.66
 * ```
 */
export function verifyEntangled(network: EntanglementNetwork, verifiedAgentId: string): {
  directlyVerified: string;
  transitivelyVerified: string[];
  transitiveConfidence: Record<string, number>;
  costSavings: number;
} {
  const transitiveConfidence: Record<string, number> = {};
  const visited = new Set<string>();
  visited.add(verifiedAgentId);

  // Build adjacency list from links
  const adjacency = new Map<string, Array<{ agentId: string; strength: number }>>();
  for (const link of network.links) {
    if (!adjacency.has(link.sourceAgentId)) {
      adjacency.set(link.sourceAgentId, []);
    }
    if (!adjacency.has(link.targetAgentId)) {
      adjacency.set(link.targetAgentId, []);
    }
    adjacency.get(link.sourceAgentId)!.push({
      agentId: link.targetAgentId,
      strength: link.entanglementStrength,
    });
    adjacency.get(link.targetAgentId)!.push({
      agentId: link.sourceAgentId,
      strength: link.entanglementStrength,
    });
  }

  // BFS with confidence decay
  const queue: Array<{ agentId: string; confidence: number }> = [];

  // Seed with directly connected agents
  const directNeighbors = adjacency.get(verifiedAgentId) ?? [];
  for (const neighbor of directNeighbors) {
    if (!visited.has(neighbor.agentId)) {
      const confidence = neighbor.strength;
      if (confidence > 0.1) {
        transitiveConfidence[neighbor.agentId] = Math.max(
          transitiveConfidence[neighbor.agentId] ?? 0,
          confidence,
        );
        queue.push({ agentId: neighbor.agentId, confidence });
        visited.add(neighbor.agentId);
      }
    }
  }

  // Continue BFS
  while (queue.length > 0) {
    const current = queue.shift()!;
    const neighbors = adjacency.get(current.agentId) ?? [];

    for (const neighbor of neighbors) {
      if (!visited.has(neighbor.agentId)) {
        const confidence = current.confidence * neighbor.strength;
        if (confidence > 0.1) {
          transitiveConfidence[neighbor.agentId] = Math.max(
            transitiveConfidence[neighbor.agentId] ?? 0,
            confidence,
          );
          queue.push({ agentId: neighbor.agentId, confidence });
          visited.add(neighbor.agentId);
        }
      }
    }
  }

  const transitivelyVerified = Object.keys(transitiveConfidence);

  // costSavings = (transitivelyVerified.length) / (network.agents.size)
  const costSavings = network.agents.size > 0
    ? transitivelyVerified.length / network.agents.size
    : 0;

  return {
    directlyVerified: verifiedAgentId,
    transitivelyVerified,
    transitiveConfidence,
    costSavings,
  };
}

/**
 * Assess the conditional risk of an agent failure cascading through the
 * entanglement network.
 *
 * Finds all agents with conditional dependencies on the failed agent and
 * computes the cascade risk as the ratio of affected link strengths to
 * total network strength.
 *
 * @param network - The entanglement network to assess.
 * @param failedAgentId - The agent that has failed.
 * @returns Risk assessment with affected agents, cascade risk, and recommendations.
 *
 * @example
 * ```typescript
 * const risk = assessConditionalRisk(network, 'agent-a');
 * console.log(risk.cascadeRisk);      // 0.4
 * console.log(risk.affectedAgents);   // ['agent-b']
 * console.log(risk.recommendations);  // ['Re-verify agent-b...']
 * ```
 */
export function assessConditionalRisk(network: EntanglementNetwork, failedAgentId: string): {
  affectedAgents: string[];
  cascadeRisk: number;
  recommendations: string[];
} {
  const affectedAgents: string[] = [];
  let affectedStrength = 0;
  let totalStrength = 0;

  for (const link of network.links) {
    totalStrength += link.entanglementStrength;

    // Check if this link involves the failed agent and has conditional dependencies
    const isSourceFailed = link.sourceAgentId === failedAgentId;
    const isTargetFailed = link.targetAgentId === failedAgentId;

    if ((isSourceFailed || isTargetFailed) && link.conditionalDependencies.length > 0) {
      const affectedAgent = isSourceFailed ? link.targetAgentId : link.sourceAgentId;
      if (!affectedAgents.includes(affectedAgent)) {
        affectedAgents.push(affectedAgent);
      }
      affectedStrength += link.entanglementStrength;
    }
  }

  const cascadeRisk = totalStrength > 0 ? affectedStrength / totalStrength : 0;

  const recommendations: string[] = [];
  if (affectedAgents.length === 0) {
    recommendations.push('No conditional dependencies found. Network impact is minimal.');
  } else {
    for (const agent of affectedAgents) {
      recommendations.push(
        `Re-verify ${agent} independently due to conditional dependency on failed agent ${failedAgentId}.`,
      );
    }
    if (cascadeRisk > 0.5) {
      recommendations.push(
        'High cascade risk detected. Consider isolating affected agents and performing full network re-verification.',
      );
    }
  }

  return {
    affectedAgents,
    cascadeRisk,
    recommendations,
  };
}
