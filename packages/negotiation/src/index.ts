import { generateId } from '@stele/crypto';
import { SteleError, SteleErrorCode } from '@stele/types';

export type {
  NegotiationSession,
  Proposal,
  NegotiationPolicy,
  UtilityFunction,
  Outcome,
  NashBargainingSolution,
  ParetoOutcome,
} from './types.js';

import type {
  NegotiationSession,
  Proposal,
  NegotiationPolicy,
  UtilityFunction,
  Outcome,
  NashBargainingSolution,
  ParetoOutcome,
} from './types.js';

/**
 * Validate a proposal has non-empty constraints and valid format.
 */
function validateProposal(proposal: Proposal): void {
  if (!proposal.from || typeof proposal.from !== 'string') {
    throw new Error('Proposal must have a non-empty "from" field');
  }
  if (!Array.isArray(proposal.constraints)) {
    throw new Error('Proposal constraints must be an array');
  }
  if (!Array.isArray(proposal.requirements)) {
    throw new Error('Proposal requirements must be an array');
  }
  if (typeof proposal.timestamp !== 'number' || proposal.timestamp < 0) {
    throw new Error('Proposal timestamp must be a non-negative number');
  }
}

/**
 * Check that a session is not in a terminal state (agreed or failed).
 */
function assertNotTerminal(session: NegotiationSession): void {
  if (session.status === 'agreed') {
    throw new Error('Cannot modify an agreed session');
  }
  if (session.status === 'failed') {
    throw new Error('Cannot modify a failed session');
  }
}

/**
 * Parse a constraint into its type prefix and resource pattern.
 * e.g. "deny:exfiltrate-data" -> { type: 'deny', resource: 'exfiltrate-data' }
 */
function parseConstraint(constraint: string): { type: string; resource: string } {
  const colonIdx = constraint.indexOf(':');
  if (colonIdx === -1) {
    return { type: 'unknown', resource: constraint };
  }
  return {
    type: constraint.slice(0, colonIdx),
    resource: constraint.slice(colonIdx + 1),
  };
}

/**
 * Initiate a new negotiation session between two parties.
 *
 * Creates a NegotiationSession with status 'proposing' and an initial proposal
 * from the initiator containing their required and preferred constraints.
 */
export function initiate(
  initiatorId: string,
  responderId: string,
  policy: NegotiationPolicy,
): NegotiationSession {
  if (!initiatorId || typeof initiatorId !== 'string') {
    throw new Error('initiatorId must be a non-empty string');
  }
  if (!responderId || typeof responderId !== 'string') {
    throw new Error('responderId must be a non-empty string');
  }
  if (policy.maxRounds < 1) {
    throw new Error('maxRounds must be at least 1');
  }
  if (policy.timeoutMs < 0) {
    throw new Error('timeoutMs must be non-negative');
  }

  const now = Date.now();
  const initialProposal: Proposal = {
    from: initiatorId,
    constraints: [...policy.requiredConstraints, ...policy.preferredConstraints],
    requirements: [...policy.requiredConstraints],
    timestamp: now,
  };

  return {
    id: generateId(),
    initiator: initiatorId,
    responder: responderId,
    status: 'proposing',
    proposals: [initialProposal],
    timeoutMs: policy.timeoutMs,
    createdAt: now,
    maxRounds: policy.maxRounds,
  };
}

/**
 * Add a proposal to an existing negotiation session.
 *
 * Appends the proposal to the session's proposals array and returns the
 * updated session. Does not change the session status.
 */
export function propose(
  session: NegotiationSession,
  proposal: Proposal,
): NegotiationSession {
  assertNotTerminal(session);
  validateProposal(proposal);

  return {
    ...session,
    proposals: [...session.proposals, proposal],
  };
}

/**
 * Add a counter-proposal to the session.
 *
 * Sets the status to 'countering' and appends the counter-proposal. Throws
 * an error if the maximum number of rounds has been exceeded.
 */
export function counter(
  session: NegotiationSession,
  counterProposal: Proposal,
): NegotiationSession {
  assertNotTerminal(session);
  validateProposal(counterProposal);

  if (session.proposals.length >= session.maxRounds) {
    throw new Error(
      `Maximum rounds (${session.maxRounds}) exceeded. Cannot add counter-proposal.`,
    );
  }

  return {
    ...session,
    status: 'countering',
    proposals: [...session.proposals, counterProposal],
  };
}

/**
 * Finalize a negotiation as agreed.
 *
 * Sets the status to 'agreed' and computes the resulting constraints using
 * constraint intersection that respects deny-wins semantics:
 * - All 'deny:' constraints from either proposal are included (deny-wins)
 * - All 'require:' constraints present in both proposals are included
 * - Other constraints are included only if present in both proposals (intersection)
 */
export function agree(session: NegotiationSession): NegotiationSession {
  const proposals = session.proposals;
  let resultingConstraints: string[] = [];

  if (proposals.length >= 2) {
    const lastProposal = proposals[proposals.length - 1]!;
    const secondLastProposal = proposals[proposals.length - 2]!;

    const lastSet = new Set(lastProposal.constraints);
    const secondLastSet = new Set(secondLastProposal.constraints);

    // Collect all deny constraints from both sides (deny-wins semantics)
    const denyConstraints = new Set<string>();
    for (const c of lastProposal.constraints) {
      if (c.startsWith('deny:')) {
        denyConstraints.add(c);
      }
    }
    for (const c of secondLastProposal.constraints) {
      if (c.startsWith('deny:')) {
        denyConstraints.add(c);
      }
    }

    // Intersection of non-deny constraints
    const intersection: string[] = [];
    for (const c of secondLastProposal.constraints) {
      if (!c.startsWith('deny:') && lastSet.has(c)) {
        intersection.push(c);
      }
    }

    // Merge: deny-wins + intersection
    resultingConstraints = [...denyConstraints, ...intersection];
  } else if (proposals.length === 1) {
    resultingConstraints = [...proposals[0]!.constraints];
  }

  return {
    ...session,
    status: 'agreed',
    resultingConstraints,
  };
}

/**
 * Evaluate a proposal against a negotiation policy.
 *
 * Returns:
 * - 'accept' if all required constraints are satisfied and no dealbreakers are found
 * - 'reject' if any dealbreaker constraint is present in the proposal
 * - 'counter' if some required constraints are missing but no dealbreakers
 *
 * Checks each constraint against the policy with proper matching:
 * - Dealbreakers are checked by both exact match and resource pattern matching
 * - Required constraints are checked with type-aware matching
 */
export function evaluate(
  proposal: Proposal,
  policy: NegotiationPolicy,
): 'accept' | 'reject' | 'counter' {
  const constraintSet = new Set(proposal.constraints);

  // Parse proposal constraints for pattern matching
  const proposalParsed = proposal.constraints.map(parseConstraint);

  // Check for dealbreakers: exact match or resource pattern match
  for (const dealbreaker of policy.dealbreakers) {
    // Exact match
    if (constraintSet.has(dealbreaker)) {
      return 'reject';
    }
    // Pattern match: check if any proposal constraint's resource matches the dealbreaker's resource
    const dbParsed = parseConstraint(dealbreaker);
    for (const pc of proposalParsed) {
      if (pc.type === dbParsed.type && pc.resource === dbParsed.resource) {
        return 'reject';
      }
    }
  }

  // Check if all required constraints are present (exact or type-compatible match)
  let allRequiredPresent = true;
  for (const required of policy.requiredConstraints) {
    if (constraintSet.has(required)) {
      continue;
    }
    // Try type-aware matching
    const reqParsed = parseConstraint(required);
    const found = proposalParsed.some(
      pc => pc.type === reqParsed.type && pc.resource === reqParsed.resource,
    );
    if (!found) {
      allRequiredPresent = false;
      break;
    }
  }

  if (allRequiredPresent) {
    return 'accept';
  }

  return 'counter';
}

/**
 * Check if a negotiation session has expired.
 *
 * Returns true if the current time exceeds the session's createdAt + timeoutMs.
 */
export function isExpired(session: NegotiationSession): boolean {
  return Date.now() > session.createdAt + session.timeoutMs;
}

/**
 * Mark a negotiation session as failed, storing the failure reason.
 *
 * Returns a copy of the session with status set to 'failed' and failureReason populated.
 */
export function fail(
  session: NegotiationSession,
  reason?: string,
): NegotiationSession {
  return {
    ...session,
    status: 'failed',
    failureReason: reason,
  };
}

/**
 * Return the number of rounds (proposals) that have occurred in the session.
 */
export function roundCount(session: NegotiationSession): number {
  return session.proposals.length;
}

/**
 * Compute the Nash Bargaining Solution between two parties.
 *
 * The Nash Bargaining Solution maximizes the product:
 *   (utilityA(outcome) - disagreementA) * (utilityB(outcome) - disagreementB)
 *
 * over all feasible outcomes, where disagreementA and disagreementB are
 * the utilities each party receives if negotiation fails.
 *
 * Only outcomes where both parties receive utility above their disagreement
 * value are considered (individual rationality constraint).
 *
 * @param outcomes - Array of possible outcomes to evaluate
 * @param utilityA - Utility function for party A (includes disagreement value)
 * @param utilityB - Utility function for party B (includes disagreement value)
 * @returns NashBargainingSolution or null if no individually rational outcome exists
 */
export function computeNashBargainingSolution(
  outcomes: Outcome[],
  utilityA: UtilityFunction,
  utilityB: UtilityFunction,
): NashBargainingSolution | null {
  if (outcomes.length === 0) {
    return null;
  }

  let bestSolution: NashBargainingSolution | null = null;
  let bestProduct = -Infinity;

  for (const outcome of outcomes) {
    const uA = utilityA.evaluate(outcome);
    const uB = utilityB.evaluate(outcome);

    // Individual rationality: both parties must be at least as well off
    // as their disagreement point
    const surplusA = uA - utilityA.disagreementValue;
    const surplusB = uB - utilityB.disagreementValue;

    if (surplusA < 0 || surplusB < 0) {
      continue;
    }

    const nashProduct = surplusA * surplusB;

    if (nashProduct > bestProduct) {
      bestProduct = nashProduct;
      bestSolution = {
        outcome,
        utilityA: uA,
        utilityB: uB,
        nashProduct,
      };
    }
  }

  return bestSolution;
}

/**
 * Compute the Pareto frontier from a set of possible outcomes.
 *
 * An outcome is Pareto-optimal if no other outcome exists that makes
 * at least one party better off without making any party worse off.
 *
 * @param outcomes - Array of possible outcomes
 * @param utilityFunctions - Array of utility functions (one per party)
 * @returns Array of ParetoOutcome objects, with `dominated` flag set appropriately
 */
export function paretoFrontier(
  outcomes: Outcome[],
  utilityFunctions: UtilityFunction[],
): ParetoOutcome[] {
  if (outcomes.length === 0 || utilityFunctions.length === 0) {
    return [];
  }

  // Compute utilities for all outcomes
  const evaluated: ParetoOutcome[] = outcomes.map(outcome => ({
    outcome,
    utilities: utilityFunctions.map(uf => uf.evaluate(outcome)),
    dominated: false,
  }));

  // Mark dominated outcomes
  for (let i = 0; i < evaluated.length; i++) {
    if (evaluated[i]!.dominated) continue;

    for (let j = 0; j < evaluated.length; j++) {
      if (i === j) continue;
      if (evaluated[j]!.dominated) continue;

      // Check if j dominates i:
      // j is at least as good in all dimensions and strictly better in at least one
      let atLeastAsGood = true;
      let strictlyBetter = false;

      for (let k = 0; k < utilityFunctions.length; k++) {
        if (evaluated[j]!.utilities[k]! < evaluated[i]!.utilities[k]!) {
          atLeastAsGood = false;
          break;
        }
        if (evaluated[j]!.utilities[k]! > evaluated[i]!.utilities[k]!) {
          strictlyBetter = true;
        }
      }

      if (atLeastAsGood && strictlyBetter) {
        evaluated[i]!.dominated = true;
        break;
      }
    }
  }

  return evaluated;
}

// ---------------------------------------------------------------------------
// N-Party Nash Bargaining
// ---------------------------------------------------------------------------

/**
 * Configuration for N-party Nash bargaining.
 */
export interface NPartyNashConfig {
  /** Number of gradient ascent iterations (default 200) */
  iterations?: number;
  /** Learning rate for gradient ascent (default 0.01) */
  learningRate?: number;
  /** Convergence tolerance for the Nash product (default 1e-9) */
  tolerance?: number;
}

/**
 * Result of N-party Nash bargaining.
 */
export interface NPartyNashResult {
  /** The selected outcome maximizing the generalized Nash product */
  outcome: Outcome;
  /** Utility achieved by each party */
  utilities: number[];
  /** Surplus above disagreement point for each party */
  surpluses: number[];
  /** The generalized Nash product value */
  nashProduct: number;
  /** Whether the solution is individually rational for all parties */
  individuallyRational: boolean;
}

/**
 * Compute the generalized N-party Nash Bargaining Solution.
 *
 * The generalized Nash product for N parties with bargaining powers w_i is:
 *
 *   Product_i (u_i(x) - d_i)^{w_i}
 *
 * where u_i is party i's utility, d_i is their disagreement value,
 * and w_i is their bargaining power (weight).
 *
 * For discrete outcome spaces, we evaluate all outcomes and pick the one
 * maximizing the generalized Nash product. Only outcomes satisfying individual
 * rationality (u_i >= d_i for all i) are considered.
 *
 * When bargaining powers are equal, this reduces to the symmetric Nash solution.
 *
 * @param outcomes - Array of feasible outcomes
 * @param utilities - Array of utility functions, one per party
 * @param bargainingPowers - Optional weights per party (default: equal weights). Must be positive.
 * @param config - Optional configuration for the algorithm
 * @returns NPartyNashResult or null if no individually rational outcome exists
 */
export function computeNPartyNash(
  outcomes: Outcome[],
  utilities: UtilityFunction[],
  bargainingPowers?: number[],
  config?: NPartyNashConfig,
): NPartyNashResult | null {
  if (outcomes.length === 0) {
    throw new SteleError('outcomes array must not be empty', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (utilities.length < 2) {
    throw new SteleError('At least 2 utility functions required for Nash bargaining', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }

  const n = utilities.length;
  const powers = bargainingPowers ?? utilities.map(() => 1.0);

  if (powers.length !== n) {
    throw new SteleError(`bargainingPowers length (${powers.length}) must match utilities length (${n})`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  for (let i = 0; i < powers.length; i++) {
    if (powers[i]! <= 0) {
      throw new SteleError(`bargainingPowers[${i}] must be positive, got ${powers[i]}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
  }

  let bestResult: NPartyNashResult | null = null;
  let bestProduct = -Infinity;

  for (const outcome of outcomes) {
    const utils: number[] = [];
    const surpluses: number[] = [];
    let allRational = true;

    for (let i = 0; i < n; i++) {
      const u = utilities[i]!.evaluate(outcome);
      const surplus = u - utilities[i]!.disagreementValue;
      utils.push(u);
      surpluses.push(surplus);
      if (surplus < 0) {
        allRational = false;
      }
    }

    if (!allRational) continue;

    // Compute generalized Nash product: Product_i (surplus_i)^{w_i}
    // Use log-space for numerical stability: sum_i w_i * ln(surplus_i)
    let logProduct = 0;
    let degenerate = false;
    for (let i = 0; i < n; i++) {
      if (surpluses[i]! <= 0) {
        degenerate = true;
        break;
      }
      logProduct += powers[i]! * Math.log(surpluses[i]!);
    }

    if (degenerate) continue;

    const nashProduct = Math.exp(logProduct);

    if (nashProduct > bestProduct) {
      bestProduct = nashProduct;
      bestResult = {
        outcome,
        utilities: utils,
        surpluses,
        nashProduct,
        individuallyRational: true,
      };
    }
  }

  return bestResult;
}

// ---------------------------------------------------------------------------
// Concession Protocol State Machine
// ---------------------------------------------------------------------------

/** States of the concession protocol. */
export type ConcessionState = 'PROPOSE' | 'COUNTER' | 'CONCEDE' | 'ACCEPT' | 'REJECT' | 'TIMEOUT';

/** A concession event in the protocol log. */
export interface ConcessionEvent {
  from: string;
  state: ConcessionState;
  proposal: Proposal;
  concessionAmount: number;
  timestamp: number;
}

/** Configuration for the concession protocol. */
export interface ConcessionConfig {
  /** Initial concession rate (fraction of remaining gap to concede per round, 0-1) */
  concessionRate: number;
  /** Deadline timestamp in ms. As deadline approaches, pressure increases. */
  deadline: number;
  /** Pressure function: 'linear' ramps linearly, 'exponential' ramps exponentially. */
  pressureFunction: 'linear' | 'exponential';
  /** Maximum number of rounds before automatic rejection. */
  maxRounds: number;
}

/**
 * ConcessionProtocol implements a formal state machine for negotiation
 * with configurable concession rates and deadline pressure.
 *
 * State transitions:
 *   PROPOSE -> COUNTER (other party counters)
 *   COUNTER -> CONCEDE (party makes a concession)
 *   CONCEDE -> COUNTER (other party counters the concession)
 *   CONCEDE -> ACCEPT (other party accepts)
 *   Any -> REJECT (rejection)
 *   Any -> TIMEOUT (deadline exceeded)
 *
 * The concession amount at each step is:
 *   amount = concessionRate * remainingGap * pressureMultiplier(t)
 *
 * where pressureMultiplier increases as the deadline approaches.
 */
export class ConcessionProtocol {
  private state: ConcessionState = 'PROPOSE';
  private log: ConcessionEvent[] = [];
  private round: number = 0;
  private readonly config: ConcessionConfig;
  private readonly startTime: number;

  constructor(config: ConcessionConfig) {
    if (config.concessionRate < 0 || config.concessionRate > 1) {
      throw new SteleError('concessionRate must be in [0, 1]', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (config.maxRounds < 1) {
      throw new SteleError('maxRounds must be >= 1', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (config.deadline <= 0) {
      throw new SteleError('deadline must be positive', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    this.config = config;
    this.startTime = Date.now();
  }

  /** Get the current protocol state. */
  getState(): ConcessionState {
    return this.state;
  }

  /** Get the full event log. */
  getLog(): ConcessionEvent[] {
    return [...this.log];
  }

  /** Get the current round number. */
  getRound(): number {
    return this.round;
  }

  /**
   * Compute deadline pressure multiplier.
   * Returns a value >= 1 that increases as the deadline approaches.
   * At the deadline, pressure is very high, encouraging larger concessions.
   */
  computePressure(currentTime: number): number {
    const totalDuration = this.config.deadline - this.startTime;
    if (totalDuration <= 0) return 10;

    const elapsed = currentTime - this.startTime;
    const fraction = Math.min(1, Math.max(0, elapsed / totalDuration));

    if (this.config.pressureFunction === 'exponential') {
      // Exponential: pressure = e^(3 * fraction) - gives ~20x at deadline
      return Math.exp(3 * fraction);
    }
    // Linear: pressure = 1 + 4 * fraction - gives 5x at deadline
    return 1 + 4 * fraction;
  }

  /**
   * Calculate the concession amount given the remaining gap between positions.
   */
  calculateConcession(remainingGap: number, currentTime: number): number {
    if (remainingGap <= 0) return 0;
    const pressure = this.computePressure(currentTime);
    return Math.min(remainingGap, this.config.concessionRate * remainingGap * pressure);
  }

  /**
   * Submit a proposal (initial or counter).
   * Transitions: PROPOSE or returns current state if already advanced.
   */
  propose(from: string, proposal: Proposal): ConcessionState {
    const now = Date.now();
    if (now > this.config.deadline) {
      this.state = 'TIMEOUT';
      return this.state;
    }

    if (this.state === 'ACCEPT' || this.state === 'REJECT' || this.state === 'TIMEOUT') {
      throw new SteleError(`Cannot propose in terminal state: ${this.state}`, SteleErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    this.log.push({
      from,
      state: 'PROPOSE',
      proposal,
      concessionAmount: 0,
      timestamp: now,
    });
    this.state = 'PROPOSE';
    this.round++;
    return this.state;
  }

  /**
   * Submit a counter-proposal.
   * Transitions: PROPOSE -> COUNTER or CONCEDE -> COUNTER
   */
  counter(from: string, proposal: Proposal): ConcessionState {
    const now = Date.now();
    if (now > this.config.deadline) {
      this.state = 'TIMEOUT';
      return this.state;
    }

    if (this.state !== 'PROPOSE' && this.state !== 'CONCEDE') {
      throw new SteleError(`Cannot counter in state: ${this.state}. Must be PROPOSE or CONCEDE.`, SteleErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    if (this.round >= this.config.maxRounds) {
      this.state = 'REJECT';
      return this.state;
    }

    this.log.push({
      from,
      state: 'COUNTER',
      proposal,
      concessionAmount: 0,
      timestamp: now,
    });
    this.state = 'COUNTER';
    this.round++;
    return this.state;
  }

  /**
   * Make a concession towards the other party's position.
   * The concession amount is calculated based on gap, rate, and deadline pressure.
   *
   * @param from - The party making the concession
   * @param proposal - The conceded proposal
   * @param remainingGap - The utility gap between current positions
   */
  concede(from: string, proposal: Proposal, remainingGap: number): ConcessionState {
    const now = Date.now();
    if (now > this.config.deadline) {
      this.state = 'TIMEOUT';
      return this.state;
    }

    if (this.state !== 'COUNTER' && this.state !== 'PROPOSE') {
      throw new SteleError(`Cannot concede in state: ${this.state}. Must be COUNTER or PROPOSE.`, SteleErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    const concessionAmount = this.calculateConcession(remainingGap, now);

    this.log.push({
      from,
      state: 'CONCEDE',
      proposal,
      concessionAmount,
      timestamp: now,
    });
    this.state = 'CONCEDE';
    this.round++;
    return this.state;
  }

  /**
   * Accept the current proposal. Terminal state.
   */
  accept(from: string, proposal: Proposal): ConcessionState {
    if (this.state === 'ACCEPT' || this.state === 'REJECT' || this.state === 'TIMEOUT') {
      throw new SteleError(`Cannot accept in terminal state: ${this.state}`, SteleErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    this.log.push({
      from,
      state: 'ACCEPT',
      proposal,
      concessionAmount: 0,
      timestamp: Date.now(),
    });
    this.state = 'ACCEPT';
    return this.state;
  }

  /**
   * Reject negotiation. Terminal state.
   */
  reject(from: string, proposal: Proposal): ConcessionState {
    if (this.state === 'ACCEPT' || this.state === 'REJECT' || this.state === 'TIMEOUT') {
      throw new SteleError(`Cannot reject in terminal state: ${this.state}`, SteleErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }

    this.log.push({
      from,
      state: 'REJECT',
      proposal,
      concessionAmount: 0,
      timestamp: Date.now(),
    });
    this.state = 'REJECT';
    return this.state;
  }
}

// ---------------------------------------------------------------------------
// Incremental Pareto Frontier
// ---------------------------------------------------------------------------

/**
 * IncrementalParetoFrontier maintains a Pareto frontier incrementally.
 *
 * Instead of O(n^2) pairwise comparison, this uses a sorted structure to
 * maintain the frontier. New points are inserted by checking dominance
 * against the frontier in O(n log n) amortized time using a sorted list
 * based on the first utility dimension.
 *
 * For 2D case, maintains a sorted array by u[0] descending; frontier
 * points must have strictly increasing u[1] as u[0] decreases.
 * For higher dimensions, falls back to dominance checking against frontier only.
 */
export class IncrementalParetoFrontier {
  private frontier: ParetoOutcome[] = [];
  private readonly dimensions: number;

  constructor(dimensions: number) {
    if (dimensions < 2) {
      throw new SteleError('Pareto frontier requires at least 2 dimensions', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    this.dimensions = dimensions;
  }

  /** Get the current Pareto frontier. */
  getFrontier(): ParetoOutcome[] {
    return [...this.frontier];
  }

  /** Get the number of points on the frontier. */
  size(): number {
    return this.frontier.length;
  }

  /**
   * Check if point a dominates point b.
   * a dominates b if a is >= in all dimensions and > in at least one.
   */
  private dominates(a: number[], b: number[]): boolean {
    let strictlyBetter = false;
    for (let k = 0; k < this.dimensions; k++) {
      if (a[k]! < b[k]!) return false;
      if (a[k]! > b[k]!) strictlyBetter = true;
    }
    return strictlyBetter;
  }

  /**
   * Insert a new point into the Pareto frontier.
   *
   * For 2D: uses binary search on the first dimension to find the insertion
   * point, then checks if dominated or if it dominates existing points.
   * Points dominated by the new point are removed.
   *
   * For higher dimensions: checks dominance against all frontier points.
   *
   * @returns true if the point was added to the frontier, false if dominated
   */
  insert(outcome: Outcome, utilities: number[]): boolean {
    if (utilities.length !== this.dimensions) {
      throw new SteleError(`Expected ${this.dimensions} utility values, got ${utilities.length}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }

    const newPoint: ParetoOutcome = {
      outcome,
      utilities: [...utilities],
      dominated: false,
    };

    // Check if new point is dominated by any frontier point
    for (const fp of this.frontier) {
      if (this.dominates(fp.utilities, utilities)) {
        return false; // New point is dominated
      }
    }

    // Remove frontier points dominated by the new point
    this.frontier = this.frontier.filter(fp => !this.dominates(utilities, fp.utilities));

    // Insert maintaining sort by first dimension (descending)
    if (this.frontier.length === 0) {
      this.frontier.push(newPoint);
    } else {
      // Binary search for insertion position (sorted by u[0] descending)
      let lo = 0;
      let hi = this.frontier.length;
      while (lo < hi) {
        const mid = (lo + hi) >>> 1;
        if (this.frontier[mid]!.utilities[0]! > utilities[0]!) {
          lo = mid + 1;
        } else {
          hi = mid;
        }
      }
      this.frontier.splice(lo, 0, newPoint);
    }

    return true;
  }

  /**
   * Build a frontier from a batch of outcomes and utility functions.
   * More efficient than inserting one by one when starting from scratch.
   */
  static fromBatch(
    outcomes: Outcome[],
    utilityFunctions: UtilityFunction[],
  ): IncrementalParetoFrontier {
    const dims = utilityFunctions.length;
    const frontier = new IncrementalParetoFrontier(dims);

    // Evaluate all utilities
    const evaluated = outcomes.map(outcome => ({
      outcome,
      utilities: utilityFunctions.map(uf => uf.evaluate(outcome)),
    }));

    // Sort by first dimension descending for efficient insertion
    evaluated.sort((a, b) => b.utilities[0]! - a.utilities[0]!);

    for (const item of evaluated) {
      frontier.insert(item.outcome, item.utilities);
    }

    return frontier;
  }
}

// ---------------------------------------------------------------------------
// Zeuthen Strategy
// ---------------------------------------------------------------------------

/**
 * Result of a Zeuthen strategy evaluation.
 */
export interface ZeuthenResult {
  /** Which party should concede ('A' or 'B') */
  conceder: 'A' | 'B';
  /** Party A's willingness to risk conflict (0-1) */
  riskA: number;
  /** Party B's willingness to risk conflict (0-1) */
  riskB: number;
  /** Utility of A's current proposal for A */
  utilityAForA: number;
  /** Utility of B's current proposal for A */
  utilityBForA: number;
  /** Utility of A's current proposal for B */
  utilityAForB: number;
  /** Utility of B's current proposal for B */
  utilityBForB: number;
}

/**
 * Implement the Zeuthen negotiation strategy.
 *
 * The Zeuthen strategy determines which party should make the next
 * concession based on each party's "willingness to risk conflict."
 *
 * For party A with current proposal pA and facing proposal pB:
 *   risk_A = (uA(pA) - uA(pB)) / uA(pA)     if uA(pA) > 0
 *          = 0                                  if uA(pA) <= 0
 *
 * The party with the LOWER willingness to risk conflict (lower risk value)
 * should concede, since they have less to lose by accepting the other's offer.
 *
 * If risk values are equal, party A concedes by convention.
 *
 * This converges to the Nash bargaining solution in the limit.
 *
 * @param proposalA - Party A's current proposal
 * @param proposalB - Party B's current proposal
 * @param utilityA - Party A's utility function
 * @param utilityB - Party B's utility function
 * @returns ZeuthenResult indicating which party should concede
 */
export function zeuthenStrategy(
  proposalA: Outcome,
  proposalB: Outcome,
  utilityA: UtilityFunction,
  utilityB: UtilityFunction,
): ZeuthenResult {
  const uAA = utilityA.evaluate(proposalA); // A's utility for A's proposal
  const uAB = utilityA.evaluate(proposalB); // A's utility for B's proposal
  const uBA = utilityB.evaluate(proposalA); // B's utility for A's proposal
  const uBB = utilityB.evaluate(proposalB); // B's utility for B's proposal

  // Willingness to risk conflict for A:
  // risk_A = (uA(pA) - uA(pB)) / uA(pA)
  // High risk means A strongly prefers their own proposal -> less willing to concede
  const riskA = uAA > 0 ? Math.max(0, (uAA - uAB) / uAA) : 0;

  // Willingness to risk conflict for B:
  // risk_B = (uB(pB) - uB(pA)) / uB(pB)
  const riskB = uBB > 0 ? Math.max(0, (uBB - uBA) / uBB) : 0;

  // The party with LOWER risk should concede (they have less to lose)
  const conceder: 'A' | 'B' = riskA <= riskB ? 'A' : 'B';

  return {
    conceder,
    riskA,
    riskB,
    utilityAForA: uAA,
    utilityBForA: uAB,
    utilityAForB: uBA,
    utilityBForB: uBB,
  };
}

/**
 * Run a multi-round Zeuthen negotiation to convergence or max rounds.
 *
 * At each round, determines which party should concede using the Zeuthen
 * strategy, then has that party pick the outcome closest to the midpoint
 * of their current position and the other's proposal.
 *
 * @param outcomes - Set of feasible outcomes
 * @param utilityA - Party A's utility function
 * @param utilityB - Party B's utility function
 * @param maxRounds - Maximum number of rounds (default 100)
 * @returns Array of ZeuthenResult for each round, plus the final agreed outcome
 */
export function runZeuthenNegotiation(
  outcomes: Outcome[],
  utilityA: UtilityFunction,
  utilityB: UtilityFunction,
  maxRounds: number = 100,
): { rounds: ZeuthenResult[]; agreedOutcome: Outcome | null } {
  if (outcomes.length === 0) {
    throw new SteleError('outcomes array must not be empty', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (maxRounds < 1) {
    throw new SteleError('maxRounds must be >= 1', SteleErrorCode.PROTOCOL_INVALID_INPUT);
  }

  // Each party starts with their most preferred outcome
  let bestForA = outcomes[0]!;
  let bestUtilA = -Infinity;
  let bestForB = outcomes[0]!;
  let bestUtilB = -Infinity;

  for (const o of outcomes) {
    const uA = utilityA.evaluate(o);
    const uB = utilityB.evaluate(o);
    if (uA > bestUtilA) { bestUtilA = uA; bestForA = o; }
    if (uB > bestUtilB) { bestUtilB = uB; bestForB = o; }
  }

  let currentA = bestForA;
  let currentB = bestForB;
  const rounds: ZeuthenResult[] = [];

  for (let round = 0; round < maxRounds; round++) {
    const result = zeuthenStrategy(currentA, currentB, utilityA, utilityB);
    rounds.push(result);

    // Check for agreement (proposals are the same)
    if (currentA === currentB) {
      return { rounds, agreedOutcome: currentA };
    }

    // Check for near-agreement (risks both near zero)
    if (result.riskA < 0.001 && result.riskB < 0.001) {
      return { rounds, agreedOutcome: currentA };
    }

    // The conceder moves toward the other's position
    if (result.conceder === 'A') {
      // A concedes: pick the outcome that maximizes A's utility
      // subject to being closer to B's current position
      const targetUtilA = (utilityA.evaluate(currentA) + utilityA.evaluate(currentB)) / 2;
      let bestDist = Infinity;
      let bestOutcome = currentA;
      for (const o of outcomes) {
        const uA = utilityA.evaluate(o);
        const dist = Math.abs(uA - targetUtilA);
        if (dist < bestDist && utilityB.evaluate(o) >= utilityB.evaluate(currentA)) {
          bestDist = dist;
          bestOutcome = o;
        }
      }
      currentA = bestOutcome;
    } else {
      // B concedes: pick the outcome that maximizes B's utility
      // subject to being closer to A's current position
      const targetUtilB = (utilityB.evaluate(currentB) + utilityB.evaluate(currentA)) / 2;
      let bestDist = Infinity;
      let bestOutcome = currentB;
      for (const o of outcomes) {
        const uB = utilityB.evaluate(o);
        const dist = Math.abs(uB - targetUtilB);
        if (dist < bestDist && utilityA.evaluate(o) >= utilityA.evaluate(currentB)) {
          bestDist = dist;
          bestOutcome = o;
        }
      }
      currentB = bestOutcome;
    }
  }

  // No agreement after max rounds
  return { rounds, agreedOutcome: null };
}
