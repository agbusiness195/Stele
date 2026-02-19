import { generateId } from '@usekova/crypto';
import { KovaError, KovaErrorCode } from '@usekova/types';

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
 * Match a glob-style wildcard pattern against a value string.
 *
 * Supports `*` as a wildcard that matches any sequence of characters:
 * - `deny:*` matches any string starting with `deny:`
 * - `permit:read-*` matches `permit:read-public`, `permit:read-private`, etc.
 * - `deny:*-data` matches `deny:exfiltrate-data`, `deny:modify-data`, etc.
 *
 * The pattern is converted to a regex: special regex characters are escaped,
 * `*` is replaced with `.*`, and the result is anchored with `^` and `$`.
 */
export function matchesPattern(pattern: string, value: string): boolean {
  // If no wildcard, do exact match for performance
  if (!pattern.includes('*')) {
    return pattern === value;
  }
  // Escape regex special characters except `*`, then replace `*` with `.*`
  const escaped = pattern.replace(/([.+?^${}()|[\]\\])/g, '\\$1');
  const regexStr = '^' + escaped.replace(/\*/g, '.*') + '$';
  const regex = new RegExp(regexStr);
  return regex.test(value);
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
  // Check for dealbreakers using glob pattern matching
  for (const dealbreaker of policy.dealbreakers) {
    for (const constraint of proposal.constraints) {
      if (matchesPattern(dealbreaker, constraint)) {
        return 'reject';
      }
    }
  }

  // Check if all required constraints are present using glob pattern matching
  // Wildcards can appear on either side: the required pattern or the constraint
  let allRequiredPresent = true;
  for (const required of policy.requiredConstraints) {
    const found = proposal.constraints.some(
      constraint => matchesPattern(required, constraint) || matchesPattern(constraint, required),
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
    throw new KovaError('outcomes array must not be empty', KovaErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (utilities.length < 2) {
    throw new KovaError('At least 2 utility functions required for Nash bargaining', KovaErrorCode.PROTOCOL_INVALID_INPUT);
  }

  const n = utilities.length;
  const powers = bargainingPowers ?? utilities.map(() => 1.0);

  if (powers.length !== n) {
    throw new KovaError(`bargainingPowers length (${powers.length}) must match utilities length (${n})`, KovaErrorCode.PROTOCOL_INVALID_INPUT);
  }
  for (let i = 0; i < powers.length; i++) {
    if (powers[i]! <= 0) {
      throw new KovaError(`bargainingPowers[${i}] must be positive, got ${powers[i]}`, KovaErrorCode.PROTOCOL_INVALID_INPUT);
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
      throw new KovaError('concessionRate must be in [0, 1]', KovaErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (config.maxRounds < 1) {
      throw new KovaError('maxRounds must be >= 1', KovaErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (config.deadline <= 0) {
      throw new KovaError('deadline must be positive', KovaErrorCode.PROTOCOL_INVALID_INPUT);
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
      throw new KovaError(`Cannot propose in terminal state: ${this.state}`, KovaErrorCode.PROTOCOL_COMPUTATION_FAILED);
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
      throw new KovaError(`Cannot counter in state: ${this.state}. Must be PROPOSE or CONCEDE.`, KovaErrorCode.PROTOCOL_COMPUTATION_FAILED);
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
      throw new KovaError(`Cannot concede in state: ${this.state}. Must be COUNTER or PROPOSE.`, KovaErrorCode.PROTOCOL_COMPUTATION_FAILED);
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
      throw new KovaError(`Cannot accept in terminal state: ${this.state}`, KovaErrorCode.PROTOCOL_COMPUTATION_FAILED);
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
      throw new KovaError(`Cannot reject in terminal state: ${this.state}`, KovaErrorCode.PROTOCOL_COMPUTATION_FAILED);
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
      throw new KovaError('Pareto frontier requires at least 2 dimensions', KovaErrorCode.PROTOCOL_INVALID_INPUT);
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
      throw new KovaError(`Expected ${this.dimensions} utility values, got ${utilities.length}`, KovaErrorCode.PROTOCOL_INVALID_INPUT);
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
    throw new KovaError('outcomes array must not be empty', KovaErrorCode.PROTOCOL_INVALID_INPUT);
  }
  if (maxRounds < 1) {
    throw new KovaError('maxRounds must be >= 1', KovaErrorCode.PROTOCOL_INVALID_INPUT);
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

// ---------------------------------------------------------------------------
// Negotiation Latency Benchmarks
// ---------------------------------------------------------------------------

export interface NegotiationBenchmark {
  /** Operation being benchmarked */
  operation: string;
  /** Number of iterations run */
  iterations: number;
  /** Mean latency in milliseconds */
  meanLatencyMs: number;
  /** P50 latency */
  p50Ms: number;
  /** P95 latency */
  p95Ms: number;
  /** P99 latency */
  p99Ms: number;
  /** Whether it meets the <100ms target */
  meetsTarget: boolean;
  targetMs: number;
}

/**
 * Compute a percentile from a sorted array of numbers.
 * Uses linear interpolation between closest ranks.
 */
function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  if (sorted.length === 1) return sorted[0]!;
  const rank = (p / 100) * (sorted.length - 1);
  const lower = Math.floor(rank);
  const upper = Math.ceil(rank);
  if (lower === upper) return sorted[lower]!;
  const fraction = rank - lower;
  return sorted[lower]! + fraction * (sorted[upper]! - sorted[lower]!);
}

/**
 * Create a NegotiationBenchmark from an array of latency measurements.
 */
function buildBenchmark(
  operation: string,
  latencies: number[],
  targetMs: number,
): NegotiationBenchmark {
  const sorted = [...latencies].sort((a, b) => a - b);
  const mean = latencies.reduce((sum, v) => sum + v, 0) / latencies.length;
  const p50 = percentile(sorted, 50);
  const p95 = percentile(sorted, 95);
  const p99 = percentile(sorted, 99);

  return {
    operation,
    iterations: latencies.length,
    meanLatencyMs: mean,
    p50Ms: p50,
    p95Ms: p95,
    p99Ms: p99,
    meetsTarget: p95 < targetMs,
    targetMs,
  };
}

/**
 * Benchmark parameters for the negotiation flow.
 */
export interface BenchmarkParams {
  /** Number of iterations to run (default: 1000) */
  iterations?: number;
  /** Target latency in milliseconds (default: 100) */
  targetMs?: number;
  /** Initiator's negotiation policy */
  initiatorPolicy?: NegotiationPolicy;
  /** Responder's negotiation policy */
  responderPolicy?: NegotiationPolicy;
}

/**
 * Run the full negotiation flow (initiate -> propose -> counter -> agree) N
 * times and measure wall-clock time for each iteration. Computes percentile
 * latencies and reports whether the <100ms covenant negotiation target is met.
 *
 * Includes sub-benchmarks for:
 *   - Initiation
 *   - Proposal evaluation
 *   - Counter-proposal generation
 *   - Agreement
 *
 * @param params - Benchmark configuration.
 * @returns An object containing the overall benchmark and sub-benchmarks.
 */
export function benchmarkNegotiation(params?: BenchmarkParams): {
  overall: NegotiationBenchmark;
  subBenchmarks: NegotiationBenchmark[];
} {
  const iterations = params?.iterations ?? 1000;
  const targetMs = params?.targetMs ?? 100;

  const defaultInitiatorPolicy: NegotiationPolicy = params?.initiatorPolicy ?? {
    requiredConstraints: ['deny:exfiltrate-data', 'require:audit-logging'],
    preferredConstraints: ['permit:read-public', 'limit:api-rate-1000'],
    dealbreakers: ['permit:unrestricted-access'],
    maxRounds: 10,
    timeoutMs: 30000,
  };

  const defaultResponderPolicy: NegotiationPolicy = params?.responderPolicy ?? {
    requiredConstraints: ['deny:exfiltrate-data', 'deny:modify-system-config'],
    preferredConstraints: ['permit:read-public', 'require:audit-logging'],
    dealbreakers: ['permit:delete-all'],
    maxRounds: 10,
    timeoutMs: 30000,
  };

  const overallLatencies: number[] = [];
  const initiationLatencies: number[] = [];
  const evaluationLatencies: number[] = [];
  const counterLatencies: number[] = [];
  const agreementLatencies: number[] = [];

  for (let i = 0; i < iterations; i++) {
    const overallStart = performance.now();

    // Sub-benchmark: Initiation
    const initStart = performance.now();
    const session = initiate('initiator-bench', 'responder-bench', defaultInitiatorPolicy);
    const initEnd = performance.now();
    initiationLatencies.push(initEnd - initStart);

    // Sub-benchmark: Proposal evaluation
    const evalStart = performance.now();
    const lastProposal = session.proposals[session.proposals.length - 1]!;
    const decision = evaluate(lastProposal, defaultResponderPolicy);
    const evalEnd = performance.now();
    evaluationLatencies.push(evalEnd - evalStart);

    // Sub-benchmark: Counter-proposal generation
    const counterStart = performance.now();
    let updatedSession = session;
    if (decision === 'counter') {
      const counterProposal: Proposal = {
        from: 'responder-bench',
        constraints: [
          ...defaultResponderPolicy.requiredConstraints,
          ...defaultResponderPolicy.preferredConstraints,
        ],
        requirements: [...defaultResponderPolicy.requiredConstraints],
        timestamp: Date.now(),
      };
      updatedSession = counter(session, counterProposal);
    } else {
      // Even if accept or reject, add a proposal so agree() has two proposals
      const acceptProposal: Proposal = {
        from: 'responder-bench',
        constraints: [...lastProposal.constraints],
        requirements: [...lastProposal.requirements],
        timestamp: Date.now(),
      };
      updatedSession = propose(session, acceptProposal);
    }
    const counterEnd = performance.now();
    counterLatencies.push(counterEnd - counterStart);

    // Sub-benchmark: Agreement
    const agreeStart = performance.now();
    agree(updatedSession);
    const agreeEnd = performance.now();
    agreementLatencies.push(agreeEnd - agreeStart);

    const overallEnd = performance.now();
    overallLatencies.push(overallEnd - overallStart);
  }

  return {
    overall: buildBenchmark('full-negotiation-flow', overallLatencies, targetMs),
    subBenchmarks: [
      buildBenchmark('initiation', initiationLatencies, targetMs),
      buildBenchmark('proposal-evaluation', evaluationLatencies, targetMs),
      buildBenchmark('counter-proposal', counterLatencies, targetMs),
      buildBenchmark('agreement', agreementLatencies, targetMs),
    ],
  };
}

// ---------------------------------------------------------------------------
// Optimized Negotiate ("Trust Handshake")
// ---------------------------------------------------------------------------

/**
 * Constraint parsed into its type and resource for fast intersection.
 */
interface ParsedConstraintEntry {
  raw: string;
  type: string;
  resource: string;
}

/**
 * Result of an optimized negotiation.
 */
export interface OptimizedNegotiationResult {
  /** Whether agreement was reached */
  agreed: boolean;
  /** The agreed-upon constraints (if agreed), or null */
  constraints: string[] | null;
  /** Time taken in milliseconds */
  elapsedMs: number;
  /** Number of deny constraints in the result (deny-wins) */
  denyCount: number;
  /** Number of permit constraints in the result */
  permitCount: number;
}

/**
 * A streamlined single-function negotiation that skips session overhead.
 *
 * Directly computes constraint intersection using deny-wins semantics:
 *   1. Collect all deny constraints from both policies (union -- deny-wins)
 *   2. Intersect permit/require/limit constraints (both parties must agree)
 *   3. Check dealbreakers -- if any resulting constraint is a dealbreaker
 *      for either party, negotiation fails
 *   4. Verify all required constraints from both parties are satisfied
 *
 * This is the "trust handshake" described in the Kova vision as completing
 * in <100ms. It avoids session creation, proposal objects, round tracking,
 * and other overhead from the multi-step session approach.
 *
 * @param initiatorPolicy - The initiator's negotiation policy.
 * @param responderPolicy - The responder's negotiation policy.
 * @returns An OptimizedNegotiationResult with the agreed constraints or null.
 */
export function optimizedNegotiate(
  initiatorPolicy: NegotiationPolicy,
  responderPolicy: NegotiationPolicy,
): OptimizedNegotiationResult {
  const start = performance.now();

  // Parse all constraints from both policies
  const initiatorAll = [
    ...initiatorPolicy.requiredConstraints,
    ...initiatorPolicy.preferredConstraints,
  ];
  const responderAll = [
    ...responderPolicy.requiredConstraints,
    ...responderPolicy.preferredConstraints,
  ];

  const initiatorDealbreakers = new Set(initiatorPolicy.dealbreakers);
  const responderDealbreakers = new Set(responderPolicy.dealbreakers);

  // Step 1: Collect all deny constraints from both sides (deny-wins: union)
  const denyConstraints = new Set<string>();
  const nonDenyInitiator: string[] = [];
  const nonDenyResponder: string[] = [];

  for (const c of initiatorAll) {
    if (c.startsWith('deny:')) {
      denyConstraints.add(c);
    } else {
      nonDenyInitiator.push(c);
    }
  }
  for (const c of responderAll) {
    if (c.startsWith('deny:')) {
      denyConstraints.add(c);
    } else {
      nonDenyResponder.push(c);
    }
  }

  // Step 2: Intersect non-deny constraints (both must agree)
  // Use pattern matching to find compatible constraints between parties
  const intersectedNonDeny: string[] = [];
  const addedToIntersection = new Set<string>();
  for (const ic of nonDenyInitiator) {
    for (const rc of nonDenyResponder) {
      if (matchesPattern(ic, rc) || matchesPattern(rc, ic)) {
        // Add the more specific (non-wildcard) constraint, or the first match
        const toAdd = ic.includes('*') ? rc : ic;
        if (!addedToIntersection.has(toAdd)) {
          intersectedNonDeny.push(toAdd);
          addedToIntersection.add(toAdd);
        }
        break;
      }
    }
  }

  // Combine: all denies + intersected non-denies
  const resultConstraints = [...denyConstraints, ...intersectedNonDeny];

  // Step 3: Check dealbreakers using pattern matching
  for (const c of resultConstraints) {
    for (const db of initiatorPolicy.dealbreakers) {
      if (matchesPattern(db, c)) {
        const elapsed = performance.now() - start;
        return {
          agreed: false,
          constraints: null,
          elapsedMs: elapsed,
          denyCount: denyConstraints.size,
          permitCount: 0,
        };
      }
    }
    for (const db of responderPolicy.dealbreakers) {
      if (matchesPattern(db, c)) {
        const elapsed = performance.now() - start;
        return {
          agreed: false,
          constraints: null,
          elapsedMs: elapsed,
          denyCount: denyConstraints.size,
          permitCount: 0,
        };
      }
    }
  }

  // Step 4: Verify required constraints are satisfied using pattern matching
  for (const req of initiatorPolicy.requiredConstraints) {
    const covered = resultConstraints.some(
      c => matchesPattern(req, c) || matchesPattern(c, req),
    );
    if (!covered) {
      const elapsed = performance.now() - start;
      return {
        agreed: false,
        constraints: null,
        elapsedMs: elapsed,
        denyCount: denyConstraints.size,
        permitCount: 0,
      };
    }
  }

  for (const req of responderPolicy.requiredConstraints) {
    const covered = resultConstraints.some(
      c => matchesPattern(req, c) || matchesPattern(c, req),
    );
    if (!covered) {
      const elapsed = performance.now() - start;
      return {
        agreed: false,
        constraints: null,
        elapsedMs: elapsed,
        denyCount: denyConstraints.size,
        permitCount: 0,
      };
    }
  }

  const elapsed = performance.now() - start;

  // Count permit constraints in result
  let permitCount = 0;
  for (const c of resultConstraints) {
    if (c.startsWith('permit:')) permitCount++;
  }

  return {
    agreed: true,
    constraints: resultConstraints,
    elapsedMs: elapsed,
    denyCount: denyConstraints.size,
    permitCount,
  };
}

// ---------------------------------------------------------------------------
// Negotiation Explanation
// ---------------------------------------------------------------------------

/**
 * Detailed explanation of why a negotiation succeeded or failed.
 */
export interface NegotiationExplanation {
  /** Whether agreement was reached */
  agreed: boolean;
  /** Which dealbreakers were triggered (pattern -> constraint that matched) */
  dealbreakers: string[];
  /** Which requirements couldn't be satisfied */
  missingRequirements: string[];
  /** Conflicting constraints between the two parties */
  constraintConflicts: Array<{ initiator: string; responder: string; reason: string }>;
}

/**
 * Run the same logic as `optimizedNegotiate` but record WHY it failed.
 *
 * Instead of returning early on the first failure, this function collects
 * all triggered dealbreakers, all unsatisfied requirements, and all
 * conflicting constraints between the two parties.
 *
 * @param initiatorPolicy - The initiator's negotiation policy.
 * @param responderPolicy - The responder's negotiation policy.
 * @returns A NegotiationExplanation describing the negotiation outcome.
 */
export function explainNegotiationFailure(
  initiatorPolicy: NegotiationPolicy,
  responderPolicy: NegotiationPolicy,
): NegotiationExplanation {
  const triggeredDealbreakers: string[] = [];
  const missingRequirements: string[] = [];
  const constraintConflicts: Array<{ initiator: string; responder: string; reason: string }> = [];

  // Gather all constraints from both policies
  const initiatorAll = [
    ...initiatorPolicy.requiredConstraints,
    ...initiatorPolicy.preferredConstraints,
  ];
  const responderAll = [
    ...responderPolicy.requiredConstraints,
    ...responderPolicy.preferredConstraints,
  ];

  // Step 1: Collect all deny constraints from both sides (deny-wins: union)
  const denyConstraints = new Set<string>();
  const nonDenyInitiator: string[] = [];
  const nonDenyResponder: string[] = [];

  for (const c of initiatorAll) {
    if (c.startsWith('deny:')) {
      denyConstraints.add(c);
    } else {
      nonDenyInitiator.push(c);
    }
  }
  for (const c of responderAll) {
    if (c.startsWith('deny:')) {
      denyConstraints.add(c);
    } else {
      nonDenyResponder.push(c);
    }
  }

  // Step 2: Intersect non-deny constraints using pattern matching
  const intersectedNonDeny: string[] = [];
  const addedToIntersection = new Set<string>();
  for (const ic of nonDenyInitiator) {
    for (const rc of nonDenyResponder) {
      if (matchesPattern(ic, rc) || matchesPattern(rc, ic)) {
        const toAdd = ic.includes('*') ? rc : ic;
        if (!addedToIntersection.has(toAdd)) {
          intersectedNonDeny.push(toAdd);
          addedToIntersection.add(toAdd);
        }
        break;
      }
    }
  }

  // Combine: all denies + intersected non-denies
  const resultConstraints = [...denyConstraints, ...intersectedNonDeny];

  // Step 3: Check dealbreakers using pattern matching -- record all triggers
  for (const c of resultConstraints) {
    for (const db of initiatorPolicy.dealbreakers) {
      if (matchesPattern(db, c)) {
        triggeredDealbreakers.push(`Initiator dealbreaker "${db}" triggered by constraint "${c}"`);
      }
    }
    for (const db of responderPolicy.dealbreakers) {
      if (matchesPattern(db, c)) {
        triggeredDealbreakers.push(`Responder dealbreaker "${db}" triggered by constraint "${c}"`);
      }
    }
  }

  // Step 4: Verify required constraints are satisfied -- record all misses
  for (const req of initiatorPolicy.requiredConstraints) {
    const covered = resultConstraints.some(
      c => matchesPattern(req, c) || matchesPattern(c, req),
    );
    if (!covered) {
      missingRequirements.push(`Initiator required constraint "${req}" not satisfied`);
    }
  }

  for (const req of responderPolicy.requiredConstraints) {
    const covered = resultConstraints.some(
      c => matchesPattern(req, c) || matchesPattern(c, req),
    );
    if (!covered) {
      missingRequirements.push(`Responder required constraint "${req}" not satisfied`);
    }
  }

  // Detect conflicting constraints: one party permits what the other denies
  for (const ic of initiatorAll) {
    const icParsed = parseConstraint(ic);
    for (const rc of responderAll) {
      const rcParsed = parseConstraint(rc);
      // Check if one is a permit and the other is a deny on the same resource
      if (
        icParsed.type === 'permit' && rcParsed.type === 'deny' &&
        matchesPattern(icParsed.resource, rcParsed.resource)
      ) {
        constraintConflicts.push({
          initiator: ic,
          responder: rc,
          reason: `Initiator permits "${icParsed.resource}" but responder denies "${rcParsed.resource}"`,
        });
      } else if (
        icParsed.type === 'deny' && rcParsed.type === 'permit' &&
        matchesPattern(rcParsed.resource, icParsed.resource)
      ) {
        constraintConflicts.push({
          initiator: ic,
          responder: rc,
          reason: `Initiator denies "${icParsed.resource}" but responder permits "${rcParsed.resource}"`,
        });
      }
    }
  }

  const agreed = triggeredDealbreakers.length === 0 && missingRequirements.length === 0;

  return {
    agreed,
    dealbreakers: triggeredDealbreakers,
    missingRequirements,
    constraintConflicts,
  };
}
