export type {
  TrustStatus,
  BreachAttestation,
  TrustNode,
  BreachEvent,
} from './types.js';

import type { KeyPair, HashHex } from '@kervyx/crypto';
import type { Severity } from '@kervyx/ccl';
import { KervyxError, KervyxErrorCode } from '@kervyx/types';
import {
  sha256Object,
  canonicalizeJson,
  signString,
  verify,
  toHex,
  fromHex,
  timestamp,
} from '@kervyx/crypto';

import type {
  BreachAttestation,
  TrustNode,
  TrustStatus,
  BreachEvent,
} from './types.js';

/**
 * Map severity to recommended action.
 */
function recommendedActionForSeverity(
  severity: Severity,
): 'revoke' | 'restrict' | 'monitor' | 'notify' {
  switch (severity) {
    case 'critical':
      return 'revoke';
    case 'high':
      return 'restrict';
    case 'medium':
      return 'monitor';
    case 'low':
      return 'notify';
    default: {
      const _exhaustive: never = severity;
      throw new Error(`Unknown severity: ${_exhaustive}`);
    }
  }
}

/**
 * Map severity to the trust status applied to the violator.
 */
function statusForSeverity(severity: Severity): TrustStatus {
  switch (severity) {
    case 'critical':
      return 'revoked';
    case 'high':
      return 'restricted';
    case 'medium':
      return 'degraded';
    case 'low':
      return 'trusted';
    default: {
      const _exhaustive: never = severity;
      throw new Error(`Unknown severity: ${_exhaustive}`);
    }
  }
}

/**
 * Degrade a trust status by one level.
 * revoked -> restricted -> degraded -> (stop)
 */
function degradeStatus(status: TrustStatus): TrustStatus | null {
  switch (status) {
    case 'revoked':
      return 'restricted';
    case 'restricted':
      return 'degraded';
    default:
      return null;
  }
}

/**
 * Numeric ordering of trust statuses for comparison.
 * Lower number means worse trust.
 */
function statusSeverityRank(status: TrustStatus): number {
  switch (status) {
    case 'revoked':
      return 0;
    case 'restricted':
      return 1;
    case 'degraded':
      return 2;
    case 'trusted':
      return 3;
    case 'unknown':
      return 4;
  }
}

/**
 * Returns the worse (lower-ranked) of two trust statuses.
 */
function worseStatus(a: TrustStatus, b: TrustStatus): TrustStatus {
  return statusSeverityRank(a) <= statusSeverityRank(b) ? a : b;
}

/**
 * Create and sign a breach attestation.
 *
 * Constructs the attestation object, determines the recommended action from
 * the severity, computes the content hash as the attestation ID, and signs
 * the canonical JSON with the reporter's key pair.
 */
export async function createBreachAttestation(
  covenantId: HashHex,
  violatorIdentityHash: HashHex,
  violatedConstraint: string,
  severity: Severity,
  action: string,
  resource: string,
  evidenceHash: HashHex,
  affectedCovenants: HashHex[],
  reporterKeyPair: KeyPair,
): Promise<BreachAttestation> {
  const recommendedAction = recommendedActionForSeverity(severity);
  const reportedAt = timestamp();
  const reporterPublicKey = reporterKeyPair.publicKeyHex;

  // Build the content object (everything except id and signature)
  const content = {
    covenantId,
    violatorIdentityHash,
    violatedConstraint,
    severity,
    action,
    resource,
    evidenceHash,
    recommendedAction,
    reporterPublicKey,
    reportedAt,
    affectedCovenants,
  };

  // ID is the SHA-256 of the canonical content
  const id = sha256Object(content);

  // Sign the canonical JSON of the attestation sans signature (includes id)
  const attestationForSigning = { ...content, id };
  const canonical = canonicalizeJson(attestationForSigning);
  const signature = await signString(canonical, reporterKeyPair.privateKey);
  const reporterSignature = toHex(signature);

  return {
    id,
    covenantId,
    violatorIdentityHash,
    violatedConstraint,
    severity,
    action,
    resource,
    evidenceHash,
    recommendedAction,
    reporterPublicKey,
    reporterSignature,
    reportedAt,
    affectedCovenants,
  };
}

/**
 * Verify a breach attestation's integrity and signature.
 *
 * Checks that the ID matches the SHA-256 of the content and that the
 * reporter's signature is valid over the canonical JSON (sans signature).
 */
export async function verifyBreachAttestation(
  attestation: BreachAttestation,
): Promise<boolean> {
  // Reconstruct the content object (everything except id and signature)
  const content = {
    covenantId: attestation.covenantId,
    violatorIdentityHash: attestation.violatorIdentityHash,
    violatedConstraint: attestation.violatedConstraint,
    severity: attestation.severity,
    action: attestation.action,
    resource: attestation.resource,
    evidenceHash: attestation.evidenceHash,
    recommendedAction: attestation.recommendedAction,
    reporterPublicKey: attestation.reporterPublicKey,
    reportedAt: attestation.reportedAt,
    affectedCovenants: attestation.affectedCovenants,
  };

  // Verify ID matches content hash
  const expectedId = sha256Object(content);
  if (attestation.id !== expectedId) {
    return false;
  }

  // Verify signature over canonical JSON of attestation sans signature
  const attestationForSigning = { ...content, id: attestation.id };
  const canonical = canonicalizeJson(attestationForSigning);
  const message = new TextEncoder().encode(canonical);
  const signatureBytes = fromHex(attestation.reporterSignature);
  const publicKeyBytes = fromHex(attestation.reporterPublicKey);

  return verify(message, signatureBytes, publicKeyBytes);
}

/**
 * A directed graph tracking trust relationships between agents.
 *
 * When a breach is processed, the violator's trust status is updated and the
 * degradation propagates through the dependency graph to all transitive
 * dependents via BFS, with each hop degrading the status by one level.
 */
export class TrustGraph {
  private nodes: Map<HashHex, TrustNode> = new Map();
  private listeners: Set<(event: BreachEvent) => void> = new Set();

  /**
   * Ensure a node exists in the graph, creating it with defaults if necessary.
   */
  private ensureNode(identityHash: HashHex): TrustNode {
    let node = this.nodes.get(identityHash);
    if (!node) {
      node = {
        identityHash,
        status: 'trusted',
        breachCount: 0,
        dependents: [],
        dependencies: [],
      };
      this.nodes.set(identityHash, node);
    }
    return node;
  }

  /**
   * Register a dependency edge: parentHash depends on childHash.
   * If parentHash is breached, all its dependents are affected.
   * childHash is a dependent of parentHash, meaning childHash depends on parentHash.
   *
   * The edge means: parentHash -> childHash (parent has childHash as dependent,
   * childHash has parentHash as dependency).
   */
  registerDependency(parentHash: HashHex, childHash: HashHex): void {
    const parent = this.ensureNode(parentHash);
    const child = this.ensureNode(childHash);

    if (!parent.dependents.includes(childHash)) {
      parent.dependents.push(childHash);
    }
    if (!child.dependencies.includes(parentHash)) {
      child.dependencies.push(parentHash);
    }
  }

  /**
   * Process a breach attestation:
   * 1. Verify the attestation cryptographically
   * 2. Update the violator's trust status based on severity
   * 3. BFS-propagate degraded status to all transitive dependents
   * 4. Emit BreachEvents for every affected node
   * 5. Notify all registered listeners
   */
  async processBreach(attestation: BreachAttestation): Promise<BreachEvent[]> {
    // Step 1: Verify attestation
    const valid = await verifyBreachAttestation(attestation);
    if (!valid) {
      throw new Error('Invalid breach attestation: verification failed');
    }

    const events: BreachEvent[] = [];
    const violatorHash = attestation.violatorIdentityHash;
    const violator = this.ensureNode(violatorHash);

    // Step 2: Update violator status
    const previousStatus = violator.status;
    const newViolatorStatus = statusForSeverity(attestation.severity);

    // Apply the worse of current and new status
    violator.status = worseStatus(violator.status, newViolatorStatus);
    violator.breachCount += 1;
    violator.lastBreachAt = attestation.reportedAt;

    // Create event for the violator (depth 0)
    events.push({
      attestation,
      affectedAgent: violatorHash,
      previousStatus,
      newStatus: violator.status,
      propagationDepth: 0,
    });

    // Step 3: BFS propagation to dependents
    // Each level degrades by one step from the status applied at the parent level
    const visited = new Set<HashHex>([violatorHash]);

    // BFS queue entries: [nodeHash, statusToPropagateFromParent, depth]
    interface QueueEntry {
      hash: HashHex;
      parentAppliedStatus: TrustStatus;
      depth: number;
    }

    const queue: QueueEntry[] = [];

    // Seed the queue with the violator's dependents
    for (const depHash of violator.dependents) {
      if (!visited.has(depHash)) {
        queue.push({
          hash: depHash,
          parentAppliedStatus: violator.status,
          depth: 1,
        });
      }
    }

    while (queue.length > 0) {
      const entry = queue.shift()!;
      if (visited.has(entry.hash)) {
        continue;
      }
      visited.add(entry.hash);

      // Degrade by one level from the parent's applied status
      const degraded = degradeStatus(entry.parentAppliedStatus);
      if (degraded === null) {
        // No further degradation possible (parent was degraded or trusted)
        continue;
      }

      const node = this.ensureNode(entry.hash);
      const prevNodeStatus = node.status;

      // Only apply if it makes things worse
      const appliedStatus = worseStatus(node.status, degraded);
      if (appliedStatus === prevNodeStatus) {
        // Status didn't change, but still need to propagate through dependents
        // if the degraded status could affect nodes further down
      }
      node.status = appliedStatus;

      events.push({
        attestation,
        affectedAgent: entry.hash,
        previousStatus: prevNodeStatus,
        newStatus: node.status,
        propagationDepth: entry.depth,
      });

      // Enqueue this node's dependents for further propagation
      for (const depHash of node.dependents) {
        if (!visited.has(depHash)) {
          queue.push({
            hash: depHash,
            parentAppliedStatus: appliedStatus,
            depth: entry.depth + 1,
          });
        }
      }
    }

    // Step 5: Notify all listeners
    for (const listener of this.listeners) {
      for (const event of events) {
        listener(event);
      }
    }

    return events;
  }

  /**
   * Get the trust status of a node, or 'unknown' if not in the graph.
   */
  getStatus(identityHash: HashHex): TrustStatus {
    const node = this.nodes.get(identityHash);
    return node ? node.status : 'unknown';
  }

  /**
   * Check whether a node is fully trusted.
   */
  isTrusted(identityHash: HashHex): boolean {
    return this.getStatus(identityHash) === 'trusted';
  }

  /**
   * Get all transitive dependents of a node via BFS.
   */
  getDependents(identityHash: HashHex): HashHex[] {
    const result: HashHex[] = [];
    const visited = new Set<HashHex>([identityHash]);
    const queue: HashHex[] = [];

    const startNode = this.nodes.get(identityHash);
    if (!startNode) {
      return result;
    }

    for (const dep of startNode.dependents) {
      if (!visited.has(dep)) {
        queue.push(dep);
        visited.add(dep);
      }
    }

    while (queue.length > 0) {
      const current = queue.shift()!;
      result.push(current);

      const node = this.nodes.get(current);
      if (node) {
        for (const dep of node.dependents) {
          if (!visited.has(dep)) {
            queue.push(dep);
            visited.add(dep);
          }
        }
      }
    }

    return result;
  }

  /**
   * Get all direct dependencies of a node.
   */
  getDependencies(identityHash: HashHex): HashHex[] {
    const node = this.nodes.get(identityHash);
    return node ? [...node.dependencies] : [];
  }

  /**
   * Get a node by its identity hash, or undefined if not in the graph.
   */
  getNode(identityHash: HashHex): TrustNode | undefined {
    const node = this.nodes.get(identityHash);
    if (!node) {
      return undefined;
    }
    // Return a shallow copy to prevent external mutation of arrays
    return {
      ...node,
      dependents: [...node.dependents],
      dependencies: [...node.dependencies],
    };
  }

  /**
   * Manually reset a node's trust status.
   */
  resetStatus(identityHash: HashHex, newStatus: TrustStatus): void {
    const node = this.nodes.get(identityHash);
    if (node) {
      node.status = newStatus;
    }
  }

  /**
   * Register a listener that is called for each BreachEvent during processBreach.
   */
  onBreach(listener: (event: BreachEvent) => void): void {
    this.listeners.add(listener);
  }

  /**
   * Remove a previously registered breach listener.
   */
  offBreach(listener: (event: BreachEvent) => void): void {
    this.listeners.delete(listener);
  }

  /**
   * Export the full graph as nodes and edges for serialization or visualization.
   */
  export(): {
    nodes: TrustNode[];
    edges: Array<{ from: HashHex; to: HashHex }>;
  } {
    const nodes: TrustNode[] = [];
    const edges: Array<{ from: HashHex; to: HashHex }> = [];

    for (const node of this.nodes.values()) {
      nodes.push({
        ...node,
        dependents: [...node.dependents],
        dependencies: [...node.dependencies],
      });
      for (const dep of node.dependents) {
        edges.push({ from: node.identityHash, to: dep });
      }
    }

    return { nodes, edges };
  }
}

// ---------------------------------------------------------------------------
// Exponential Trust Degradation
// ---------------------------------------------------------------------------

/**
 * Configuration for exponential trust degradation across graph hops.
 */
export interface ExponentialDegradationConfig {
  /** Base trust loss at the breach origin (hop 0). Must be in (0, 1]. */
  baseLoss: number;
  /** Decay rate constant. Higher lambda = faster decay over hops. Must be > 0. */
  lambda: number;
}

/**
 * Computes trust loss that decays exponentially over graph hops.
 *
 * The trust loss at a given hop distance is:
 *   loss = baseLoss * e^(-lambda * hopDistance)
 *
 * This models the intuition that entities closer to a breach source
 * should experience greater trust degradation than distant ones.
 * At hop 0 (the violator) the full baseLoss applies; at large hop
 * distances the loss asymptotically approaches zero.
 */
export class ExponentialDegradation {
  private readonly baseLoss: number;
  private readonly lambda: number;

  constructor(config: ExponentialDegradationConfig) {
    if (config.baseLoss <= 0 || config.baseLoss > 1) {
      throw new KervyxError(
        'ExponentialDegradation baseLoss must be in (0, 1]',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (config.lambda <= 0) {
      throw new KervyxError(
        'ExponentialDegradation lambda must be > 0',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.baseLoss = config.baseLoss;
    this.lambda = config.lambda;
  }

  /**
   * Compute trust loss at a given hop distance.
   * @param hopDistance - Non-negative integer hop count from breach origin.
   * @returns Trust loss in [0, baseLoss], decaying exponentially.
   */
  computeLoss(hopDistance: number): number {
    if (hopDistance < 0 || !Number.isFinite(hopDistance)) {
      throw new KervyxError(
        'hopDistance must be a non-negative finite number',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    return this.baseLoss * Math.exp(-this.lambda * hopDistance);
  }

  /**
   * Compute resulting trust score after degradation.
   * @param currentTrust - Current trust value in [0, 1].
   * @param hopDistance - Distance from breach origin.
   * @returns New trust value, clamped to [0, 1].
   */
  degrade(currentTrust: number, hopDistance: number): number {
    if (currentTrust < 0 || currentTrust > 1) {
      throw new KervyxError(
        'currentTrust must be in [0, 1]',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    const loss = this.computeLoss(hopDistance);
    return Math.max(0, Math.min(1, currentTrust - loss));
  }

  /**
   * Compute a full degradation profile for hops 0..maxHops.
   * Returns an array where index i is the trust loss at hop i.
   */
  profile(maxHops: number): number[] {
    if (maxHops < 0 || !Number.isInteger(maxHops)) {
      throw new KervyxError(
        'maxHops must be a non-negative integer',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    const result: number[] = [];
    for (let i = 0; i <= maxHops; i++) {
      result.push(this.computeLoss(i));
    }
    return result;
  }

  /**
   * Find the hop distance at which trust loss drops below a threshold.
   * Useful for determining the effective blast radius of a breach.
   * @param threshold - Minimum trust loss to consider significant.
   * @returns The maximum hop distance where loss >= threshold, or 0 if baseLoss < threshold.
   */
  effectiveRadius(threshold: number): number {
    if (threshold <= 0 || threshold > 1) {
      throw new KervyxError(
        'threshold must be in (0, 1]',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.baseLoss < threshold) {
      return 0;
    }
    // Solve: baseLoss * e^(-lambda * d) = threshold
    // d = -ln(threshold / baseLoss) / lambda
    return Math.floor(-Math.log(threshold / this.baseLoss) / this.lambda);
  }
}

// ---------------------------------------------------------------------------
// Breach State Machine
// ---------------------------------------------------------------------------

/** Valid states in the breach lifecycle. */
export type BreachState = 'detected' | 'confirmed' | 'remediated' | 'recovered';

/** Evidence attached to a breach state transition. */
export interface BreachEvidence {
  /** Type of evidence (e.g., 'log', 'attestation', 'audit'). */
  type: string;
  /** Hash of the evidence content. */
  hash: string;
  /** Human-readable description. */
  description: string;
}

/** Record of a single state transition in the breach lifecycle. */
export interface BreachTransition {
  from: BreachState;
  to: BreachState;
  timestamp: number;
  evidence: BreachEvidence[];
  actor: string;
}

/** Configuration for breach state machine timeouts. */
export interface BreachStateMachineConfig {
  /** Max milliseconds in 'detected' before auto-confirming. 0 = no timeout. */
  detectedTimeoutMs: number;
  /** Max milliseconds in 'confirmed' before requiring remediation. 0 = no timeout. */
  confirmedTimeoutMs: number;
  /** Max milliseconds in 'remediated' before auto-recovering. 0 = no timeout. */
  remediatedTimeoutMs: number;
}

const VALID_TRANSITIONS: Record<BreachState, BreachState[]> = {
  detected: ['confirmed'],
  confirmed: ['remediated'],
  remediated: ['recovered'],
  recovered: [],
};

/**
 * Tracks the lifecycle of a breach through well-defined states:
 * DETECTED -> CONFIRMED -> REMEDIATED -> RECOVERED.
 *
 * Each transition records a timestamp, evidence, and the actor performing
 * the transition. Optional timeout-based auto-transitions allow the state
 * machine to advance when human intervention is delayed.
 */
export class BreachStateMachine {
  private _state: BreachState = 'detected';
  private readonly transitions: BreachTransition[] = [];
  private readonly stateTimestamps: Map<BreachState, number> = new Map();
  private readonly config: BreachStateMachineConfig;
  private readonly breachId: string;

  constructor(breachId: string, config?: Partial<BreachStateMachineConfig>) {
    if (!breachId || breachId.trim().length === 0) {
      throw new KervyxError(
        'breachId must be a non-empty string',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.breachId = breachId;
    this.config = {
      detectedTimeoutMs: config?.detectedTimeoutMs ?? 0,
      confirmedTimeoutMs: config?.confirmedTimeoutMs ?? 0,
      remediatedTimeoutMs: config?.remediatedTimeoutMs ?? 0,
    };
    this.stateTimestamps.set('detected', Date.now());
  }

  /** Current state of the breach. */
  get state(): BreachState {
    return this._state;
  }

  /** The breach identifier. */
  get id(): string {
    return this.breachId;
  }

  /** All transitions that have occurred. */
  getTransitions(): ReadonlyArray<BreachTransition> {
    return [...this.transitions];
  }

  /** Timestamp when the breach entered a given state, or undefined. */
  getStateTimestamp(state: BreachState): number | undefined {
    return this.stateTimestamps.get(state);
  }

  /** Duration in ms that the breach has been in the current state. */
  timeInCurrentState(): number {
    const entered = this.stateTimestamps.get(this._state);
    if (entered === undefined) return 0;
    return Date.now() - entered;
  }

  /**
   * Attempt a state transition.
   * @param to - Target state.
   * @param actor - Identifier of the entity performing the transition.
   * @param evidence - Evidence supporting the transition.
   * @throws KervyxError if the transition is invalid.
   */
  transition(to: BreachState, actor: string, evidence: BreachEvidence[] = []): void {
    const allowedTargets = VALID_TRANSITIONS[this._state];
    if (!allowedTargets.includes(to)) {
      throw new KervyxError(
        `Invalid breach state transition: ${this._state} -> ${to}. Allowed: [${allowedTargets.join(', ')}]`,
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (!actor || actor.trim().length === 0) {
      throw new KervyxError(
        'actor must be a non-empty string',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    const now = Date.now();
    const from = this._state;
    this.transitions.push({ from, to, timestamp: now, evidence, actor });
    this._state = to;
    this.stateTimestamps.set(to, now);
  }

  /**
   * Check timeout-based auto-transitions and apply them.
   * Returns the new state if an auto-transition occurred, or null.
   */
  checkTimeouts(autoActor: string = 'system:timeout'): BreachState | null {
    const elapsed = this.timeInCurrentState();

    if (
      this._state === 'detected' &&
      this.config.detectedTimeoutMs > 0 &&
      elapsed >= this.config.detectedTimeoutMs
    ) {
      this.transition('confirmed', autoActor, [
        { type: 'timeout', hash: '', description: `Auto-confirmed after ${elapsed}ms timeout` },
      ]);
      return 'confirmed';
    }

    if (
      this._state === 'confirmed' &&
      this.config.confirmedTimeoutMs > 0 &&
      elapsed >= this.config.confirmedTimeoutMs
    ) {
      this.transition('remediated', autoActor, [
        { type: 'timeout', hash: '', description: `Auto-remediated after ${elapsed}ms timeout` },
      ]);
      return 'remediated';
    }

    if (
      this._state === 'remediated' &&
      this.config.remediatedTimeoutMs > 0 &&
      elapsed >= this.config.remediatedTimeoutMs
    ) {
      this.transition('recovered', autoActor, [
        { type: 'timeout', hash: '', description: `Auto-recovered after ${elapsed}ms timeout` },
      ]);
      return 'recovered';
    }

    return null;
  }

  /** Whether the breach lifecycle is complete. */
  isResolved(): boolean {
    return this._state === 'recovered';
  }
}

// ---------------------------------------------------------------------------
// Reputation Recovery Model
// ---------------------------------------------------------------------------

/** Configuration for the logistic recovery curve. */
export interface RecoveryModelConfig {
  /** Maximum achievable trust after recovery (0, 1]. */
  maxRecovery: number;
  /** Steepness of the logistic curve. Higher = faster mid-phase recovery. Must be > 0. */
  steepness: number;
  /** Time offset (in ms) at which recovery reaches 50% of maxRecovery. Must be > 0. */
  midpointMs: number;
}

/**
 * Models trust recovery over time after a breach using a logistic curve.
 *
 * The recovery function is:
 *   trust(t) = preBreach * maxRecovery * L(t)
 *
 * where L(t) is the logistic function:
 *   L(t) = 1 / (1 + e^(-steepness * (t - midpoint)))
 *
 * The logistic curve is parameterized by breach severity (which scales
 * maxRecovery down) and the agent's historical reliability (which
 * adjusts the steepness, rewarding agents with better track records
 * with faster recovery).
 */
export class RecoveryModel {
  private readonly config: RecoveryModelConfig;

  constructor(config: RecoveryModelConfig) {
    if (config.maxRecovery <= 0 || config.maxRecovery > 1) {
      throw new KervyxError(
        'maxRecovery must be in (0, 1]',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (config.steepness <= 0) {
      throw new KervyxError(
        'steepness must be > 0',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (config.midpointMs <= 0) {
      throw new KervyxError(
        'midpointMs must be > 0',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    this.config = { ...config };
  }

  /**
   * Compute the recovery fraction at a given time since breach resolution.
   * @param elapsedMs - Time elapsed since the breach was resolved.
   * @returns Recovery fraction in [0, maxRecovery].
   */
  recoveryFraction(elapsedMs: number): number {
    if (elapsedMs < 0) {
      throw new KervyxError(
        'elapsedMs must be non-negative',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    const { maxRecovery, steepness, midpointMs } = this.config;
    const logistic = 1 / (1 + Math.exp(-steepness * (elapsedMs - midpointMs)));
    return maxRecovery * logistic;
  }

  /**
   * Compute the recovered trust score for an agent.
   *
   * @param preBreachTrust - Trust level before the breach (0, 1].
   * @param severity - Breach severity, used to scale down max recovery.
   * @param historicalReliability - Agent's historical reliability [0, 1].
   *        Higher reliability accelerates recovery (steepness multiplier).
   * @param elapsedMs - Time elapsed since breach resolution.
   * @returns Recovered trust value in [0, preBreachTrust * maxRecovery].
   */
  computeRecovery(
    preBreachTrust: number,
    severity: Severity,
    historicalReliability: number,
    elapsedMs: number,
  ): number {
    if (preBreachTrust < 0 || preBreachTrust > 1) {
      throw new KervyxError(
        'preBreachTrust must be in [0, 1]',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (historicalReliability < 0 || historicalReliability > 1) {
      throw new KervyxError(
        'historicalReliability must be in [0, 1]',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (elapsedMs < 0) {
      throw new KervyxError(
        'elapsedMs must be non-negative',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }

    // Severity scales down the ceiling of recovery
    const severityMultiplier = severityToRecoveryMultiplier(severity);

    // Historical reliability accelerates the recovery curve
    // Agents with 100% reliability recover at configured steepness;
    // agents with 0% reliability recover at 25% of configured steepness.
    const reliabilityMultiplier = 0.25 + 0.75 * historicalReliability;

    const { maxRecovery, steepness, midpointMs } = this.config;
    const adjustedSteepness = steepness * reliabilityMultiplier;
    const effectiveMax = maxRecovery * severityMultiplier;

    const logistic = 1 / (1 + Math.exp(-adjustedSteepness * (elapsedMs - midpointMs)));
    return Math.max(0, Math.min(1, preBreachTrust * effectiveMax * logistic));
  }

  /**
   * Estimate the time needed to reach a target recovery fraction.
   * @param targetFraction - Desired recovery fraction in (0, maxRecovery).
   * @returns Estimated time in milliseconds, or Infinity if target is unachievable.
   */
  timeToRecover(targetFraction: number): number {
    const { maxRecovery, steepness, midpointMs } = this.config;
    if (targetFraction <= 0 || targetFraction >= maxRecovery) {
      return targetFraction <= 0 ? 0 : Infinity;
    }
    // Invert the logistic: t = midpoint - (1/steepness) * ln(maxRecovery/targetFraction - 1)
    const ratio = maxRecovery / targetFraction - 1;
    if (ratio <= 0) return Infinity;
    return midpointMs - (1 / steepness) * Math.log(ratio);
  }
}

/**
 * Map breach severity to a recovery ceiling multiplier.
 * Critical breaches allow less total recovery; low breaches allow near-full.
 */
function severityToRecoveryMultiplier(severity: Severity): number {
  switch (severity) {
    case 'critical':
      return 0.4;
    case 'high':
      return 0.6;
    case 'medium':
      return 0.8;
    case 'low':
      return 0.95;
    default:
      return 0.5;
  }
}

// ---------------------------------------------------------------------------
// Repeat Offender Detection
// ---------------------------------------------------------------------------

/** A single breach record for pattern tracking. */
export interface BreachRecord {
  /** Unique breach identifier. */
  breachId: string;
  /** Severity of the breach. */
  severity: Severity;
  /** Timestamp of the breach (ms since epoch). */
  timestamp: number;
  /** Resource that was breached. */
  resource: string;
  /** Action that caused the breach. */
  action: string;
}

/** Penalty level applied to a repeat offender. */
export type PenaltyLevel = 'none' | 'warning' | 'restriction' | 'revocation';

/** Result of repeat offender analysis for one agent. */
export interface OffenderProfile {
  /** Agent identifier. */
  agentId: string;
  /** Total number of breaches recorded. */
  totalBreaches: number;
  /** Breaches within the configured detection window. */
  recentBreaches: number;
  /** Whether breaches are escalating in severity. */
  escalating: boolean;
  /** Current penalty level. */
  penalty: PenaltyLevel;
  /** Penalty score (higher = more severe, used for progressive penalties). */
  penaltyScore: number;
  /** Dominant breach pattern (most common resource+action combination). */
  dominantPattern: string | null;
}

/** Configuration for the repeat offender detector. */
export interface RepeatOffenderConfig {
  /** Time window in ms for "recent" breaches. Default: 7 days. */
  windowMs: number;
  /** Number of recent breaches to trigger a warning. */
  warningThreshold: number;
  /** Number of recent breaches to trigger a restriction. */
  restrictionThreshold: number;
  /** Number of recent breaches to trigger revocation. */
  revocationThreshold: number;
  /** Weight applied for severity escalation (adds to penalty score). */
  escalationWeight: number;
}

const DEFAULT_OFFENDER_CONFIG: RepeatOffenderConfig = {
  windowMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  warningThreshold: 2,
  restrictionThreshold: 4,
  revocationThreshold: 7,
  escalationWeight: 1.5,
};

/**
 * Tracks breach patterns per agent, identifies escalating behavior,
 * and applies progressive penalties (warning -> restriction -> revocation).
 *
 * The detector maintains a history of breach records per agent and
 * computes a penalty score that accounts for:
 * - Frequency of recent breaches
 * - Severity escalation (each severity level has a weight)
 * - Pattern repetition (same resource+action targeted repeatedly)
 */
export class RepeatOffenderDetector {
  private readonly history: Map<string, BreachRecord[]> = new Map();
  private readonly config: RepeatOffenderConfig;

  constructor(config?: Partial<RepeatOffenderConfig>) {
    this.config = { ...DEFAULT_OFFENDER_CONFIG, ...config };
    if (this.config.warningThreshold <= 0) {
      throw new KervyxError(
        'warningThreshold must be > 0',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.config.restrictionThreshold <= this.config.warningThreshold) {
      throw new KervyxError(
        'restrictionThreshold must be > warningThreshold',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    if (this.config.revocationThreshold <= this.config.restrictionThreshold) {
      throw new KervyxError(
        'revocationThreshold must be > restrictionThreshold',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
  }

  /**
   * Record a breach for an agent.
   */
  recordBreach(agentId: string, record: BreachRecord): void {
    if (!agentId || agentId.trim().length === 0) {
      throw new KervyxError(
        'agentId must be a non-empty string',
        KervyxErrorCode.PROTOCOL_INVALID_INPUT,
      );
    }
    let records = this.history.get(agentId);
    if (!records) {
      records = [];
      this.history.set(agentId, records);
    }
    records.push({ ...record });
    // Keep sorted by timestamp for efficient window queries
    records.sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Analyze an agent's breach history and return their offender profile.
   */
  analyze(agentId: string): OffenderProfile {
    const records = this.history.get(agentId);
    if (!records || records.length === 0) {
      return {
        agentId,
        totalBreaches: 0,
        recentBreaches: 0,
        escalating: false,
        penalty: 'none',
        penaltyScore: 0,
        dominantPattern: null,
      };
    }

    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const recentRecords = records.filter((r) => r.timestamp >= windowStart);
    const recentBreaches = recentRecords.length;

    // Detect severity escalation: check if later breaches have higher severity
    const escalating = this.detectEscalation(recentRecords);

    // Compute penalty score: base from breach count + severity weights + escalation bonus
    let penaltyScore = 0;
    for (const r of recentRecords) {
      penaltyScore += severityWeight(r.severity);
    }
    if (escalating) {
      penaltyScore *= this.config.escalationWeight;
    }

    // Determine penalty level from recent breach count
    let penalty: PenaltyLevel = 'none';
    if (recentBreaches >= this.config.revocationThreshold) {
      penalty = 'revocation';
    } else if (recentBreaches >= this.config.restrictionThreshold) {
      penalty = 'restriction';
    } else if (recentBreaches >= this.config.warningThreshold) {
      penalty = 'warning';
    }

    // Find dominant pattern
    const dominantPattern = this.findDominantPattern(recentRecords);

    return {
      agentId,
      totalBreaches: records.length,
      recentBreaches,
      escalating,
      penalty,
      penaltyScore,
      dominantPattern,
    };
  }

  /**
   * Return all agent IDs that currently have an active penalty.
   */
  getOffenders(): string[] {
    const result: string[] = [];
    for (const agentId of this.history.keys()) {
      const profile = this.analyze(agentId);
      if (profile.penalty !== 'none') {
        result.push(agentId);
      }
    }
    return result;
  }

  /**
   * Clear breach history for an agent (e.g., after successful remediation).
   */
  clearHistory(agentId: string): void {
    this.history.delete(agentId);
  }

  /**
   * Detect whether severity is escalating over recent breaches.
   * Escalation is detected if the weighted severity trend is positive
   * using linear regression on severity weights over time.
   */
  private detectEscalation(records: BreachRecord[]): boolean {
    if (records.length < 2) return false;

    // Use indices as x-values and severity weights as y-values
    const n = records.length;
    let sumX = 0;
    let sumY = 0;
    let sumXY = 0;
    let sumX2 = 0;

    for (let i = 0; i < n; i++) {
      const x = i;
      const y = severityWeight(records[i]!.severity);
      sumX += x;
      sumY += y;
      sumXY += x * y;
      sumX2 += x * x;
    }

    const denom = n * sumX2 - sumX * sumX;
    if (denom === 0) return false;

    // Slope of the linear regression
    const slope = (n * sumXY - sumX * sumY) / denom;
    // Positive slope means severity is increasing over time
    return slope > 0;
  }

  /**
   * Find the most common resource+action pattern in a set of breach records.
   */
  private findDominantPattern(records: BreachRecord[]): string | null {
    if (records.length === 0) return null;

    const counts = new Map<string, number>();
    for (const r of records) {
      const key = `${r.resource}:${r.action}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }

    let maxCount = 0;
    let dominant: string | null = null;
    for (const [pattern, count] of counts) {
      if (count > maxCount) {
        maxCount = count;
        dominant = pattern;
      }
    }
    return dominant;
  }
}

/**
 * Map severity to a numeric weight for penalty scoring.
 */
function severityWeight(severity: Severity): number {
  switch (severity) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'medium':
      return 2;
    case 'low':
      return 1;
    default:
      return 1;
  }
}

// ---------------------------------------------------------------------------
// Crisis Playbook
// ---------------------------------------------------------------------------

/** Severity level for incidents in the crisis playbook. */
export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical';

/** Escalation levels for incident response. */
export type EscalationLevel = 'team' | 'management' | 'executive' | 'regulator' | 'public';

/** Pre-built incident analysis template. */
export interface IncidentTemplate {
  id: string;
  name: string;
  severity: IncidentSeverity;
  category: string;
  description: string;
  immediateActions: string[];
  investigationSteps: string[];
  escalationPath: EscalationLevel[];
  communicationTemplate: string;
  estimatedResolutionHours: number;
}

/** Crisis playbook containing templates, escalation matrix, and SLAs. */
export interface CrisisPlaybook {
  templates: IncidentTemplate[];
  escalationMatrix: Record<IncidentSeverity, EscalationLevel[]>;
  responseTimeSLA: Record<IncidentSeverity, number>; // minutes
}

/** Report tracking the lifecycle of an incident. */
export interface IncidentReport {
  id: string;
  template: IncidentTemplate;
  agentId: string;
  timestamp: number;
  status: 'detected' | 'investigating' | 'contained' | 'resolved' | 'post_mortem';
  timeline: Array<{ action: string; timestamp: number; actor: string }>;
  rootCause?: string;
  lessonsLearned?: string[];
}

/**
 * Create a crisis playbook with 5 standard incident templates and
 * pre-configured escalation matrix and response time SLAs.
 */
export function createPlaybook(): CrisisPlaybook {
  const templates: IncidentTemplate[] = [
    {
      id: 'data_breach',
      name: 'Data Breach',
      severity: 'critical',
      category: 'data_breach',
      description: 'Unauthorized data access detected',
      immediateActions: [
        'Isolate affected systems',
        'Revoke compromised credentials',
        'Preserve forensic evidence',
        'Notify security team',
      ],
      investigationSteps: [
        'Identify scope of data exposure',
        'Determine attack vector',
        'Assess data sensitivity',
        'Review access logs',
        'Identify affected parties',
      ],
      escalationPath: ['team', 'management', 'executive', 'regulator'],
      communicationTemplate: 'A data breach has been detected involving unauthorized access to sensitive data. Immediate containment measures are in progress. Affected parties will be notified within the regulatory timeline.',
      estimatedResolutionHours: 24,
    },
    {
      id: 'covenant_violation',
      name: 'Covenant Violation',
      severity: 'high',
      category: 'covenant_violation',
      description: 'Agent exceeded covenant bounds',
      immediateActions: [
        'Restrict agent permissions',
        'Log violation details',
        'Notify covenant stakeholders',
      ],
      investigationSteps: [
        'Review agent action logs',
        'Compare actions against covenant constraints',
        'Assess impact of violation',
        'Determine if intentional or accidental',
      ],
      escalationPath: ['team', 'management', 'executive'],
      communicationTemplate: 'A covenant violation has been detected. The agent has been restricted while the violation is being investigated. Stakeholders will be updated with findings.',
      estimatedResolutionHours: 8,
    },
    {
      id: 'key_compromise',
      name: 'Key Compromise',
      severity: 'critical',
      category: 'key_compromise',
      description: 'Signing key potentially compromised',
      immediateActions: [
        'Rotate all affected keys immediately',
        'Revoke compromised key attestations',
        'Audit all actions signed with compromised key',
        'Enable enhanced monitoring',
      ],
      investigationSteps: [
        'Determine how the key was compromised',
        'Identify all documents signed with compromised key',
        'Verify integrity of affected covenants',
        'Assess downstream impact',
      ],
      escalationPath: ['team', 'management', 'executive', 'regulator'],
      communicationTemplate: 'A signing key compromise has been detected. All affected keys have been rotated and compromised attestations revoked. A full audit of signed documents is underway.',
      estimatedResolutionHours: 12,
    },
    {
      id: 'cascade_failure',
      name: 'Cascade Failure',
      severity: 'high',
      category: 'cascade_failure',
      description: 'Multiple agents failing simultaneously',
      immediateActions: [
        'Activate circuit breakers',
        'Isolate failing agents',
        'Enable fallback procedures',
      ],
      investigationSteps: [
        'Identify root cause of cascade',
        'Map failure propagation path',
        'Assess system-wide impact',
        'Review dependency graph',
      ],
      escalationPath: ['team', 'management', 'executive'],
      communicationTemplate: 'A cascade failure has been detected affecting multiple agents. Circuit breakers have been activated and failing agents isolated. Root cause analysis is in progress.',
      estimatedResolutionHours: 6,
    },
    {
      id: 'compliance_gap',
      name: 'Compliance Gap',
      severity: 'medium',
      category: 'compliance_gap',
      description: 'Regulatory requirement not met',
      immediateActions: [
        'Document the compliance gap',
        'Assess regulatory exposure',
        'Begin remediation planning',
      ],
      investigationSteps: [
        'Identify specific regulatory requirements not met',
        'Determine timeline for compliance',
        'Evaluate remediation options',
        'Estimate cost and effort',
      ],
      escalationPath: ['team', 'management'],
      communicationTemplate: 'A compliance gap has been identified. A remediation plan is being developed to address the regulatory requirement. Timeline and impact assessment will follow.',
      estimatedResolutionHours: 48,
    },
  ];

  const escalationMatrix: Record<IncidentSeverity, EscalationLevel[]> = {
    low: ['team'],
    medium: ['team', 'management'],
    high: ['team', 'management', 'executive'],
    critical: ['team', 'management', 'executive', 'regulator'],
  };

  const responseTimeSLA: Record<IncidentSeverity, number> = {
    low: 480,
    medium: 120,
    high: 60,
    critical: 15,
  };

  return { templates, escalationMatrix, responseTimeSLA };
}

/**
 * Find the best matching incident template by category first, then severity.
 *
 * @param playbook - The crisis playbook to search.
 * @param params - Matching criteria (category, severity, description).
 * @returns The best matching template, or null if no match is found.
 */
export function matchIncident(
  playbook: CrisisPlaybook,
  params: {
    category?: string;
    severity?: IncidentSeverity;
    description?: string;
  },
): IncidentTemplate | null {
  let candidates = playbook.templates;

  // Filter by category first (exact match)
  if (params.category) {
    const categoryMatches = candidates.filter(t => t.category === params.category);
    if (categoryMatches.length > 0) {
      candidates = categoryMatches;
    }
  }

  // Filter by severity
  if (params.severity) {
    const severityMatches = candidates.filter(t => t.severity === params.severity);
    if (severityMatches.length > 0) {
      candidates = severityMatches;
    }
  }

  // Filter by description (substring match)
  if (params.description) {
    const descLower = params.description.toLowerCase();
    const descMatches = candidates.filter(
      t => t.description.toLowerCase().includes(descLower) ||
           t.name.toLowerCase().includes(descLower),
    );
    if (descMatches.length > 0) {
      candidates = descMatches;
    }
  }

  return candidates.length > 0 ? candidates[0]! : null;
}

/**
 * Create an incident report from a template.
 *
 * @param template - The incident template to base the report on.
 * @param agentId - The ID of the agent involved.
 * @returns A new incident report with status 'detected' and initial timeline entry.
 */
export function createIncidentReport(
  template: IncidentTemplate,
  agentId: string,
): IncidentReport {
  const now = Date.now();
  return {
    id: `incident-${now}-${agentId}`,
    template,
    agentId,
    timestamp: now,
    status: 'detected',
    timeline: [
      {
        action: `Incident detected: ${template.name}`,
        timestamp: now,
        actor: 'system',
      },
    ],
  };
}

/**
 * Escalate an incident by looking up the escalation path and response deadline.
 *
 * @param report - The incident report to escalate.
 * @param playbook - The crisis playbook for escalation rules.
 * @returns The updated report, notification levels, and deadline.
 */
export function escalateIncident(
  report: IncidentReport,
  playbook: CrisisPlaybook,
): {
  report: IncidentReport;
  notifyLevels: EscalationLevel[];
  deadlineMinutes: number;
} {
  const severity = report.template.severity;
  const notifyLevels = playbook.escalationMatrix[severity] ?? ['team'];
  const deadlineMinutes = playbook.responseTimeSLA[severity] ?? 480;

  const now = Date.now();
  const updatedReport: IncidentReport = {
    ...report,
    status: 'investigating',
    timeline: [
      ...report.timeline,
      {
        action: `Incident escalated to: ${notifyLevels.join(', ')}`,
        timestamp: now,
        actor: 'system',
      },
    ],
  };

  return {
    report: updatedReport,
    notifyLevels,
    deadlineMinutes,
  };
}

/**
 * Resolve an incident by setting root cause and lessons learned.
 *
 * @param report - The incident report to resolve.
 * @param params - Resolution details including root cause and lessons learned.
 * @returns The resolved incident report.
 */
export function resolveIncident(
  report: IncidentReport,
  params: {
    rootCause: string;
    lessonsLearned: string[];
  },
): IncidentReport {
  const now = Date.now();
  return {
    ...report,
    status: 'resolved',
    rootCause: params.rootCause,
    lessonsLearned: params.lessonsLearned,
    timeline: [
      ...report.timeline,
      {
        action: `Incident resolved. Root cause: ${params.rootCause}`,
        timestamp: now,
        actor: 'system',
      },
    ],
  };
}
