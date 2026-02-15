import { sha256Object, generateId } from '@stele/crypto';
import { SteleError, SteleErrorCode } from '@stele/types';

export type {
  TriggerType,
  TriggerAction,
  EvolutionPolicy,
  EvolutionTrigger,
  TransitionFunction,
  EvolutionEvent,
  AgentState,
  CovenantState,
  DecayPoint,
  ViolationRecord,
  ExpirationForecastResult,
} from './types';

import type {
  TriggerType,
  TriggerAction,
  EvolutionPolicy,
  EvolutionTrigger,
  TransitionFunction,
  EvolutionEvent,
  AgentState,
  CovenantState,
  DecayPoint,
  ViolationRecord,
  ExpirationForecastResult,
} from './types';

const VALID_TRIGGER_TYPES: TriggerType[] = [
  'capability_change',
  'time_elapsed',
  'reputation_threshold',
  'breach_event',
  'governance_vote',
];

const VALID_TRIGGER_ACTIONS: TriggerAction[] = [
  'tighten',
  'relax',
  'add_constraint',
  'remove_constraint',
];

/**
 * Validate a single trigger's condition format. Throws on malformed conditions.
 */
function validateTriggerCondition(trigger: EvolutionTrigger): void {
  if (!trigger.type || !VALID_TRIGGER_TYPES.includes(trigger.type)) {
    throw new Error(`Invalid trigger type: ${trigger.type}`);
  }
  if (!trigger.action || !VALID_TRIGGER_ACTIONS.includes(trigger.action)) {
    throw new Error(`Invalid trigger action: ${trigger.action}`);
  }
  if (typeof trigger.condition !== 'string') {
    throw new Error('Trigger condition must be a string');
  }

  switch (trigger.type) {
    case 'time_elapsed': {
      const conditionMs = parseFloat(trigger.condition);
      if (isNaN(conditionMs) || conditionMs < 0) {
        throw new Error(
          `Invalid time_elapsed condition: "${trigger.condition}". Must be a non-negative number (milliseconds).`,
        );
      }
      break;
    }
    case 'reputation_threshold': {
      const match = trigger.condition.match(/^([><]=?)(\d+(?:\.\d+)?)$/);
      if (!match) {
        throw new Error(
          `Invalid reputation_threshold condition: "${trigger.condition}". Must be ">N", "<N", ">=N", or "<=N".`,
        );
      }
      break;
    }
    case 'breach_event': {
      // breach_event accepts any condition string (e.g. 'any')
      if (trigger.condition.length === 0) {
        throw new Error('breach_event condition must not be empty');
      }
      break;
    }
    case 'capability_change': {
      // Must be a comma-separated list, possibly empty (meaning "no capabilities expected")
      // but the string itself must be present
      if (typeof trigger.condition !== 'string') {
        throw new Error('capability_change condition must be a string');
      }
      break;
    }
    case 'governance_vote': {
      if (trigger.condition.length === 0) {
        throw new Error('governance_vote condition must not be empty (should be proposal ID)');
      }
      break;
    }
  }
}

/**
 * Validate a transition function. Throws on invalid values.
 */
function validateTransition(transition: TransitionFunction): void {
  if (!transition.fromConstraint || typeof transition.fromConstraint !== 'string') {
    throw new Error('Transition fromConstraint must be a non-empty string');
  }
  if (!transition.toConstraint || typeof transition.toConstraint !== 'string') {
    throw new Error('Transition toConstraint must be a non-empty string');
  }
  if (typeof transition.cooldown !== 'number' || transition.cooldown < 0) {
    throw new Error(`Transition cooldown must be a non-negative number, got: ${transition.cooldown}`);
  }
}

/**
 * Create an EvolutionPolicy for a covenant.
 * Validates all triggers and transitions before creating the policy.
 */
export function defineEvolution(
  covenantId: string,
  triggers: EvolutionTrigger[],
  transitions: TransitionFunction[],
  governanceApproval: boolean = false,
): EvolutionPolicy {
  if (!covenantId || typeof covenantId !== 'string') {
    throw new Error('covenantId must be a non-empty string');
  }

  for (const trigger of triggers) {
    validateTriggerCondition(trigger);
  }

  for (const transition of transitions) {
    validateTransition(transition);
  }

  return {
    covenantId,
    triggers,
    transitions,
    governanceApproval,
  };
}

/**
 * Evaluate all triggers in the covenant's policy against the current agent state.
 * Returns an array of EvolutionTriggers that have fired.
 *
 * Trigger evaluation rules:
 *  - time_elapsed: condition is a number (ms). Fires if currentTime - lastTransitionAt > conditionMs.
 *  - reputation_threshold: condition is '>N', '<N', '>=N', or '<=N'. Fires if reputation matches.
 *  - breach_event: fires if agentState.breachCount > 0.
 *  - capability_change: condition is a comma-separated list of expected capabilities.
 *    Fires if the agent's current capabilities differ from the expected set.
 *  - governance_vote: fires if governanceVotes exist and the trigger's condition key is voted true.
 *
 * Throws on malformed conditions instead of silently ignoring them.
 * Validates that agentState fields exist before evaluating triggers.
 */
export function evaluateTriggers(
  covenant: CovenantState,
  agentState: AgentState,
): EvolutionTrigger[] {
  if (!covenant.policy) return [];

  // Validate agentState fields
  if (typeof agentState.reputationScore !== 'number') {
    throw new Error('agentState.reputationScore must be a number');
  }
  if (!Array.isArray(agentState.capabilities)) {
    throw new Error('agentState.capabilities must be an array');
  }
  if (typeof agentState.breachCount !== 'number') {
    throw new Error('agentState.breachCount must be a number');
  }
  if (typeof agentState.currentTime !== 'number') {
    throw new Error('agentState.currentTime must be a number');
  }

  const fired: EvolutionTrigger[] = [];

  for (const trigger of covenant.policy.triggers) {
    switch (trigger.type) {
      case 'time_elapsed': {
        const conditionMs = parseFloat(trigger.condition);
        if (isNaN(conditionMs)) {
          throw new Error(
            `Malformed time_elapsed condition: "${trigger.condition}". Expected a number.`,
          );
        }
        const lastTransition = covenant.lastTransitionAt ?? 0;
        if (agentState.currentTime - lastTransition > conditionMs) {
          fired.push(trigger);
        }
        break;
      }
      case 'reputation_threshold': {
        const match = trigger.condition.match(/^([><]=?)(\d+(?:\.\d+)?)$/);
        if (!match) {
          throw new Error(
            `Malformed reputation_threshold condition: "${trigger.condition}". Expected ">N", "<N", ">=N", or "<=N".`,
          );
        }
        const operator = match[1]!;
        const threshold = parseFloat(match[2]!);
        if (operator === '>' && agentState.reputationScore > threshold) {
          fired.push(trigger);
        } else if (operator === '<' && agentState.reputationScore < threshold) {
          fired.push(trigger);
        } else if (operator === '>=' && agentState.reputationScore >= threshold) {
          fired.push(trigger);
        } else if (operator === '<=' && agentState.reputationScore <= threshold) {
          fired.push(trigger);
        }
        break;
      }
      case 'breach_event': {
        if (agentState.breachCount > 0) {
          fired.push(trigger);
        }
        break;
      }
      case 'capability_change': {
        const expected = trigger.condition
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s.length > 0)
          .sort();
        const actual = [...agentState.capabilities].sort();
        const differs =
          expected.length !== actual.length ||
          expected.some((cap, i) => cap !== actual[i]);
        if (differs) {
          fired.push(trigger);
        }
        break;
      }
      case 'governance_vote': {
        if (
          agentState.governanceVotes &&
          agentState.governanceVotes[trigger.condition] === true
        ) {
          fired.push(trigger);
        }
        break;
      }
      default: {
        throw new Error(`Unknown trigger type: ${(trigger as EvolutionTrigger).type}`);
      }
    }
  }

  return fired;
}

/**
 * Check whether a trigger can be applied to a covenant, respecting cooldown
 * periods and governance approval requirements.
 *
 * Cooldown check: matches transitions by fromConstraint/toConstraint
 * against the covenant's current constraints, not by trigger vs condition.
 */
export function canEvolve(covenant: CovenantState, trigger: EvolutionTrigger): boolean {
  if (!covenant.policy) return false;

  // Check governance approval requirement
  if (covenant.policy.governanceApproval) {
    if (trigger.type !== 'governance_vote') {
      return false;
    }
  }

  // Check cooldown: find matching transitions by fromConstraint/toConstraint
  // A transition matches if its fromConstraint is in the current constraints
  // and its toConstraint matches the trigger's constraintId (or action target).
  const now = Date.now();
  const lastTransition = covenant.lastTransitionAt ?? 0;

  for (const transition of covenant.policy.transitions) {
    const fromMatch = covenant.constraints.includes(transition.fromConstraint);
    const toMatch = trigger.constraintId === transition.toConstraint ||
      (trigger.action === 'tighten' && covenant.constraints.includes(transition.fromConstraint)) ||
      (trigger.action === 'relax' && trigger.constraintId === transition.fromConstraint);

    if (fromMatch && toMatch) {
      if (now - lastTransition < transition.cooldown) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Apply a trigger action to the covenant constraints.
 * Returns the updated covenant state and the evolution event.
 *
 * Actions:
 *  - tighten: add a new restriction constraint (generates a new constraint ID).
 *  - relax: remove the constraint specified by trigger.constraintId.
 *  - add_constraint: add trigger.constraintId to the constraints.
 *  - remove_constraint: remove trigger.constraintId from the constraints.
 *
 * Respects cooldown periods by checking transitions using fromConstraint/toConstraint matching.
 * If governance approval is required and trigger is not governance_vote, the event
 * is marked as not approved with governanceStatus='pending' and no changes are made.
 */
export function evolve(
  covenant: CovenantState,
  trigger: EvolutionTrigger,
): { covenant: CovenantState; event: EvolutionEvent } {
  const previousConstraints = [...covenant.constraints];
  const timestamp = Date.now();
  let approved = true;

  // Check governance approval
  if (covenant.policy?.governanceApproval && trigger.type !== 'governance_vote') {
    approved = false;
    const event: EvolutionEvent = {
      covenantId: covenant.id,
      trigger,
      previousConstraints,
      newConstraints: previousConstraints,
      timestamp,
      approved,
      governanceStatus: 'pending',
    };
    return {
      covenant: {
        ...covenant,
        history: [...covenant.history, event],
      },
      event,
    };
  }

  // Check cooldown: match transitions by fromConstraint/toConstraint
  if (covenant.policy) {
    for (const transition of covenant.policy.transitions) {
      const fromMatch = covenant.constraints.includes(transition.fromConstraint);
      const toMatch = trigger.constraintId === transition.toConstraint ||
        (trigger.action === 'tighten' && covenant.constraints.includes(transition.fromConstraint)) ||
        (trigger.action === 'relax' && trigger.constraintId === transition.fromConstraint);

      if (fromMatch && toMatch) {
        const lastTransition = covenant.lastTransitionAt ?? 0;
        if (timestamp - lastTransition < transition.cooldown) {
          approved = false;
          const event: EvolutionEvent = {
            covenantId: covenant.id,
            trigger,
            previousConstraints,
            newConstraints: previousConstraints,
            timestamp,
            approved,
          };
          return {
            covenant: {
              ...covenant,
              history: [...covenant.history, event],
            },
            event,
          };
        }
      }
    }
  }

  // Apply the action
  let newConstraints = [...previousConstraints];

  switch (trigger.action) {
    case 'tighten': {
      const newId = trigger.constraintId ?? `tightened-${generateId(8)}`;
      newConstraints.push(newId);
      break;
    }
    case 'relax': {
      if (trigger.constraintId) {
        newConstraints = newConstraints.filter((c) => c !== trigger.constraintId);
      }
      break;
    }
    case 'add_constraint': {
      if (trigger.constraintId && !newConstraints.includes(trigger.constraintId)) {
        newConstraints.push(trigger.constraintId);
      }
      break;
    }
    case 'remove_constraint': {
      if (trigger.constraintId) {
        newConstraints = newConstraints.filter((c) => c !== trigger.constraintId);
      }
      break;
    }
  }

  const governanceStatus = covenant.policy?.governanceApproval && trigger.type === 'governance_vote'
    ? 'approved' as const
    : undefined;

  const event: EvolutionEvent = {
    covenantId: covenant.id,
    trigger,
    previousConstraints,
    newConstraints,
    timestamp,
    approved: true,
    ...(governanceStatus ? { governanceStatus } : {}),
  };

  return {
    covenant: {
      ...covenant,
      constraints: newConstraints,
      history: [...covenant.history, event],
      lastTransitionAt: timestamp,
    },
    event,
  };
}

/**
 * Return the evolution history for a covenant.
 */
export function evolutionHistory(covenant: CovenantState): EvolutionEvent[] {
  return covenant.history;
}

/**
 * Compute a decay schedule showing how a covenant's enforcement weight
 * decreases over its lifetime.
 *
 * Uses an exponential decay model: value(t) = initialWeight * e^(-decayRate * t)
 *
 * The schedule is sampled at `steps` evenly-spaced time points from 0 to `lifetimeMs`.
 *
 * @param initialWeight - The starting enforcement weight (must be > 0)
 * @param decayRate - The exponential decay rate (must be >= 0). Higher = faster decay.
 * @param lifetimeMs - The total lifetime in milliseconds (must be > 0)
 * @param steps - The number of sample points (must be >= 2)
 * @returns Array of (time, value) pairs
 */
export function computeDecaySchedule(
  initialWeight: number,
  decayRate: number,
  lifetimeMs: number,
  steps: number,
): DecayPoint[] {
  if (initialWeight <= 0) {
    throw new Error('initialWeight must be positive');
  }
  if (decayRate < 0) {
    throw new Error('decayRate must be non-negative');
  }
  if (lifetimeMs <= 0) {
    throw new Error('lifetimeMs must be positive');
  }
  if (steps < 2) {
    throw new Error('steps must be at least 2');
  }

  const schedule: DecayPoint[] = [];
  const stepSize = lifetimeMs / (steps - 1);

  for (let i = 0; i < steps; i++) {
    const time = i * stepSize;
    // Normalize time to [0, 1] for the decay calculation
    const normalizedTime = time / lifetimeMs;
    const value = initialWeight * Math.exp(-decayRate * normalizedTime);
    schedule.push({ time, value });
  }

  return schedule;
}

/**
 * Predict when a covenant will functionally expire based on violation patterns.
 *
 * Analyzes the history of violations to estimate:
 * 1. The current enforcement weight (decayed from initial)
 * 2. The trend in violations (accelerating, stable, or decelerating)
 * 3. The predicted time when enforcement weight drops below a functional threshold
 *
 * The model considers:
 * - Each violation reduces the effective weight by (severity * violationImpact)
 * - Natural decay reduces weight over time via exponential decay
 * - Violation frequency trends are used to extrapolate future violations
 *
 * @param initialWeight - The starting enforcement weight (must be > 0)
 * @param decayRate - The exponential decay rate (must be >= 0)
 * @param violations - Array of violation records with timestamps and severities
 * @param currentTime - The current time in milliseconds
 * @param threshold - The weight below which the covenant is considered expired (default 0.1)
 * @param violationImpact - How much each unit of severity reduces weight (default 0.05)
 * @returns ExpirationForecastResult with predicted expiration time and metadata
 */
export function expirationForecast(
  initialWeight: number,
  decayRate: number,
  violations: ViolationRecord[],
  currentTime: number,
  threshold: number = 0.1,
  violationImpact: number = 0.05,
): ExpirationForecastResult {
  if (initialWeight <= 0) {
    throw new Error('initialWeight must be positive');
  }
  if (decayRate < 0) {
    throw new Error('decayRate must be non-negative');
  }
  if (threshold < 0 || threshold >= initialWeight) {
    throw new Error('threshold must be in [0, initialWeight)');
  }
  if (violationImpact < 0) {
    throw new Error('violationImpact must be non-negative');
  }

  // Sort violations by timestamp
  const sorted = [...violations].sort((a, b) => a.timestamp - b.timestamp);

  // Compute cumulative violation damage
  let totalViolationDamage = 0;
  for (const v of sorted) {
    if (v.timestamp <= currentTime) {
      totalViolationDamage += v.severity * violationImpact;
    }
  }

  // Compute current weight considering both natural decay and violation damage
  // Use 1 year as reference lifetime for normalization
  const referenceLifetime = 365 * 24 * 60 * 60 * 1000;
  const normalizedCurrentTime = currentTime / referenceLifetime;
  const naturalDecayWeight = initialWeight * Math.exp(-decayRate * normalizedCurrentTime);
  const remainingWeight = Math.max(0, naturalDecayWeight - totalViolationDamage);

  // Determine violation trend by comparing intervals between recent violations
  let violationTrend: 'accelerating' | 'stable' | 'decelerating' = 'stable';
  const recentViolations = sorted.filter(v => v.timestamp <= currentTime);

  if (recentViolations.length >= 3) {
    // Compare average interval of first half vs second half
    const mid = Math.floor(recentViolations.length / 2);
    const firstHalfIntervals: number[] = [];
    const secondHalfIntervals: number[] = [];

    for (let i = 1; i < recentViolations.length; i++) {
      const interval = recentViolations[i]!.timestamp - recentViolations[i - 1]!.timestamp;
      if (i <= mid) {
        firstHalfIntervals.push(interval);
      } else {
        secondHalfIntervals.push(interval);
      }
    }

    const avgFirst = firstHalfIntervals.length > 0
      ? firstHalfIntervals.reduce((a, b) => a + b, 0) / firstHalfIntervals.length
      : Infinity;
    const avgSecond = secondHalfIntervals.length > 0
      ? secondHalfIntervals.reduce((a, b) => a + b, 0) / secondHalfIntervals.length
      : Infinity;

    // If intervals are getting shorter, violations are accelerating
    if (avgSecond < avgFirst * 0.8) {
      violationTrend = 'accelerating';
    } else if (avgSecond > avgFirst * 1.2) {
      violationTrend = 'decelerating';
    }
  }

  // If already below threshold, covenant is already expired
  if (remainingWeight <= threshold) {
    return {
      predictedExpirationTime: currentTime,
      confidence: 1.0,
      remainingWeight,
      violationTrend,
    };
  }

  // Predict future expiration by projecting violation rate and natural decay
  // Estimate violation rate (violations per ms)
  let violationRate = 0;
  if (recentViolations.length >= 2) {
    const timeSpan = recentViolations[recentViolations.length - 1]!.timestamp - recentViolations[0]!.timestamp;
    if (timeSpan > 0) {
      violationRate = recentViolations.length / timeSpan;
      // Adjust rate based on trend
      if (violationTrend === 'accelerating') {
        violationRate *= 1.5;
      } else if (violationTrend === 'decelerating') {
        violationRate *= 0.7;
      }
    }
  }

  // Average severity of violations
  const avgSeverity = recentViolations.length > 0
    ? recentViolations.reduce((sum, v) => sum + v.severity, 0) / recentViolations.length
    : 0;

  // Binary search for when remaining weight hits threshold
  let low = currentTime;
  let high = currentTime + referenceLifetime * 10; // Search up to 10x reference lifetime
  const maxIterations = 100;

  for (let iter = 0; iter < maxIterations; iter++) {
    const mid = (low + high) / 2;
    const dt = mid - currentTime;

    // Project natural decay from current time
    const futureNormalizedTime = mid / referenceLifetime;
    const futureNaturalWeight = initialWeight * Math.exp(-decayRate * futureNormalizedTime);

    // Project additional violation damage
    const projectedNewViolations = violationRate * dt;
    const projectedAdditionalDamage = projectedNewViolations * avgSeverity * violationImpact;
    const projectedWeight = Math.max(0, futureNaturalWeight - totalViolationDamage - projectedAdditionalDamage);

    if (Math.abs(projectedWeight - threshold) < threshold * 0.001) {
      low = mid;
      break;
    }

    if (projectedWeight > threshold) {
      low = mid;
    } else {
      high = mid;
    }
  }

  const predictedExpirationTime = low;

  // Confidence is higher with more violation data
  const confidence = Math.min(1.0, 0.3 + 0.1 * recentViolations.length);

  return {
    predictedExpirationTime,
    confidence,
    remainingWeight,
    violationTrend,
  };
}

// ---------------------------------------------------------------------------
// Multi-Model Decay
// ---------------------------------------------------------------------------

/** Supported decay model types. */
export type DecayModelType = 'exponential' | 'linear' | 'step' | 'seasonal';

/** Configuration for a single decay model. */
export interface DecayModelConfig {
  type: DecayModelType;
  /** Decay rate for exponential, slope for linear, period for seasonal. */
  rate: number;
  /** For step: array of [time_fraction, value_multiplier] breakpoints. */
  steps?: Array<[number, number]>;
  /** For seasonal: amplitude of the seasonal component (0-1). */
  amplitude?: number;
  /** For seasonal: phase offset in radians. */
  phase?: number;
}

/**
 * DecayModel supports multiple decay functions and their composition.
 *
 * Supported models:
 * - Exponential: value(t) = e^(-rate * t)
 * - Linear: value(t) = max(0, 1 - rate * t)
 * - Step: value(t) = step_value at the highest breakpoint <= t
 * - Seasonal: value(t) = 1 + amplitude * sin(2*pi*rate*t + phase)
 *
 * Models can be composed by multiplying their outputs:
 *   composed(t) = model1(t) * model2(t) * ...
 *
 * This allows, e.g., exponential decay with a seasonal overlay.
 */
export class DecayModel {
  private models: DecayModelConfig[];

  constructor(models: DecayModelConfig[]) {
    if (models.length === 0) {
      throw new SteleError('At least one decay model is required', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    for (const m of models) {
      this.validateModel(m);
    }
    this.models = [...models];
  }

  private validateModel(model: DecayModelConfig): void {
    if (model.type === 'exponential' && model.rate < 0) {
      throw new SteleError('Exponential decay rate must be >= 0', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (model.type === 'linear' && model.rate < 0) {
      throw new SteleError('Linear decay rate must be >= 0', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (model.type === 'step') {
      if (!model.steps || model.steps.length === 0) {
        throw new SteleError('Step decay requires at least one breakpoint', SteleErrorCode.PROTOCOL_INVALID_INPUT);
      }
      for (const [t, v] of model.steps) {
        if (t < 0 || t > 1) {
          throw new SteleError(`Step time fraction must be in [0, 1], got ${t}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
        }
        if (v < 0) {
          throw new SteleError(`Step value must be >= 0, got ${v}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
        }
      }
    }
    if (model.type === 'seasonal') {
      if (model.rate <= 0) {
        throw new SteleError('Seasonal frequency (rate) must be > 0', SteleErrorCode.PROTOCOL_INVALID_INPUT);
      }
      if (model.amplitude !== undefined && (model.amplitude < 0 || model.amplitude > 1)) {
        throw new SteleError(`Seasonal amplitude must be in [0, 1], got ${model.amplitude}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
      }
    }
  }

  /**
   * Evaluate a single model at normalized time t (0 = start, 1 = end of lifetime).
   */
  private evaluateOne(model: DecayModelConfig, t: number): number {
    switch (model.type) {
      case 'exponential':
        return Math.exp(-model.rate * t);

      case 'linear':
        return Math.max(0, 1 - model.rate * t);

      case 'step': {
        // Sort steps by time fraction
        const sorted = [...model.steps!].sort((a, b) => a[0] - b[0]);
        let value = 1.0; // Default before first step
        for (const [time, val] of sorted) {
          if (t >= time) {
            value = val;
          } else {
            break;
          }
        }
        return value;
      }

      case 'seasonal': {
        const amplitude = model.amplitude ?? 0.2;
        const phase = model.phase ?? 0;
        // Seasonal oscillation centered around 1.0
        return 1.0 + amplitude * Math.sin(2 * Math.PI * model.rate * t + phase);
      }

      default:
        throw new SteleError(`Unknown decay model type: ${model.type}`, SteleErrorCode.PROTOCOL_COMPUTATION_FAILED);
    }
  }

  /**
   * Evaluate the composed decay at normalized time t.
   * All model outputs are multiplied together.
   *
   * @param t - Normalized time in [0, 1] where 0=start, 1=end of lifetime
   * @param initialWeight - Starting weight (default 1.0)
   * @returns The decayed weight value
   */
  evaluate(t: number, initialWeight: number = 1.0): number {
    if (initialWeight < 0) {
      throw new SteleError('initialWeight must be >= 0', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }

    let composedFactor = 1.0;
    for (const model of this.models) {
      composedFactor *= this.evaluateOne(model, t);
    }

    return Math.max(0, initialWeight * composedFactor);
  }

  /**
   * Generate a decay schedule sampled at evenly-spaced points.
   */
  schedule(initialWeight: number, steps: number): DecayPoint[] {
    if (steps < 2) {
      throw new SteleError('steps must be >= 2', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }

    const points: DecayPoint[] = [];
    for (let i = 0; i < steps; i++) {
      const t = i / (steps - 1);
      points.push({ time: t, value: this.evaluate(t, initialWeight) });
    }
    return points;
  }

  /**
   * Find the time fraction at which the value drops below a threshold.
   * Uses binary search.
   *
   * @returns Normalized time fraction, or null if threshold is never reached
   */
  findThresholdTime(initialWeight: number, threshold: number): number | null {
    if (threshold <= 0) return null;
    if (this.evaluate(0, initialWeight) < threshold) return 0;
    if (this.evaluate(1, initialWeight) >= threshold) return null;

    let lo = 0;
    let hi = 1;
    for (let i = 0; i < 100; i++) {
      const mid = (lo + hi) / 2;
      if (this.evaluate(mid, initialWeight) >= threshold) {
        lo = mid;
      } else {
        hi = mid;
      }
    }

    return hi;
  }
}

// ---------------------------------------------------------------------------
// Continuous Trigger Scoring
// ---------------------------------------------------------------------------

/** Configuration for a continuous trigger. */
export interface ContinuousTriggerConfig {
  /** Trigger type (same as EvolutionTrigger types). */
  type: TriggerType;
  /** Center of the sigmoid threshold. */
  threshold: number;
  /** Steepness of the sigmoid curve (higher = sharper transition). Default 10. */
  steepness?: number;
  /** Weight of this trigger in the combined score (default 1.0). */
  weight?: number;
  /** Action to take when trigger activation is high. */
  action: TriggerAction;
}

/** Result of continuous trigger evaluation. */
export interface ContinuousTriggerResult {
  /** Per-trigger activation scores (0 to 1). */
  activations: Array<{ type: TriggerType; activation: number; weight: number }>;
  /** Combined weighted score (0 to 1). */
  combinedScore: number;
  /** Whether the combined score exceeds the activation threshold. */
  activated: boolean;
  /** The activation threshold used. */
  activationThreshold: number;
}

/**
 * ContinuousTrigger replaces boolean trigger evaluation with smooth
 * sigmoid-based scoring. Instead of hard thresholds, triggers have
 * soft thresholds with configurable steepness.
 *
 * The sigmoid activation function is:
 *   sigma(x) = 1 / (1 + e^(-steepness * (x - threshold)))
 *
 * This maps any real-valued input to a score in (0, 1):
 * - At x = threshold: activation = 0.5
 * - Above threshold: activation approaches 1
 * - Below threshold: activation approaches 0
 * - Steepness controls how sharp the transition is
 */
export class ContinuousTrigger {
  private triggers: ContinuousTriggerConfig[];
  private readonly activationThreshold: number;

  constructor(triggers: ContinuousTriggerConfig[], activationThreshold: number = 0.5) {
    if (triggers.length === 0) {
      throw new SteleError('At least one trigger is required', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (activationThreshold < 0 || activationThreshold > 1) {
      throw new SteleError('activationThreshold must be in [0, 1]', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    for (const t of triggers) {
      if (t.steepness !== undefined && t.steepness <= 0) {
        throw new SteleError('steepness must be > 0', SteleErrorCode.PROTOCOL_INVALID_INPUT);
      }
      if (t.weight !== undefined && t.weight < 0) {
        throw new SteleError('weight must be >= 0', SteleErrorCode.PROTOCOL_INVALID_INPUT);
      }
    }
    this.triggers = triggers;
    this.activationThreshold = activationThreshold;
  }

  /**
   * Sigmoid activation function.
   * Returns a value in (0, 1) representing the degree of activation.
   */
  private sigmoid(value: number, threshold: number, steepness: number): number {
    return 1 / (1 + Math.exp(-steepness * (value - threshold)));
  }

  /**
   * Extract the relevant numeric value from agent state for a trigger type.
   */
  private extractValue(type: TriggerType, agentState: AgentState, covenant: CovenantState): number {
    switch (type) {
      case 'reputation_threshold':
        return agentState.reputationScore;
      case 'breach_event':
        return agentState.breachCount;
      case 'time_elapsed': {
        const lastTransition = covenant.lastTransitionAt ?? 0;
        return agentState.currentTime - lastTransition;
      }
      case 'capability_change':
        return agentState.capabilities.length;
      case 'governance_vote': {
        if (!agentState.governanceVotes) return 0;
        const votes = Object.values(agentState.governanceVotes);
        return votes.filter(v => v).length / Math.max(votes.length, 1);
      }
      default:
        return 0;
    }
  }

  /**
   * Evaluate all triggers against the current state, returning
   * continuous activation scores instead of boolean decisions.
   */
  evaluate(agentState: AgentState, covenant: CovenantState): ContinuousTriggerResult {
    const activations: Array<{ type: TriggerType; activation: number; weight: number }> = [];
    let totalWeight = 0;
    let weightedSum = 0;

    for (const trigger of this.triggers) {
      const value = this.extractValue(trigger.type, agentState, covenant);
      const steepness = trigger.steepness ?? 10;
      const weight = trigger.weight ?? 1.0;
      const activation = this.sigmoid(value, trigger.threshold, steepness);

      activations.push({ type: trigger.type, activation, weight });
      weightedSum += activation * weight;
      totalWeight += weight;
    }

    const combinedScore = totalWeight > 0 ? weightedSum / totalWeight : 0;

    return {
      activations,
      combinedScore,
      activated: combinedScore >= this.activationThreshold,
      activationThreshold: this.activationThreshold,
    };
  }
}

// ---------------------------------------------------------------------------
// Holt-Winters Forecasting (Double Exponential Smoothing)
// ---------------------------------------------------------------------------

/** Configuration for the violation forecaster. */
export interface ForecastConfig {
  /** Smoothing factor for the level (0 < alpha < 1). */
  alpha: number;
  /** Smoothing factor for the trend (0 < beta < 1). */
  beta: number;
  /** Number of future periods to forecast. */
  forecastPeriods: number;
  /** Confidence level for bands (default 0.95). */
  confidenceLevel?: number;
}

/** A single forecast data point. */
export interface ForecastPoint {
  /** Time period index. */
  period: number;
  /** Forecasted violation rate. */
  rate: number;
  /** Upper confidence bound. */
  upperBound: number;
  /** Lower confidence bound. */
  lowerBound: number;
}

/** Result of violation forecasting. */
export interface ForecastResult {
  /** The forecasted data points. */
  forecasts: ForecastPoint[];
  /** Final level component. */
  level: number;
  /** Final trend component. */
  trend: number;
  /** Mean Absolute Error on the training data. */
  mae: number;
  /** Direction of the forecast ('increasing', 'decreasing', 'stable'). */
  direction: 'increasing' | 'decreasing' | 'stable';
}

/**
 * ViolationForecaster uses Holt's method (double exponential smoothing)
 * to forecast future violation rates.
 *
 * Holt's method maintains two components:
 * - Level (l_t): the current smoothed value
 * - Trend (b_t): the current smoothed slope
 *
 * Update equations:
 *   l_t = alpha * y_t + (1 - alpha) * (l_{t-1} + b_{t-1})
 *   b_t = beta * (l_t - l_{t-1}) + (1 - beta) * b_{t-1}
 *
 * Forecast:
 *   y_{t+h} = l_t + h * b_t
 *
 * Confidence bands are computed from the residual standard error.
 */
export class ViolationForecaster {
  private readonly config: ForecastConfig;

  constructor(config: ForecastConfig) {
    if (config.alpha <= 0 || config.alpha >= 1) {
      throw new SteleError('alpha must be in (0, 1)', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (config.beta <= 0 || config.beta >= 1) {
      throw new SteleError('beta must be in (0, 1)', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (config.forecastPeriods < 1) {
      throw new SteleError('forecastPeriods must be >= 1', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (config.confidenceLevel !== undefined) {
      if (config.confidenceLevel <= 0 || config.confidenceLevel >= 1) {
        throw new SteleError('confidenceLevel must be in (0, 1)', SteleErrorCode.PROTOCOL_INVALID_INPUT);
      }
    }
    this.config = config;
  }

  /**
   * Forecast future violation rates based on historical data.
   *
   * @param historicalRates - Array of observed violation rates ordered by time period.
   *                          Must have at least 2 data points.
   * @returns ForecastResult with predicted rates and confidence bands
   */
  forecast(historicalRates: number[]): ForecastResult {
    if (historicalRates.length < 2) {
      throw new SteleError('At least 2 historical data points required', SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }

    for (let i = 0; i < historicalRates.length; i++) {
      if (typeof historicalRates[i] !== 'number' || isNaN(historicalRates[i]!)) {
        throw new SteleError(`historicalRates[${i}] must be a valid number`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
      }
    }

    const { alpha, beta, forecastPeriods } = this.config;
    const confidenceLevel = this.config.confidenceLevel ?? 0.95;

    // Initialize: level = first value, trend = average difference
    let level = historicalRates[0]!;
    let trend = (historicalRates[historicalRates.length - 1]! - historicalRates[0]!) /
      (historicalRates.length - 1);

    // Fit the model and compute residuals
    const residuals: number[] = [];

    for (let t = 1; t < historicalRates.length; t++) {
      const predicted = level + trend;
      const actual = historicalRates[t]!;
      residuals.push(actual - predicted);

      // Update level and trend
      const prevLevel = level;
      level = alpha * actual + (1 - alpha) * (level + trend);
      trend = beta * (level - prevLevel) + (1 - beta) * trend;
    }

    // Compute Mean Absolute Error
    const mae = residuals.length > 0
      ? residuals.reduce((sum, r) => sum + Math.abs(r), 0) / residuals.length
      : 0;

    // Compute residual standard error for confidence bands
    const sse = residuals.reduce((sum, r) => sum + r * r, 0);
    const sigma = Math.sqrt(sse / Math.max(residuals.length - 1, 1));

    // Z-score for confidence level (approximation for common levels)
    const zScore = this.approximateZScore(confidenceLevel);

    // Generate forecasts
    const forecasts: ForecastPoint[] = [];
    const n = historicalRates.length;

    for (let h = 1; h <= forecastPeriods; h++) {
      const rate = level + h * trend;
      // Confidence interval widens with forecast horizon
      // Variance grows linearly with h for Holt's method
      const forecastStdErr = sigma * Math.sqrt(1 + h * alpha * alpha);
      const margin = zScore * forecastStdErr;

      forecasts.push({
        period: n + h,
        rate,
        upperBound: rate + margin,
        lowerBound: Math.max(0, rate - margin), // Violation rates can't be negative
      });
    }

    // Determine direction
    let direction: 'increasing' | 'decreasing' | 'stable';
    if (trend > sigma * 0.1) {
      direction = 'increasing';
    } else if (trend < -sigma * 0.1) {
      direction = 'decreasing';
    } else {
      direction = 'stable';
    }

    return {
      forecasts,
      level,
      trend,
      mae,
      direction,
    };
  }

  /**
   * Approximate the Z-score for a given confidence level.
   * Uses a simple lookup for common values.
   */
  private approximateZScore(confidence: number): number {
    if (confidence >= 0.99) return 2.576;
    if (confidence >= 0.975) return 2.241;
    if (confidence >= 0.95) return 1.96;
    if (confidence >= 0.9) return 1.645;
    if (confidence >= 0.8) return 1.282;
    // Fallback: use probit approximation
    const p = (1 + confidence) / 2;
    const t = Math.sqrt(-2 * Math.log(1 - p));
    return t - (2.515517 + 0.802853 * t + 0.010328 * t * t) /
      (1 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t);
  }
}

// ---------------------------------------------------------------------------
// Temporal Constraint Algebra
// ---------------------------------------------------------------------------

/** A temporal constraint with a time range and enforcement weight. */
export interface TemporalConstraint {
  /** Unique identifier for this constraint. */
  id: string;
  /** Start time (normalized fraction in [0, 1]). */
  start: number;
  /** End time (normalized fraction in [0, 1]). */
  end: number;
  /** Enforcement weight in [0, 1]. */
  weight: number;
  /** Constraint identifier (e.g., a CCL rule reference). */
  constraintRef: string;
}

/** Result of a temporal algebra operation. */
export interface TemporalAlgebraResult {
  /** The resulting constraints after the operation. */
  constraints: TemporalConstraint[];
  /** The operation that was applied. */
  operation: 'intersection' | 'union' | 'difference';
  /** Human-readable description of the result. */
  description: string;
}

/**
 * TemporalConstraintAlgebra provides operations for combining temporal
 * constraints: intersection (tightest of both), union (loosest), and
 * difference (A minus B).
 *
 * Constraints are modeled as weighted intervals on a normalized [0, 1]
 * time range. The algebra operates on these intervals:
 *
 * - Intersection: overlapping time ranges, taking the maximum weight
 *   (most restrictive). Only the overlapping portions survive.
 *
 * - Union: merged time ranges, taking the minimum weight (least
 *   restrictive) in overlapping regions.
 *
 * - Difference: portions of A that don't overlap with B, preserving
 *   A's weight.
 */
export class TemporalConstraintAlgebra {
  /**
   * Validate a temporal constraint.
   */
  private validate(constraint: TemporalConstraint): void {
    if (constraint.start < 0 || constraint.start > 1) {
      throw new SteleError(`start must be in [0, 1], got ${constraint.start}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (constraint.end < 0 || constraint.end > 1) {
      throw new SteleError(`end must be in [0, 1], got ${constraint.end}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (constraint.start > constraint.end) {
      throw new SteleError(`start (${constraint.start}) must be <= end (${constraint.end})`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
    if (constraint.weight < 0 || constraint.weight > 1) {
      throw new SteleError(`weight must be in [0, 1], got ${constraint.weight}`, SteleErrorCode.PROTOCOL_INVALID_INPUT);
    }
  }

  /**
   * Intersection: compute the tightest constraints from both sets.
   *
   * For each pair of overlapping constraints (one from A, one from B),
   * creates a new constraint covering only the overlap with the maximum
   * weight (more restrictive).
   */
  intersection(setA: TemporalConstraint[], setB: TemporalConstraint[]): TemporalAlgebraResult {
    for (const c of setA) this.validate(c);
    for (const c of setB) this.validate(c);

    const results: TemporalConstraint[] = [];

    for (const a of setA) {
      for (const b of setB) {
        // Find overlap
        const overlapStart = Math.max(a.start, b.start);
        const overlapEnd = Math.min(a.end, b.end);

        if (overlapStart < overlapEnd) {
          results.push({
            id: `${a.id}_AND_${b.id}`,
            start: overlapStart,
            end: overlapEnd,
            weight: Math.max(a.weight, b.weight), // Most restrictive
            constraintRef: `${a.constraintRef} AND ${b.constraintRef}`,
          });
        }
      }
    }

    return {
      constraints: results,
      operation: 'intersection',
      description: `Intersection produced ${results.length} constraint(s) from ${setA.length} x ${setB.length} inputs`,
    };
  }

  /**
   * Union: compute the loosest constraints from both sets.
   *
   * Merges overlapping time ranges. In regions where both A and B have
   * constraints, takes the minimum weight (less restrictive). Non-overlapping
   * regions are included as-is.
   *
   * Uses an interval sweep-line algorithm for correct merging.
   */
  union(setA: TemporalConstraint[], setB: TemporalConstraint[]): TemporalAlgebraResult {
    for (const c of setA) this.validate(c);
    for (const c of setB) this.validate(c);

    // Combine all constraints and sort by start time
    const all = [...setA, ...setB].sort((a, b) => a.start - b.start || a.end - b.end);

    if (all.length === 0) {
      return { constraints: [], operation: 'union', description: 'Union of empty sets is empty' };
    }

    // Sweep-line merge
    const merged: TemporalConstraint[] = [];
    let current = { ...all[0]! };

    for (let i = 1; i < all.length; i++) {
      const next = all[i]!;

      if (next.start <= current.end) {
        // Overlapping: extend and take minimum weight in overlap
        const overlapWeight = Math.min(current.weight, next.weight);
        // If non-overlapping part of current has different weight, split
        if (next.start > current.start && current.weight !== overlapWeight) {
          // Emit the non-overlapping prefix
          merged.push({
            ...current,
            id: `${current.id}_prefix`,
            end: next.start,
          });
          current = {
            ...current,
            id: `${current.id}_AND_${next.id}`,
            start: next.start,
            end: Math.max(current.end, next.end),
            weight: overlapWeight,
            constraintRef: `${current.constraintRef} OR ${next.constraintRef}`,
          };
        } else {
          current = {
            ...current,
            id: `${current.id}_OR_${next.id}`,
            end: Math.max(current.end, next.end),
            weight: overlapWeight,
            constraintRef: `${current.constraintRef} OR ${next.constraintRef}`,
          };
        }
      } else {
        // No overlap: emit current and start new
        merged.push(current);
        current = { ...next };
      }
    }
    merged.push(current);

    return {
      constraints: merged,
      operation: 'union',
      description: `Union merged ${setA.length + setB.length} constraints into ${merged.length}`,
    };
  }

  /**
   * Difference: compute constraints in A but not overlapping with B.
   *
   * For each constraint in A, subtracts the time ranges covered by B.
   * The remaining fragments of A are returned with their original weight.
   */
  difference(setA: TemporalConstraint[], setB: TemporalConstraint[]): TemporalAlgebraResult {
    for (const c of setA) this.validate(c);
    for (const c of setB) this.validate(c);

    const results: TemporalConstraint[] = [];

    for (const a of setA) {
      // Start with the full range of a
      let fragments: Array<[number, number]> = [[a.start, a.end]];

      // Subtract each b interval
      for (const b of setB) {
        const newFragments: Array<[number, number]> = [];
        for (const [fStart, fEnd] of fragments) {
          if (b.end <= fStart || b.start >= fEnd) {
            // No overlap, keep fragment
            newFragments.push([fStart, fEnd]);
          } else {
            // Overlap: split fragment
            if (fStart < b.start) {
              newFragments.push([fStart, b.start]);
            }
            if (fEnd > b.end) {
              newFragments.push([b.end, fEnd]);
            }
          }
        }
        fragments = newFragments;
      }

      // Convert remaining fragments to constraints
      for (let i = 0; i < fragments.length; i++) {
        const [fStart, fEnd] = fragments[i]!;
        if (fEnd > fStart) {
          results.push({
            id: `${a.id}_diff_${i}`,
            start: fStart,
            end: fEnd,
            weight: a.weight,
            constraintRef: a.constraintRef,
          });
        }
      }
    }

    return {
      constraints: results,
      operation: 'difference',
      description: `Difference produced ${results.length} fragment(s) from ${setA.length} constraints minus ${setB.length}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Governance Bootstrap Sequence
// ---------------------------------------------------------------------------

/**
 * Governance phase identifiers for the bootstrap sequence.
 *
 * - Phase 0 (centralized): 0-99 agents, founder decision, labeled temporary
 * - Phase 1 (advisory_council): 100-999 agents, council vote
 * - Phase 2 (participation_weighted): 1000-9999 agents, weighted voting
 * - Phase 3 (fully_decentralized): 10000+ agents, full token governance
 */
export type GovernancePhase = 'centralized' | 'advisory_council' | 'participation_weighted' | 'fully_decentralized';

export interface GovernanceState {
  currentPhase: GovernancePhase;
  agentCount: number;
  phaseTransitions: Array<{ from: GovernancePhase; to: GovernancePhase; agentCount: number; timestamp: number }>;
  isTemporary: boolean; // true for phase 0
  decisionMechanism: string;
  votingWeights: 'equal' | 'stake_weighted' | 'participation_weighted' | 'reputation_weighted';
}

export interface GovernanceBootstrapConfig {
  phases: Array<{
    phase: GovernancePhase;
    minAgents: number;
    maxAgents: number;
    mechanism: string;
    votingWeights: GovernanceState['votingWeights'];
  }>;
}

/**
 * Default governance bootstrap configuration.
 *
 * Phase 0: centralized, 0-99, "founder_decision", equal, isTemporary=true
 * Phase 1: advisory_council, 100-999, "council_vote", stake_weighted
 * Phase 2: participation_weighted, 1000-9999, "weighted_vote", participation_weighted
 * Phase 3: fully_decentralized, 10000+, "token_governance", reputation_weighted
 */
export const DEFAULT_GOVERNANCE_BOOTSTRAP: GovernanceBootstrapConfig = {
  phases: [
    { phase: 'centralized', minAgents: 0, maxAgents: 99, mechanism: 'founder_decision', votingWeights: 'equal' },
    { phase: 'advisory_council', minAgents: 100, maxAgents: 999, mechanism: 'council_vote', votingWeights: 'stake_weighted' },
    { phase: 'participation_weighted', minAgents: 1000, maxAgents: 9999, mechanism: 'weighted_vote', votingWeights: 'participation_weighted' },
    { phase: 'fully_decentralized', minAgents: 10000, maxAgents: Infinity, mechanism: 'token_governance', votingWeights: 'reputation_weighted' },
  ],
};

/**
 * Determine the appropriate phase for a given agent count.
 */
function getPhaseForAgentCount(
  agentCount: number,
  config: GovernanceBootstrapConfig = DEFAULT_GOVERNANCE_BOOTSTRAP,
): GovernanceBootstrapConfig['phases'][number] {
  for (const phase of config.phases) {
    if (agentCount >= phase.minAgents && agentCount <= phase.maxAgents) {
      return phase;
    }
  }
  // Fallback to the last phase
  return config.phases[config.phases.length - 1]!;
}

/**
 * Initialize a governance state at the appropriate phase based on agentCount.
 *
 * @param agentCount - Current number of agents (default 0).
 * @returns A new GovernanceState.
 */
export function initializeGovernance(agentCount: number = 0): GovernanceState {
  const phaseConfig = getPhaseForAgentCount(agentCount);

  return {
    currentPhase: phaseConfig.phase,
    agentCount,
    phaseTransitions: [],
    isTemporary: phaseConfig.phase === 'centralized',
    decisionMechanism: phaseConfig.mechanism,
    votingWeights: phaseConfig.votingWeights,
  };
}

/**
 * Evaluate whether a phase transition should occur given a new agent count.
 *
 * @param state - The current governance state.
 * @param newAgentCount - The updated agent count.
 * @returns An evaluation result indicating whether transition is needed.
 */
export function evaluatePhaseTransition(
  state: GovernanceState,
  newAgentCount: number,
): {
  shouldTransition: boolean;
  currentPhase: GovernancePhase;
  nextPhase: GovernancePhase | null;
  agentsUntilTransition: number;
} {
  const currentPhaseConfig = getPhaseForAgentCount(state.agentCount);
  const newPhaseConfig = getPhaseForAgentCount(newAgentCount);

  if (newPhaseConfig.phase !== currentPhaseConfig.phase) {
    return {
      shouldTransition: true,
      currentPhase: state.currentPhase,
      nextPhase: newPhaseConfig.phase,
      agentsUntilTransition: 0,
    };
  }

  // No transition needed — compute how many agents until the next phase
  const agentsUntilTransition = currentPhaseConfig.maxAgents === Infinity
    ? Infinity
    : currentPhaseConfig.maxAgents - newAgentCount + 1;

  return {
    shouldTransition: false,
    currentPhase: state.currentPhase,
    nextPhase: null,
    agentsUntilTransition: Math.max(0, agentsUntilTransition),
  };
}

/**
 * Transition the governance state to the phase appropriate for the new agent count.
 *
 * If newAgentCount crosses a threshold, transitions to the next phase.
 * Records the transition in phaseTransitions. Updates decisionMechanism and votingWeights.
 *
 * @param state - The current governance state.
 * @param newAgentCount - The updated agent count.
 * @returns The updated GovernanceState.
 */
export function transitionPhase(state: GovernanceState, newAgentCount: number): GovernanceState {
  const newPhaseConfig = getPhaseForAgentCount(newAgentCount);

  if (newPhaseConfig.phase === state.currentPhase) {
    // No phase change, just update the agent count
    return {
      ...state,
      agentCount: newAgentCount,
    };
  }

  const transition = {
    from: state.currentPhase,
    to: newPhaseConfig.phase,
    agentCount: newAgentCount,
    timestamp: Date.now(),
  };

  return {
    currentPhase: newPhaseConfig.phase,
    agentCount: newAgentCount,
    phaseTransitions: [...state.phaseTransitions, transition],
    isTemporary: newPhaseConfig.phase === 'centralized',
    decisionMechanism: newPhaseConfig.mechanism,
    votingWeights: newPhaseConfig.votingWeights,
  };
}

/**
 * Compute the voting power for an agent in the current governance phase.
 *
 * Based on the current phase's votingWeights:
 * - equal: always 1
 * - stake_weighted: stake || 1
 * - participation_weighted: (participationRate || 0.5) * 10
 * - reputation_weighted: (reputationScore || 0.5) * 20
 *
 * @param state - The current governance state.
 * @param params - Agent-specific voting parameters.
 * @returns The computed voting power.
 */
export function computeVotingPower(
  state: GovernanceState,
  params: {
    stake?: number;
    participationRate?: number;
    reputationScore?: number;
  },
): number {
  switch (state.votingWeights) {
    case 'equal':
      return 1;
    case 'stake_weighted':
      return params.stake ?? 1;
    case 'participation_weighted':
      return (params.participationRate ?? 0.5) * 10;
    case 'reputation_weighted':
      return (params.reputationScore ?? 0.5) * 20;
    default:
      return 1;
  }
}
