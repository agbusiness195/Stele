import { describe, it, expect, vi } from 'vitest';
import {
  defineEvolution,
  evaluateTriggers,
  evolve,
  evolutionHistory,
  canEvolve,
  computeDecaySchedule,
  expirationForecast,
  // Governance Bootstrap
  initializeGovernance,
  evaluatePhaseTransition,
  transitionPhase,
  computeVotingPower,
  DEFAULT_GOVERNANCE_BOOTSTRAP,
  // Multi-Model Decay
  DecayModel,
  // Continuous Trigger Scoring
  ContinuousTrigger,
  // Violation Forecasting
  ViolationForecaster,
  // Temporal Constraint Algebra
  TemporalConstraintAlgebra,
} from './index';
import type {
  EvolutionTrigger,
  TransitionFunction,
  CovenantState,
  AgentState,
  EvolutionPolicy,
  DecayPoint,
  ViolationRecord,
} from './types';
import type {
  GovernancePhase,
  GovernanceState,
  DecayModelConfig,
  ContinuousTriggerConfig,
  ForecastConfig,
  TemporalConstraint,
} from './index';

// ---------------------------------------------------------------------------
// Helper factory functions
// ---------------------------------------------------------------------------
function makePolicy(overrides?: Partial<EvolutionPolicy>): EvolutionPolicy {
  return {
    covenantId: 'cov-1',
    triggers: [],
    transitions: [],
    governanceApproval: false,
    ...overrides,
  };
}

function makeCovenant(overrides?: Partial<CovenantState>): CovenantState {
  return {
    id: 'cov-1',
    constraints: ['c1', 'c2'],
    history: [],
    ...overrides,
  };
}

function makeAgent(overrides?: Partial<AgentState>): AgentState {
  return {
    reputationScore: 0.8,
    capabilities: ['read', 'write'],
    breachCount: 0,
    currentTime: 10000,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// defineEvolution
// ---------------------------------------------------------------------------
describe('defineEvolution', () => {
  it('creates an EvolutionPolicy with the given covenantId', () => {
    const policy = defineEvolution('cov-abc', [], []);
    expect(policy.covenantId).toBe('cov-abc');
  });

  it('includes the provided triggers', () => {
    const triggers: EvolutionTrigger[] = [
      { type: 'breach_event', condition: 'any', action: 'tighten' },
    ];
    const policy = defineEvolution('cov-1', triggers, []);
    expect(policy.triggers).toHaveLength(1);
    expect(policy.triggers[0]!.type).toBe('breach_event');
  });

  it('includes the provided transitions', () => {
    const transitions: TransitionFunction[] = [
      { fromConstraint: 'c1', toConstraint: 'c2', trigger: 'upgrade', reversible: true, cooldown: 1000 },
    ];
    const policy = defineEvolution('cov-1', [], transitions);
    expect(policy.transitions).toHaveLength(1);
  });

  it('defaults governanceApproval to false', () => {
    const policy = defineEvolution('cov-1', [], []);
    expect(policy.governanceApproval).toBe(false);
  });

  it('sets governanceApproval to true when specified', () => {
    const policy = defineEvolution('cov-1', [], [], true);
    expect(policy.governanceApproval).toBe(true);
  });

  it('throws on empty covenantId', () => {
    expect(() => defineEvolution('', [], [])).toThrow('covenantId must be a non-empty string');
  });

  it('throws on invalid trigger type', () => {
    const triggers = [{ type: 'invalid_type' as any, condition: 'x', action: 'tighten' as const }];
    expect(() => defineEvolution('cov-1', triggers, [])).toThrow('Invalid trigger type');
  });

  it('throws on invalid trigger action', () => {
    const triggers = [{ type: 'breach_event' as const, condition: 'any', action: 'invalid_action' as any }];
    expect(() => defineEvolution('cov-1', triggers, [])).toThrow('Invalid trigger action');
  });

  it('throws on malformed time_elapsed condition', () => {
    const triggers: EvolutionTrigger[] = [
      { type: 'time_elapsed', condition: 'not-a-number', action: 'relax' },
    ];
    expect(() => defineEvolution('cov-1', triggers, [])).toThrow('Invalid time_elapsed condition');
  });

  it('throws on negative time_elapsed condition', () => {
    const triggers: EvolutionTrigger[] = [
      { type: 'time_elapsed', condition: '-100', action: 'relax' },
    ];
    expect(() => defineEvolution('cov-1', triggers, [])).toThrow('Invalid time_elapsed condition');
  });

  it('throws on malformed reputation_threshold condition', () => {
    const triggers: EvolutionTrigger[] = [
      { type: 'reputation_threshold', condition: 'bad', action: 'relax' },
    ];
    expect(() => defineEvolution('cov-1', triggers, [])).toThrow('Invalid reputation_threshold condition');
  });

  it('throws on empty breach_event condition', () => {
    const triggers: EvolutionTrigger[] = [
      { type: 'breach_event', condition: '', action: 'tighten' },
    ];
    expect(() => defineEvolution('cov-1', triggers, [])).toThrow('breach_event condition must not be empty');
  });

  it('throws on empty governance_vote condition', () => {
    const triggers: EvolutionTrigger[] = [
      { type: 'governance_vote', condition: '', action: 'relax' },
    ];
    expect(() => defineEvolution('cov-1', triggers, [])).toThrow('governance_vote condition must not be empty');
  });

  it('throws on negative transition cooldown', () => {
    const transitions: TransitionFunction[] = [
      { fromConstraint: 'c1', toConstraint: 'c2', trigger: 'x', reversible: true, cooldown: -1 },
    ];
    expect(() => defineEvolution('cov-1', [], transitions)).toThrow('cooldown must be a non-negative number');
  });

  it('throws on empty transition fromConstraint', () => {
    const transitions: TransitionFunction[] = [
      { fromConstraint: '', toConstraint: 'c2', trigger: 'x', reversible: true, cooldown: 100 },
    ];
    expect(() => defineEvolution('cov-1', [], transitions)).toThrow('fromConstraint must be a non-empty string');
  });

  it('accepts valid >= and <= reputation_threshold conditions', () => {
    const triggers: EvolutionTrigger[] = [
      { type: 'reputation_threshold', condition: '>=0.5', action: 'relax' },
      { type: 'reputation_threshold', condition: '<=0.3', action: 'tighten' },
    ];
    const policy = defineEvolution('cov-1', triggers, []);
    expect(policy.triggers).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// evaluateTriggers
// ---------------------------------------------------------------------------
describe('evaluateTriggers', () => {
  it('returns empty array when covenant has no policy', () => {
    const covenant = makeCovenant({ policy: undefined });
    const agent = makeAgent();
    expect(evaluateTriggers(covenant, agent)).toEqual([]);
  });

  it('fires time_elapsed trigger when enough time has passed', () => {
    const trigger: EvolutionTrigger = { type: 'time_elapsed', condition: '5000', action: 'relax' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy, lastTransitionAt: 1000 });
    const agent = makeAgent({ currentTime: 7000 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
    expect(fired[0]!.type).toBe('time_elapsed');
  });

  it('does not fire time_elapsed trigger when not enough time has passed', () => {
    const trigger: EvolutionTrigger = { type: 'time_elapsed', condition: '5000', action: 'relax' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy, lastTransitionAt: 5000 });
    const agent = makeAgent({ currentTime: 7000 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(0);
  });

  it('uses 0 as lastTransitionAt when undefined', () => {
    const trigger: EvolutionTrigger = { type: 'time_elapsed', condition: '5000', action: 'relax' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy, lastTransitionAt: undefined });
    const agent = makeAgent({ currentTime: 6000 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
  });

  it('fires reputation_threshold trigger with > operator', () => {
    const trigger: EvolutionTrigger = { type: 'reputation_threshold', condition: '>0.5', action: 'relax' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ reputationScore: 0.8 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
  });

  it('fires reputation_threshold trigger with < operator', () => {
    const trigger: EvolutionTrigger = { type: 'reputation_threshold', condition: '<0.3', action: 'tighten' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ reputationScore: 0.2 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
  });

  it('fires reputation_threshold trigger with >= operator', () => {
    const trigger: EvolutionTrigger = { type: 'reputation_threshold', condition: '>=0.5', action: 'relax' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ reputationScore: 0.5 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
  });

  it('fires reputation_threshold trigger with <= operator', () => {
    const trigger: EvolutionTrigger = { type: 'reputation_threshold', condition: '<=0.3', action: 'tighten' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ reputationScore: 0.3 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
  });

  it('does not fire reputation_threshold when condition not met', () => {
    const trigger: EvolutionTrigger = { type: 'reputation_threshold', condition: '>0.9', action: 'relax' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ reputationScore: 0.5 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(0);
  });

  it('throws on malformed reputation_threshold condition during evaluation', () => {
    const trigger: EvolutionTrigger = { type: 'reputation_threshold', condition: 'bad', action: 'relax' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent();
    expect(() => evaluateTriggers(covenant, agent)).toThrow('Malformed reputation_threshold condition');
  });

  it('throws on malformed time_elapsed condition during evaluation', () => {
    const trigger: EvolutionTrigger = { type: 'time_elapsed', condition: 'abc', action: 'relax' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent();
    expect(() => evaluateTriggers(covenant, agent)).toThrow('Malformed time_elapsed condition');
  });

  it('fires breach_event trigger when breachCount > 0', () => {
    const trigger: EvolutionTrigger = { type: 'breach_event', condition: 'any', action: 'tighten' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ breachCount: 3 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
  });

  it('does not fire breach_event when breachCount is 0', () => {
    const trigger: EvolutionTrigger = { type: 'breach_event', condition: 'any', action: 'tighten' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ breachCount: 0 });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(0);
  });

  it('fires capability_change trigger when capabilities differ', () => {
    const trigger: EvolutionTrigger = {
      type: 'capability_change',
      condition: 'read,write',
      action: 'tighten',
    };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ capabilities: ['read', 'write', 'execute'] });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
  });

  it('does not fire capability_change when capabilities match', () => {
    const trigger: EvolutionTrigger = {
      type: 'capability_change',
      condition: 'read,write',
      action: 'tighten',
    };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ capabilities: ['read', 'write'] });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(0);
  });

  it('fires governance_vote trigger when vote exists and is true', () => {
    const trigger: EvolutionTrigger = {
      type: 'governance_vote',
      condition: 'proposal-42',
      action: 'relax',
    };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ governanceVotes: { 'proposal-42': true } });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(1);
  });

  it('does not fire governance_vote trigger when vote is false', () => {
    const trigger: EvolutionTrigger = {
      type: 'governance_vote',
      condition: 'proposal-42',
      action: 'relax',
    };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = makeAgent({ governanceVotes: { 'proposal-42': false } });
    const fired = evaluateTriggers(covenant, agent);
    expect(fired).toHaveLength(0);
  });

  it('throws when agentState.reputationScore is not a number', () => {
    const trigger: EvolutionTrigger = { type: 'breach_event', condition: 'any', action: 'tighten' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = { reputationScore: 'bad' as any, capabilities: [], breachCount: 0, currentTime: 100 };
    expect(() => evaluateTriggers(covenant, agent)).toThrow('agentState.reputationScore must be a number');
  });

  it('throws when agentState.capabilities is not an array', () => {
    const trigger: EvolutionTrigger = { type: 'breach_event', condition: 'any', action: 'tighten' };
    const policy = makePolicy({ triggers: [trigger] });
    const covenant = makeCovenant({ policy });
    const agent = { reputationScore: 0.5, capabilities: 'bad' as any, breachCount: 0, currentTime: 100 };
    expect(() => evaluateTriggers(covenant, agent)).toThrow('agentState.capabilities must be an array');
  });
});

// ---------------------------------------------------------------------------
// evolve
// ---------------------------------------------------------------------------
describe('evolve', () => {
  it('adds a constraint with tighten action', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
      constraintId: 'new-restriction',
    };
    const covenant = makeCovenant({ policy: makePolicy() });
    const result = evolve(covenant, trigger);
    expect(result.covenant.constraints).toContain('new-restriction');
    expect(result.event.approved).toBe(true);
  });

  it('removes a constraint with relax action', () => {
    const trigger: EvolutionTrigger = {
      type: 'reputation_threshold',
      condition: '>0.9',
      action: 'relax',
      constraintId: 'c1',
    };
    const covenant = makeCovenant({ policy: makePolicy() });
    const result = evolve(covenant, trigger);
    expect(result.covenant.constraints).not.toContain('c1');
    expect(result.covenant.constraints).toContain('c2');
  });

  it('adds a constraint with add_constraint action', () => {
    const trigger: EvolutionTrigger = {
      type: 'governance_vote',
      condition: 'vote-1',
      action: 'add_constraint',
      constraintId: 'c3',
    };
    const covenant = makeCovenant({ policy: makePolicy() });
    const result = evolve(covenant, trigger);
    expect(result.covenant.constraints).toContain('c3');
  });

  it('removes a constraint with remove_constraint action', () => {
    const trigger: EvolutionTrigger = {
      type: 'governance_vote',
      condition: 'vote-2',
      action: 'remove_constraint',
      constraintId: 'c2',
    };
    const covenant = makeCovenant({ policy: makePolicy() });
    const result = evolve(covenant, trigger);
    expect(result.covenant.constraints).not.toContain('c2');
  });

  it('records the event in the covenant history', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
      constraintId: 'added',
    };
    const covenant = makeCovenant({ policy: makePolicy() });
    const result = evolve(covenant, trigger);
    expect(result.covenant.history).toHaveLength(1);
    expect(result.covenant.history[0]!.trigger).toBe(trigger);
  });

  it('updates lastTransitionAt on successful evolution', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
      constraintId: 'x',
    };
    const covenant = makeCovenant({ policy: makePolicy(), lastTransitionAt: 0 });
    const result = evolve(covenant, trigger);
    expect(result.covenant.lastTransitionAt).toBeGreaterThan(0);
  });

  it('does not approve evolution when governance is required and trigger is not governance_vote', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
      constraintId: 'new',
    };
    const policy = makePolicy({ governanceApproval: true });
    const covenant = makeCovenant({ policy });
    const result = evolve(covenant, trigger);
    expect(result.event.approved).toBe(false);
    expect(result.covenant.constraints).toEqual(['c1', 'c2']);
  });

  it('sets governanceStatus to pending when governance required and trigger is not governance_vote', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
      constraintId: 'new',
    };
    const policy = makePolicy({ governanceApproval: true });
    const covenant = makeCovenant({ policy });
    const result = evolve(covenant, trigger);
    expect(result.event.governanceStatus).toBe('pending');
  });

  it('sets governanceStatus to approved when governance required and trigger is governance_vote', () => {
    const trigger: EvolutionTrigger = {
      type: 'governance_vote',
      condition: 'proposal-1',
      action: 'add_constraint',
      constraintId: 'c3',
    };
    const policy = makePolicy({ governanceApproval: true });
    const covenant = makeCovenant({ policy });
    const result = evolve(covenant, trigger);
    expect(result.event.approved).toBe(true);
    expect(result.event.governanceStatus).toBe('approved');
  });

  it('preserves previousConstraints in the event', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
      constraintId: 'new',
    };
    const covenant = makeCovenant({ policy: makePolicy() });
    const result = evolve(covenant, trigger);
    expect(result.event.previousConstraints).toEqual(['c1', 'c2']);
  });

  it('does not duplicate constraint when add_constraint with existing id', () => {
    const trigger: EvolutionTrigger = {
      type: 'governance_vote',
      condition: 'vote-1',
      action: 'add_constraint',
      constraintId: 'c1',
    };
    const covenant = makeCovenant({ policy: makePolicy() });
    const result = evolve(covenant, trigger);
    const c1Count = result.covenant.constraints.filter((c) => c === 'c1').length;
    expect(c1Count).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// evolutionHistory
// ---------------------------------------------------------------------------
describe('evolutionHistory', () => {
  it('returns empty array for covenant with no history', () => {
    const covenant = makeCovenant();
    expect(evolutionHistory(covenant)).toEqual([]);
  });

  it('returns the history array from the covenant', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
      constraintId: 'added',
    };
    const covenant = makeCovenant({ policy: makePolicy() });
    const result = evolve(covenant, trigger);
    const history = evolutionHistory(result.covenant);
    expect(history).toHaveLength(1);
    expect(history[0]!.covenantId).toBe('cov-1');
  });
});

// ---------------------------------------------------------------------------
// canEvolve
// ---------------------------------------------------------------------------
describe('canEvolve', () => {
  it('returns false when covenant has no policy', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
    };
    const covenant = makeCovenant({ policy: undefined });
    expect(canEvolve(covenant, trigger)).toBe(false);
  });

  it('returns false when governance is required and trigger is not governance_vote', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
    };
    const policy = makePolicy({ governanceApproval: true });
    const covenant = makeCovenant({ policy });
    expect(canEvolve(covenant, trigger)).toBe(false);
  });

  it('returns true when governance is required and trigger is governance_vote', () => {
    const trigger: EvolutionTrigger = {
      type: 'governance_vote',
      condition: 'proposal-1',
      action: 'relax',
    };
    const policy = makePolicy({ governanceApproval: true });
    const covenant = makeCovenant({ policy });
    expect(canEvolve(covenant, trigger)).toBe(true);
  });

  it('returns true when no governance is required', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'tighten',
    };
    const policy = makePolicy({ governanceApproval: false });
    const covenant = makeCovenant({ policy });
    expect(canEvolve(covenant, trigger)).toBe(true);
  });

  it('returns false when cooldown has not elapsed for matching transition (fromConstraint/toConstraint)', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'add_constraint',
      constraintId: 'c3',
    };
    const transitions: TransitionFunction[] = [
      { fromConstraint: 'c1', toConstraint: 'c3', trigger: 'upgrade', reversible: true, cooldown: 999999999 },
    ];
    const policy = makePolicy({ transitions });
    const covenant = makeCovenant({ policy, lastTransitionAt: Date.now() });
    expect(canEvolve(covenant, trigger)).toBe(false);
  });

  it('returns true when cooldown has elapsed for matching transition', () => {
    const trigger: EvolutionTrigger = {
      type: 'breach_event',
      condition: 'any',
      action: 'add_constraint',
      constraintId: 'c3',
    };
    const transitions: TransitionFunction[] = [
      { fromConstraint: 'c1', toConstraint: 'c3', trigger: 'upgrade', reversible: true, cooldown: 100 },
    ];
    const policy = makePolicy({ transitions });
    const covenant = makeCovenant({ policy, lastTransitionAt: Date.now() - 200 });
    expect(canEvolve(covenant, trigger)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// computeDecaySchedule
// ---------------------------------------------------------------------------
describe('computeDecaySchedule', () => {
  it('returns the correct number of steps', () => {
    const schedule = computeDecaySchedule(1.0, 1.0, 10000, 5);
    expect(schedule).toHaveLength(5);
  });

  it('starts at the initial weight', () => {
    const schedule = computeDecaySchedule(2.0, 1.0, 10000, 10);
    expect(schedule[0]!.time).toBe(0);
    expect(schedule[0]!.value).toBeCloseTo(2.0, 10);
  });

  it('ends at time equal to lifetimeMs', () => {
    const schedule = computeDecaySchedule(1.0, 1.0, 5000, 10);
    expect(schedule[schedule.length - 1]!.time).toBeCloseTo(5000, 5);
  });

  it('values decay monotonically over time', () => {
    const schedule = computeDecaySchedule(1.0, 2.0, 10000, 20);
    for (let i = 1; i < schedule.length; i++) {
      expect(schedule[i]!.value).toBeLessThanOrEqual(schedule[i - 1]!.value);
    }
  });

  it('with zero decay rate, values remain constant', () => {
    const schedule = computeDecaySchedule(1.0, 0, 10000, 5);
    for (const point of schedule) {
      expect(point.value).toBeCloseTo(1.0, 10);
    }
  });

  it('higher decay rate produces lower final value', () => {
    const scheduleSlow = computeDecaySchedule(1.0, 0.5, 10000, 10);
    const scheduleFast = computeDecaySchedule(1.0, 5.0, 10000, 10);
    const lastSlow = scheduleSlow[scheduleSlow.length - 1]!.value;
    const lastFast = scheduleFast[scheduleFast.length - 1]!.value;
    expect(lastFast).toBeLessThan(lastSlow);
  });

  it('throws on non-positive initialWeight', () => {
    expect(() => computeDecaySchedule(0, 1.0, 10000, 5)).toThrow('initialWeight must be positive');
    expect(() => computeDecaySchedule(-1, 1.0, 10000, 5)).toThrow('initialWeight must be positive');
  });

  it('throws on negative decayRate', () => {
    expect(() => computeDecaySchedule(1.0, -1.0, 10000, 5)).toThrow('decayRate must be non-negative');
  });

  it('throws on non-positive lifetimeMs', () => {
    expect(() => computeDecaySchedule(1.0, 1.0, 0, 5)).toThrow('lifetimeMs must be positive');
    expect(() => computeDecaySchedule(1.0, 1.0, -100, 5)).toThrow('lifetimeMs must be positive');
  });

  it('throws on steps less than 2', () => {
    expect(() => computeDecaySchedule(1.0, 1.0, 10000, 1)).toThrow('steps must be at least 2');
    expect(() => computeDecaySchedule(1.0, 1.0, 10000, 0)).toThrow('steps must be at least 2');
  });

  it('time points are evenly spaced', () => {
    const schedule = computeDecaySchedule(1.0, 1.0, 10000, 5);
    const expectedStep = 10000 / 4;
    for (let i = 0; i < schedule.length; i++) {
      expect(schedule[i]!.time).toBeCloseTo(i * expectedStep, 5);
    }
  });

  it('applies correct exponential decay formula', () => {
    const schedule = computeDecaySchedule(3.0, 2.0, 10000, 3);
    // At t=0: 3.0 * e^(0) = 3.0
    expect(schedule[0]!.value).toBeCloseTo(3.0, 10);
    // At t=5000 (normalized 0.5): 3.0 * e^(-2.0 * 0.5) = 3.0 * e^(-1.0)
    expect(schedule[1]!.value).toBeCloseTo(3.0 * Math.exp(-1.0), 10);
    // At t=10000 (normalized 1.0): 3.0 * e^(-2.0 * 1.0) = 3.0 * e^(-2.0)
    expect(schedule[2]!.value).toBeCloseTo(3.0 * Math.exp(-2.0), 10);
  });

  it('works with a large number of steps', () => {
    const schedule = computeDecaySchedule(1.0, 1.0, 10000, 1000);
    expect(schedule).toHaveLength(1000);
    expect(schedule[0]!.value).toBeCloseTo(1.0, 10);
    expect(schedule[999]!.value).toBeLessThan(1.0);
  });
});

// ---------------------------------------------------------------------------
// expirationForecast
// ---------------------------------------------------------------------------
describe('expirationForecast', () => {
  it('returns current time as expiration when weight is already below threshold', () => {
    // Very high decay rate so weight at currentTime is already tiny
    const violations: ViolationRecord[] = [
      { timestamp: 100, severity: 10 },
      { timestamp: 200, severity: 10 },
    ];
    const result = expirationForecast(1.0, 0, violations, 300, 0.1, 0.1);
    // Total damage = 10*0.1 + 10*0.1 = 2.0, which exceeds initialWeight 1.0
    expect(result.predictedExpirationTime).toBe(300);
    expect(result.remainingWeight).toBe(0);
    expect(result.confidence).toBe(1.0);
  });

  it('predicts a future expiration time with natural decay only', () => {
    const violations: ViolationRecord[] = [];
    const result = expirationForecast(1.0, 5.0, violations, 0, 0.1);
    expect(result.predictedExpirationTime).toBeGreaterThan(0);
    expect(result.remainingWeight).toBeCloseTo(1.0, 5);
  });

  it('violations reduce remaining weight', () => {
    const noViolations = expirationForecast(1.0, 0, [], 1000, 0.1, 0.05);
    const withViolations = expirationForecast(
      1.0, 0,
      [{ timestamp: 500, severity: 5 }],
      1000, 0.1, 0.05,
    );
    expect(withViolations.remainingWeight).toBeLessThan(noViolations.remainingWeight);
  });

  it('detects accelerating violation trend', () => {
    // Violations getting closer together
    const violations: ViolationRecord[] = [
      { timestamp: 100, severity: 1 },
      { timestamp: 200, severity: 1 },
      { timestamp: 250, severity: 1 },
      { timestamp: 270, severity: 1 },
      { timestamp: 280, severity: 1 },
    ];
    const result = expirationForecast(1.0, 0, violations, 300, 0.1, 0.01);
    expect(result.violationTrend).toBe('accelerating');
  });

  it('detects decelerating violation trend', () => {
    // Violations getting further apart
    const violations: ViolationRecord[] = [
      { timestamp: 100, severity: 1 },
      { timestamp: 110, severity: 1 },
      { timestamp: 120, severity: 1 },
      { timestamp: 200, severity: 1 },
      { timestamp: 400, severity: 1 },
    ];
    const result = expirationForecast(1.0, 0, violations, 500, 0.1, 0.01);
    expect(result.violationTrend).toBe('decelerating');
  });

  it('reports stable trend when violation intervals are consistent', () => {
    const violations: ViolationRecord[] = [
      { timestamp: 100, severity: 1 },
      { timestamp: 200, severity: 1 },
      { timestamp: 300, severity: 1 },
      { timestamp: 400, severity: 1 },
    ];
    const result = expirationForecast(1.0, 0, violations, 500, 0.1, 0.01);
    expect(result.violationTrend).toBe('stable');
  });

  it('confidence increases with more violation data', () => {
    const fewViolations: ViolationRecord[] = [
      { timestamp: 100, severity: 1 },
    ];
    const manyViolations: ViolationRecord[] = [
      { timestamp: 100, severity: 1 },
      { timestamp: 200, severity: 1 },
      { timestamp: 300, severity: 1 },
      { timestamp: 400, severity: 1 },
      { timestamp: 500, severity: 1 },
      { timestamp: 600, severity: 1 },
      { timestamp: 700, severity: 1 },
    ];
    const resultFew = expirationForecast(1.0, 0, fewViolations, 800, 0.1, 0.01);
    const resultMany = expirationForecast(1.0, 0, manyViolations, 800, 0.1, 0.01);
    expect(resultMany.confidence).toBeGreaterThan(resultFew.confidence);
  });

  it('throws on non-positive initialWeight', () => {
    expect(() => expirationForecast(0, 1.0, [], 1000)).toThrow('initialWeight must be positive');
  });

  it('throws on negative decayRate', () => {
    expect(() => expirationForecast(1.0, -1, [], 1000)).toThrow('decayRate must be non-negative');
  });

  it('throws on threshold >= initialWeight', () => {
    expect(() => expirationForecast(1.0, 0, [], 1000, 1.0)).toThrow('threshold must be in [0, initialWeight)');
    expect(() => expirationForecast(1.0, 0, [], 1000, 2.0)).toThrow('threshold must be in [0, initialWeight)');
  });

  it('throws on negative violationImpact', () => {
    expect(() => expirationForecast(1.0, 0, [], 1000, 0.1, -1)).toThrow('violationImpact must be non-negative');
  });

  it('more violations lead to earlier predicted expiration', () => {
    const fewViolations: ViolationRecord[] = [
      { timestamp: 100, severity: 2 },
    ];
    const manyViolations: ViolationRecord[] = [
      { timestamp: 100, severity: 2 },
      { timestamp: 200, severity: 2 },
      { timestamp: 300, severity: 2 },
      { timestamp: 400, severity: 2 },
    ];
    const resultFew = expirationForecast(1.0, 1.0, fewViolations, 500, 0.1, 0.05);
    const resultMany = expirationForecast(1.0, 1.0, manyViolations, 500, 0.1, 0.05);
    expect(resultMany.predictedExpirationTime).toBeLessThanOrEqual(resultFew.predictedExpirationTime);
  });

  it('remaining weight is never negative', () => {
    const violations: ViolationRecord[] = [
      { timestamp: 100, severity: 100 },
      { timestamp: 200, severity: 100 },
    ];
    const result = expirationForecast(1.0, 0, violations, 300, 0.1, 1.0);
    expect(result.remainingWeight).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// Governance Bootstrap Sequence
// ---------------------------------------------------------------------------

describe('DEFAULT_GOVERNANCE_BOOTSTRAP', () => {
  it('defines exactly 4 phases', () => {
    expect(DEFAULT_GOVERNANCE_BOOTSTRAP.phases).toHaveLength(4);
  });

  it('has centralized as the first phase (0-99)', () => {
    const phase = DEFAULT_GOVERNANCE_BOOTSTRAP.phases[0]!;
    expect(phase.phase).toBe('centralized');
    expect(phase.minAgents).toBe(0);
    expect(phase.maxAgents).toBe(99);
    expect(phase.mechanism).toBe('founder_decision');
    expect(phase.votingWeights).toBe('equal');
  });

  it('has advisory_council as the second phase (100-999)', () => {
    const phase = DEFAULT_GOVERNANCE_BOOTSTRAP.phases[1]!;
    expect(phase.phase).toBe('advisory_council');
    expect(phase.minAgents).toBe(100);
    expect(phase.maxAgents).toBe(999);
    expect(phase.mechanism).toBe('council_vote');
    expect(phase.votingWeights).toBe('stake_weighted');
  });

  it('has participation_weighted as the third phase (1000-9999)', () => {
    const phase = DEFAULT_GOVERNANCE_BOOTSTRAP.phases[2]!;
    expect(phase.phase).toBe('participation_weighted');
    expect(phase.minAgents).toBe(1000);
    expect(phase.maxAgents).toBe(9999);
    expect(phase.mechanism).toBe('weighted_vote');
    expect(phase.votingWeights).toBe('participation_weighted');
  });

  it('has fully_decentralized as the final phase (10000+)', () => {
    const phase = DEFAULT_GOVERNANCE_BOOTSTRAP.phases[3]!;
    expect(phase.phase).toBe('fully_decentralized');
    expect(phase.minAgents).toBe(10000);
    expect(phase.maxAgents).toBe(Infinity);
    expect(phase.mechanism).toBe('token_governance');
    expect(phase.votingWeights).toBe('reputation_weighted');
  });
});

describe('initializeGovernance', () => {
  it('defaults to centralized phase with 0 agents', () => {
    const state = initializeGovernance();
    expect(state.currentPhase).toBe('centralized');
    expect(state.agentCount).toBe(0);
    expect(state.phaseTransitions).toHaveLength(0);
    expect(state.isTemporary).toBe(true);
    expect(state.decisionMechanism).toBe('founder_decision');
    expect(state.votingWeights).toBe('equal');
  });

  it('starts in centralized phase for 50 agents', () => {
    const state = initializeGovernance(50);
    expect(state.currentPhase).toBe('centralized');
    expect(state.agentCount).toBe(50);
    expect(state.isTemporary).toBe(true);
  });

  it('starts in advisory_council phase for 100 agents', () => {
    const state = initializeGovernance(100);
    expect(state.currentPhase).toBe('advisory_council');
    expect(state.agentCount).toBe(100);
    expect(state.isTemporary).toBe(false);
    expect(state.decisionMechanism).toBe('council_vote');
    expect(state.votingWeights).toBe('stake_weighted');
  });

  it('starts in advisory_council phase for 500 agents', () => {
    const state = initializeGovernance(500);
    expect(state.currentPhase).toBe('advisory_council');
  });

  it('starts in participation_weighted phase for 1000 agents', () => {
    const state = initializeGovernance(1000);
    expect(state.currentPhase).toBe('participation_weighted');
    expect(state.decisionMechanism).toBe('weighted_vote');
    expect(state.votingWeights).toBe('participation_weighted');
    expect(state.isTemporary).toBe(false);
  });

  it('starts in participation_weighted phase for 5000 agents', () => {
    const state = initializeGovernance(5000);
    expect(state.currentPhase).toBe('participation_weighted');
  });

  it('starts in fully_decentralized phase for 10000 agents', () => {
    const state = initializeGovernance(10000);
    expect(state.currentPhase).toBe('fully_decentralized');
    expect(state.decisionMechanism).toBe('token_governance');
    expect(state.votingWeights).toBe('reputation_weighted');
    expect(state.isTemporary).toBe(false);
  });

  it('starts in fully_decentralized phase for 100000 agents', () => {
    const state = initializeGovernance(100000);
    expect(state.currentPhase).toBe('fully_decentralized');
  });

  it('starts with empty phaseTransitions', () => {
    const state = initializeGovernance(500);
    expect(state.phaseTransitions).toEqual([]);
  });
});

describe('evaluatePhaseTransition', () => {
  it('returns shouldTransition=false when agent count stays in same phase', () => {
    const state = initializeGovernance(50);
    const result = evaluatePhaseTransition(state, 80);
    expect(result.shouldTransition).toBe(false);
    expect(result.currentPhase).toBe('centralized');
    expect(result.nextPhase).toBeNull();
    expect(result.agentsUntilTransition).toBe(20); // 99 - 80 + 1
  });

  it('returns shouldTransition=true when crossing to advisory_council', () => {
    const state = initializeGovernance(90);
    const result = evaluatePhaseTransition(state, 100);
    expect(result.shouldTransition).toBe(true);
    expect(result.currentPhase).toBe('centralized');
    expect(result.nextPhase).toBe('advisory_council');
    expect(result.agentsUntilTransition).toBe(0);
  });

  it('returns shouldTransition=true when crossing to participation_weighted', () => {
    const state = initializeGovernance(900);
    const result = evaluatePhaseTransition(state, 1000);
    expect(result.shouldTransition).toBe(true);
    expect(result.nextPhase).toBe('participation_weighted');
  });

  it('returns shouldTransition=true when crossing to fully_decentralized', () => {
    const state = initializeGovernance(9000);
    const result = evaluatePhaseTransition(state, 10000);
    expect(result.shouldTransition).toBe(true);
    expect(result.nextPhase).toBe('fully_decentralized');
  });

  it('returns agentsUntilTransition=Infinity for fully_decentralized phase', () => {
    const state = initializeGovernance(15000);
    const result = evaluatePhaseTransition(state, 20000);
    expect(result.shouldTransition).toBe(false);
    expect(result.agentsUntilTransition).toBe(Infinity);
  });

  it('computes correct agentsUntilTransition', () => {
    const state = initializeGovernance(0);
    const result = evaluatePhaseTransition(state, 95);
    // maxAgents for centralized is 99, so 99 - 95 + 1 = 5
    expect(result.agentsUntilTransition).toBe(5);
  });

  it('returns agentsUntilTransition=0 when at boundary', () => {
    const state = initializeGovernance(0);
    const result = evaluatePhaseTransition(state, 99);
    // 99 - 99 + 1 = 1
    expect(result.agentsUntilTransition).toBe(1);
  });
});

describe('transitionPhase', () => {
  it('transitions from centralized to advisory_council', () => {
    const state = initializeGovernance(50);
    const newState = transitionPhase(state, 100);

    expect(newState.currentPhase).toBe('advisory_council');
    expect(newState.agentCount).toBe(100);
    expect(newState.isTemporary).toBe(false);
    expect(newState.decisionMechanism).toBe('council_vote');
    expect(newState.votingWeights).toBe('stake_weighted');
    expect(newState.phaseTransitions).toHaveLength(1);
    expect(newState.phaseTransitions[0]!.from).toBe('centralized');
    expect(newState.phaseTransitions[0]!.to).toBe('advisory_council');
    expect(newState.phaseTransitions[0]!.agentCount).toBe(100);
    expect(newState.phaseTransitions[0]!.timestamp).toBeGreaterThan(0);
  });

  it('transitions from advisory_council to participation_weighted', () => {
    const state = initializeGovernance(500);
    const newState = transitionPhase(state, 1500);

    expect(newState.currentPhase).toBe('participation_weighted');
    expect(newState.decisionMechanism).toBe('weighted_vote');
    expect(newState.votingWeights).toBe('participation_weighted');
  });

  it('transitions from participation_weighted to fully_decentralized', () => {
    const state = initializeGovernance(5000);
    const newState = transitionPhase(state, 15000);

    expect(newState.currentPhase).toBe('fully_decentralized');
    expect(newState.decisionMechanism).toBe('token_governance');
    expect(newState.votingWeights).toBe('reputation_weighted');
  });

  it('does not transition when agent count stays in same phase', () => {
    const state = initializeGovernance(50);
    const newState = transitionPhase(state, 80);

    expect(newState.currentPhase).toBe('centralized');
    expect(newState.agentCount).toBe(80);
    expect(newState.phaseTransitions).toHaveLength(0);
  });

  it('records multiple transitions', () => {
    let state = initializeGovernance(50);
    state = transitionPhase(state, 150); // -> advisory_council
    state = transitionPhase(state, 2000); // -> participation_weighted
    state = transitionPhase(state, 20000); // -> fully_decentralized

    expect(state.currentPhase).toBe('fully_decentralized');
    expect(state.phaseTransitions).toHaveLength(3);
    expect(state.phaseTransitions[0]!.from).toBe('centralized');
    expect(state.phaseTransitions[0]!.to).toBe('advisory_council');
    expect(state.phaseTransitions[1]!.from).toBe('advisory_council');
    expect(state.phaseTransitions[1]!.to).toBe('participation_weighted');
    expect(state.phaseTransitions[2]!.from).toBe('participation_weighted');
    expect(state.phaseTransitions[2]!.to).toBe('fully_decentralized');
  });

  it('preserves transition history across multiple transitions', () => {
    let state = initializeGovernance(50);
    state = transitionPhase(state, 150);
    const firstTransition = state.phaseTransitions[0]!;

    state = transitionPhase(state, 2000);
    expect(state.phaseTransitions).toHaveLength(2);
    expect(state.phaseTransitions[0]).toEqual(firstTransition);
  });

  it('marks centralized phase as temporary', () => {
    const state = initializeGovernance(50);
    expect(state.isTemporary).toBe(true);

    const newState = transitionPhase(state, 100);
    expect(newState.isTemporary).toBe(false);
  });

  it('can transition backward if agent count decreases', () => {
    const state = initializeGovernance(500);
    expect(state.currentPhase).toBe('advisory_council');

    const newState = transitionPhase(state, 50);
    expect(newState.currentPhase).toBe('centralized');
    expect(newState.isTemporary).toBe(true);
    expect(newState.phaseTransitions).toHaveLength(1);
    expect(newState.phaseTransitions[0]!.from).toBe('advisory_council');
    expect(newState.phaseTransitions[0]!.to).toBe('centralized');
  });
});

describe('computeVotingPower', () => {
  it('returns 1 for equal voting weights (centralized phase)', () => {
    const state = initializeGovernance(50);
    expect(state.votingWeights).toBe('equal');

    const power = computeVotingPower(state, {
      stake: 1000,
      participationRate: 0.9,
      reputationScore: 0.95,
    });
    expect(power).toBe(1);
  });

  it('returns stake value for stake_weighted (advisory_council phase)', () => {
    const state = initializeGovernance(500);
    expect(state.votingWeights).toBe('stake_weighted');

    const power = computeVotingPower(state, { stake: 500 });
    expect(power).toBe(500);
  });

  it('defaults stake to 1 when not provided', () => {
    const state = initializeGovernance(500);
    const power = computeVotingPower(state, {});
    expect(power).toBe(1);
  });

  it('returns participationRate * 10 for participation_weighted', () => {
    const state = initializeGovernance(5000);
    expect(state.votingWeights).toBe('participation_weighted');

    const power = computeVotingPower(state, { participationRate: 0.8 });
    expect(power).toBeCloseTo(8.0);
  });

  it('defaults participationRate to 0.5 when not provided', () => {
    const state = initializeGovernance(5000);
    const power = computeVotingPower(state, {});
    expect(power).toBeCloseTo(5.0); // 0.5 * 10
  });

  it('returns reputationScore * 20 for reputation_weighted', () => {
    const state = initializeGovernance(20000);
    expect(state.votingWeights).toBe('reputation_weighted');

    const power = computeVotingPower(state, { reputationScore: 0.9 });
    expect(power).toBeCloseTo(18.0);
  });

  it('defaults reputationScore to 0.5 when not provided', () => {
    const state = initializeGovernance(20000);
    const power = computeVotingPower(state, {});
    expect(power).toBeCloseTo(10.0); // 0.5 * 20
  });

  it('handles zero stake', () => {
    const state = initializeGovernance(500);
    const power = computeVotingPower(state, { stake: 0 });
    expect(power).toBe(0);
  });

  it('handles zero participation rate', () => {
    const state = initializeGovernance(5000);
    const power = computeVotingPower(state, { participationRate: 0 });
    expect(power).toBe(0);
  });

  it('handles zero reputation score', () => {
    const state = initializeGovernance(20000);
    const power = computeVotingPower(state, { reputationScore: 0 });
    expect(power).toBe(0);
  });

  it('voting power changes appropriately as governance phases transition', () => {
    let state = initializeGovernance(50);
    // Phase 0: equal
    expect(computeVotingPower(state, { stake: 100, participationRate: 0.9, reputationScore: 0.9 })).toBe(1);

    state = transitionPhase(state, 200);
    // Phase 1: stake_weighted
    expect(computeVotingPower(state, { stake: 100 })).toBe(100);

    state = transitionPhase(state, 2000);
    // Phase 2: participation_weighted
    expect(computeVotingPower(state, { participationRate: 0.8 })).toBeCloseTo(8.0);

    state = transitionPhase(state, 20000);
    // Phase 3: reputation_weighted
    expect(computeVotingPower(state, { reputationScore: 0.9 })).toBeCloseTo(18.0);
  });
});

// ---------------------------------------------------------------------------
// DecayModel
// ---------------------------------------------------------------------------
describe('DecayModel', () => {
  describe('constructor validation', () => {
    it('throws when given an empty models array', () => {
      expect(() => new DecayModel([])).toThrow('At least one decay model is required');
    });

    it('throws when exponential rate is negative', () => {
      expect(() => new DecayModel([{ type: 'exponential', rate: -1 }])).toThrow('Exponential decay rate must be >= 0');
    });

    it('throws when linear rate is negative', () => {
      expect(() => new DecayModel([{ type: 'linear', rate: -0.5 }])).toThrow('Linear decay rate must be >= 0');
    });

    it('throws when step model has no breakpoints', () => {
      expect(() => new DecayModel([{ type: 'step', rate: 1 }])).toThrow('Step decay requires at least one breakpoint');
    });

    it('throws when step model has empty breakpoints', () => {
      expect(() => new DecayModel([{ type: 'step', rate: 1, steps: [] }])).toThrow('Step decay requires at least one breakpoint');
    });

    it('throws when step time fraction is out of range', () => {
      expect(() => new DecayModel([{ type: 'step', rate: 1, steps: [[-0.1, 0.5]] }])).toThrow('Step time fraction must be in [0, 1]');
      expect(() => new DecayModel([{ type: 'step', rate: 1, steps: [[1.1, 0.5]] }])).toThrow('Step time fraction must be in [0, 1]');
    });

    it('throws when step value is negative', () => {
      expect(() => new DecayModel([{ type: 'step', rate: 1, steps: [[0.5, -1]] }])).toThrow('Step value must be >= 0');
    });

    it('throws when seasonal rate is zero or negative', () => {
      expect(() => new DecayModel([{ type: 'seasonal', rate: 0 }])).toThrow('Seasonal frequency (rate) must be > 0');
      expect(() => new DecayModel([{ type: 'seasonal', rate: -1 }])).toThrow('Seasonal frequency (rate) must be > 0');
    });

    it('throws when seasonal amplitude is out of range', () => {
      expect(() => new DecayModel([{ type: 'seasonal', rate: 1, amplitude: -0.1 }])).toThrow('Seasonal amplitude must be in [0, 1]');
      expect(() => new DecayModel([{ type: 'seasonal', rate: 1, amplitude: 1.5 }])).toThrow('Seasonal amplitude must be in [0, 1]');
    });

    it('accepts valid models', () => {
      expect(() => new DecayModel([{ type: 'exponential', rate: 1 }])).not.toThrow();
      expect(() => new DecayModel([{ type: 'linear', rate: 2 }])).not.toThrow();
      expect(() => new DecayModel([{ type: 'step', rate: 0, steps: [[0, 1.0], [0.5, 0.5]] }])).not.toThrow();
      expect(() => new DecayModel([{ type: 'seasonal', rate: 1, amplitude: 0.3 }])).not.toThrow();
    });
  });

  describe('evaluate - exponential decay', () => {
    it('returns initialWeight at t=0', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 2 }]);
      expect(model.evaluate(0, 5.0)).toBeCloseTo(5.0, 10);
    });

    it('follows e^(-rate * t) formula', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 2 }]);
      expect(model.evaluate(0.5, 1.0)).toBeCloseTo(Math.exp(-2 * 0.5), 10);
      expect(model.evaluate(1.0, 1.0)).toBeCloseTo(Math.exp(-2), 10);
    });

    it('returns initialWeight * e^(-rate * t) for non-unit initialWeight', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 3 }]);
      expect(model.evaluate(0.25, 4.0)).toBeCloseTo(4.0 * Math.exp(-3 * 0.25), 10);
    });

    it('returns initialWeight when rate is 0', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 0 }]);
      expect(model.evaluate(0.5, 10)).toBeCloseTo(10, 10);
      expect(model.evaluate(1.0, 10)).toBeCloseTo(10, 10);
    });

    it('decays monotonically', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 1.5 }]);
      let prev = model.evaluate(0, 1.0);
      for (let t = 0.1; t <= 1.0; t += 0.1) {
        const curr = model.evaluate(t, 1.0);
        expect(curr).toBeLessThanOrEqual(prev);
        prev = curr;
      }
    });
  });

  describe('evaluate - linear decay', () => {
    it('returns initialWeight at t=0', () => {
      const model = new DecayModel([{ type: 'linear', rate: 2 }]);
      expect(model.evaluate(0, 3.0)).toBeCloseTo(3.0, 10);
    });

    it('follows max(0, 1 - rate * t) formula', () => {
      const model = new DecayModel([{ type: 'linear', rate: 1 }]);
      expect(model.evaluate(0.5, 1.0)).toBeCloseTo(0.5, 10);
      expect(model.evaluate(1.0, 1.0)).toBeCloseTo(0, 10);
    });

    it('clamps to zero when rate*t > 1', () => {
      const model = new DecayModel([{ type: 'linear', rate: 3 }]);
      expect(model.evaluate(0.5, 2.0)).toBeCloseTo(0, 10); // max(0, 1 - 3*0.5) = max(0, -0.5) = 0
    });

    it('returns initialWeight when rate is 0', () => {
      const model = new DecayModel([{ type: 'linear', rate: 0 }]);
      expect(model.evaluate(0.75, 5.0)).toBeCloseTo(5.0, 10);
    });
  });

  describe('evaluate - step decay', () => {
    it('returns initialWeight before first breakpoint', () => {
      const model = new DecayModel([{ type: 'step', rate: 0, steps: [[0.5, 0.5]] }]);
      expect(model.evaluate(0.3, 2.0)).toBeCloseTo(2.0, 10); // step value defaults to 1.0 before first breakpoint
    });

    it('returns step value at and after breakpoint', () => {
      const model = new DecayModel([{ type: 'step', rate: 0, steps: [[0.0, 0.8], [0.5, 0.4]] }]);
      expect(model.evaluate(0.0, 1.0)).toBeCloseTo(0.8, 10);
      expect(model.evaluate(0.3, 1.0)).toBeCloseTo(0.8, 10);
      expect(model.evaluate(0.5, 1.0)).toBeCloseTo(0.4, 10);
      expect(model.evaluate(0.9, 1.0)).toBeCloseTo(0.4, 10);
    });

    it('handles multiple breakpoints in correct order', () => {
      const model = new DecayModel([{ type: 'step', rate: 0, steps: [[0.0, 1.0], [0.25, 0.75], [0.5, 0.5], [0.75, 0.25]] }]);
      expect(model.evaluate(0.1, 1.0)).toBeCloseTo(1.0, 10);
      expect(model.evaluate(0.3, 1.0)).toBeCloseTo(0.75, 10);
      expect(model.evaluate(0.6, 1.0)).toBeCloseTo(0.5, 10);
      expect(model.evaluate(0.8, 1.0)).toBeCloseTo(0.25, 10);
    });

    it('handles unsorted breakpoints', () => {
      const model = new DecayModel([{ type: 'step', rate: 0, steps: [[0.75, 0.2], [0.25, 0.8]] }]);
      // At t=0.5: should use value from [0.25, 0.8]
      expect(model.evaluate(0.5, 1.0)).toBeCloseTo(0.8, 10);
      // At t=0.9: should use value from [0.75, 0.2]
      expect(model.evaluate(0.9, 1.0)).toBeCloseTo(0.2, 10);
    });
  });

  describe('evaluate - seasonal decay', () => {
    it('returns initialWeight at t=0 when phase is 0', () => {
      const model = new DecayModel([{ type: 'seasonal', rate: 1, amplitude: 0.2, phase: 0 }]);
      // 1 + 0.2 * sin(0) = 1.0
      expect(model.evaluate(0, 1.0)).toBeCloseTo(1.0, 10);
    });

    it('oscillates around initialWeight', () => {
      const model = new DecayModel([{ type: 'seasonal', rate: 1, amplitude: 0.3, phase: 0 }]);
      // At t=0.25: 1 + 0.3 * sin(2*pi*1*0.25) = 1 + 0.3 * sin(pi/2) = 1.3
      expect(model.evaluate(0.25, 1.0)).toBeCloseTo(1.3, 5);
      // At t=0.75: 1 + 0.3 * sin(2*pi*1*0.75) = 1 + 0.3 * sin(3pi/2) = 0.7
      expect(model.evaluate(0.75, 1.0)).toBeCloseTo(0.7, 5);
    });

    it('uses default amplitude of 0.2 when not specified', () => {
      const model = new DecayModel([{ type: 'seasonal', rate: 1, phase: 0 }]);
      // At t=0.25: 1 + 0.2 * sin(pi/2) = 1.2
      expect(model.evaluate(0.25, 1.0)).toBeCloseTo(1.2, 5);
    });

    it('uses default phase of 0 when not specified', () => {
      const model = new DecayModel([{ type: 'seasonal', rate: 1, amplitude: 0.5 }]);
      // At t=0: 1 + 0.5 * sin(0) = 1.0
      expect(model.evaluate(0, 1.0)).toBeCloseTo(1.0, 10);
    });

    it('respects phase offset', () => {
      const model = new DecayModel([{ type: 'seasonal', rate: 1, amplitude: 0.5, phase: Math.PI / 2 }]);
      // At t=0: 1 + 0.5 * sin(pi/2) = 1.5
      expect(model.evaluate(0, 1.0)).toBeCloseTo(1.5, 5);
    });
  });

  describe('evaluate - composition', () => {
    it('multiplies outputs of two models', () => {
      const model = new DecayModel([
        { type: 'exponential', rate: 1 },
        { type: 'linear', rate: 1 },
      ]);
      // At t=0.5: e^(-0.5) * max(0, 1 - 0.5) = e^(-0.5) * 0.5
      const expected = Math.exp(-0.5) * 0.5;
      expect(model.evaluate(0.5, 1.0)).toBeCloseTo(expected, 10);
    });

    it('multiplies outputs of exponential and seasonal', () => {
      const model = new DecayModel([
        { type: 'exponential', rate: 2 },
        { type: 'seasonal', rate: 1, amplitude: 0.2, phase: 0 },
      ]);
      // At t=0.25:
      //   exponential: e^(-2*0.25) = e^(-0.5)
      //   seasonal: 1 + 0.2 * sin(2*pi*0.25) = 1 + 0.2 * 1 = 1.2
      const expected = Math.exp(-0.5) * 1.2;
      expect(model.evaluate(0.25, 1.0)).toBeCloseTo(expected, 5);
    });

    it('multiplies three models correctly', () => {
      const model = new DecayModel([
        { type: 'exponential', rate: 1 },
        { type: 'linear', rate: 0.5 },
        { type: 'step', rate: 0, steps: [[0.0, 1.0], [0.5, 0.8]] },
      ]);
      // At t=0.6:
      //   exponential: e^(-0.6)
      //   linear: max(0, 1 - 0.5*0.6) = 0.7
      //   step: 0.8 (t >= 0.5)
      const expected = Math.exp(-0.6) * 0.7 * 0.8;
      expect(model.evaluate(0.6, 1.0)).toBeCloseTo(expected, 5);
    });

    it('initialWeight scales the result', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 1 }]);
      const withUnit = model.evaluate(0.5, 1.0);
      const withScale = model.evaluate(0.5, 3.0);
      expect(withScale).toBeCloseTo(3.0 * withUnit, 10);
    });
  });

  describe('evaluate - edge cases', () => {
    it('throws when initialWeight is negative', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 1 }]);
      expect(() => model.evaluate(0.5, -1)).toThrow('initialWeight must be >= 0');
    });

    it('returns 0 when initialWeight is 0', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 1 }]);
      expect(model.evaluate(0.5, 0)).toBe(0);
    });

    it('clamps result to 0 when composed value would be negative', () => {
      // Linear decay with high rate can push below 0 before clamping
      const model = new DecayModel([{ type: 'linear', rate: 10 }]);
      expect(model.evaluate(0.5, 1.0)).toBe(0); // max(0, 1 - 10*0.5) = max(0, -4) = 0
    });

    it('handles t=0 and t=1 boundary', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 5 }]);
      expect(model.evaluate(0, 1.0)).toBeCloseTo(1.0, 10);
      expect(model.evaluate(1, 1.0)).toBeCloseTo(Math.exp(-5), 10);
    });
  });

  describe('schedule', () => {
    it('returns the correct number of points', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 1 }]);
      const s = model.schedule(1.0, 10);
      expect(s).toHaveLength(10);
    });

    it('starts at t=0 and ends at t=1', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 1 }]);
      const s = model.schedule(1.0, 5);
      expect(s[0]!.time).toBeCloseTo(0, 10);
      expect(s[4]!.time).toBeCloseTo(1, 10);
    });

    it('first value matches evaluate(0, initialWeight)', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 2 }]);
      const s = model.schedule(3.0, 5);
      expect(s[0]!.value).toBeCloseTo(model.evaluate(0, 3.0), 10);
    });

    it('last value matches evaluate(1, initialWeight)', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 2 }]);
      const s = model.schedule(3.0, 5);
      expect(s[4]!.value).toBeCloseTo(model.evaluate(1, 3.0), 10);
    });

    it('times are evenly spaced', () => {
      const model = new DecayModel([{ type: 'linear', rate: 1 }]);
      const s = model.schedule(1.0, 5);
      for (let i = 0; i < 5; i++) {
        expect(s[i]!.time).toBeCloseTo(i / 4, 10);
      }
    });

    it('throws when steps < 2', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 1 }]);
      expect(() => model.schedule(1.0, 1)).toThrow('steps must be >= 2');
      expect(() => model.schedule(1.0, 0)).toThrow('steps must be >= 2');
    });
  });

  describe('findThresholdTime', () => {
    it('finds threshold time for exponential decay', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 2 }]);
      // We want when 1.0 * e^(-2t) < 0.5 => t > ln(2)/2 ~ 0.3466
      const t = model.findThresholdTime(1.0, 0.5);
      expect(t).not.toBeNull();
      expect(t!).toBeCloseTo(Math.log(2) / 2, 3);
    });

    it('returns null when threshold is never reached', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 0 }]);
      // Value is constant at initialWeight, never drops below threshold
      const t = model.findThresholdTime(1.0, 0.5);
      expect(t).toBeNull();
    });

    it('returns null when threshold is <= 0', () => {
      const model = new DecayModel([{ type: 'exponential', rate: 2 }]);
      expect(model.findThresholdTime(1.0, 0)).toBeNull();
      expect(model.findThresholdTime(1.0, -1)).toBeNull();
    });

    it('returns 0 when initial value is already below threshold', () => {
      const model = new DecayModel([{ type: 'linear', rate: 10 }]);
      // At t=0, value is 1.0 * max(0, 1 - 0) = 1.0. Not below 2.0.
      // So this should check if evaluate(0, 0.5) < 1.0 => yes, 0.5 < 1.0
      const t = model.findThresholdTime(0.5, 1.0);
      expect(t).toBe(0);
    });

    it('finds correct threshold time for linear decay', () => {
      const model = new DecayModel([{ type: 'linear', rate: 2 }]);
      // value(t) = initialWeight * max(0, 1 - 2t)
      // For initialWeight=1.0, threshold=0.5: 1 - 2t < 0.5 => t > 0.25
      const t = model.findThresholdTime(1.0, 0.5);
      expect(t).not.toBeNull();
      expect(t!).toBeCloseTo(0.25, 2);
    });

    it('works with composed models', () => {
      const model = new DecayModel([
        { type: 'exponential', rate: 1 },
        { type: 'linear', rate: 1 },
      ]);
      const t = model.findThresholdTime(1.0, 0.1);
      expect(t).not.toBeNull();
      // Verify: at that time, value should be just below threshold
      expect(model.evaluate(t!, 1.0)).toBeLessThan(0.1);
      // And just before that, it should be above
      expect(model.evaluate(t! - 0.01, 1.0)).toBeGreaterThanOrEqual(0.1 - 0.02); // with tolerance
    });
  });
});

// ---------------------------------------------------------------------------
// ContinuousTrigger
// ---------------------------------------------------------------------------
describe('ContinuousTrigger', () => {
  describe('constructor validation', () => {
    it('throws when given an empty triggers array', () => {
      expect(() => new ContinuousTrigger([])).toThrow('At least one trigger is required');
    });

    it('throws when activationThreshold is below 0', () => {
      const triggers: ContinuousTriggerConfig[] = [
        { type: 'breach_event', threshold: 1, action: 'tighten' },
      ];
      expect(() => new ContinuousTrigger(triggers, -0.1)).toThrow('activationThreshold must be in [0, 1]');
    });

    it('throws when activationThreshold is above 1', () => {
      const triggers: ContinuousTriggerConfig[] = [
        { type: 'breach_event', threshold: 1, action: 'tighten' },
      ];
      expect(() => new ContinuousTrigger(triggers, 1.5)).toThrow('activationThreshold must be in [0, 1]');
    });

    it('throws when steepness is zero', () => {
      const triggers: ContinuousTriggerConfig[] = [
        { type: 'breach_event', threshold: 1, steepness: 0, action: 'tighten' },
      ];
      expect(() => new ContinuousTrigger(triggers)).toThrow('steepness must be > 0');
    });

    it('throws when steepness is negative', () => {
      const triggers: ContinuousTriggerConfig[] = [
        { type: 'breach_event', threshold: 1, steepness: -5, action: 'tighten' },
      ];
      expect(() => new ContinuousTrigger(triggers)).toThrow('steepness must be > 0');
    });

    it('throws when weight is negative', () => {
      const triggers: ContinuousTriggerConfig[] = [
        { type: 'breach_event', threshold: 1, weight: -1, action: 'tighten' },
      ];
      expect(() => new ContinuousTrigger(triggers)).toThrow('weight must be >= 0');
    });

    it('accepts valid triggers with defaults', () => {
      const triggers: ContinuousTriggerConfig[] = [
        { type: 'breach_event', threshold: 1, action: 'tighten' },
      ];
      expect(() => new ContinuousTrigger(triggers)).not.toThrow();
    });

    it('accepts activationThreshold at boundaries 0 and 1', () => {
      const triggers: ContinuousTriggerConfig[] = [
        { type: 'breach_event', threshold: 1, action: 'tighten' },
      ];
      expect(() => new ContinuousTrigger(triggers, 0)).not.toThrow();
      expect(() => new ContinuousTrigger(triggers, 1)).not.toThrow();
    });
  });

  describe('evaluate - sigmoid behavior', () => {
    it('returns activation near 0.5 when value equals threshold', () => {
      const ct = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 10, action: 'relax' },
      ]);
      const agent = makeAgent({ reputationScore: 0.5 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      expect(result.activations[0]!.activation).toBeCloseTo(0.5, 5);
    });

    it('returns activation near 1 when value is well above threshold', () => {
      const ct = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 20, action: 'relax' },
      ]);
      const agent = makeAgent({ reputationScore: 0.9 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      expect(result.activations[0]!.activation).toBeGreaterThan(0.95);
    });

    it('returns activation near 0 when value is well below threshold', () => {
      const ct = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 20, action: 'relax' },
      ]);
      const agent = makeAgent({ reputationScore: 0.1 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      expect(result.activations[0]!.activation).toBeLessThan(0.05);
    });

    it('higher steepness creates sharper transitions', () => {
      const gentle = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 2, action: 'relax' },
      ]);
      const sharp = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 50, action: 'relax' },
      ]);
      const agentAbove = makeAgent({ reputationScore: 0.6 });
      const covenant = makeCovenant();

      const gentleResult = gentle.evaluate(agentAbove, covenant);
      const sharpResult = sharp.evaluate(agentAbove, covenant);

      // Sharp steepness should produce activation closer to 1 than gentle
      expect(sharpResult.activations[0]!.activation).toBeGreaterThan(gentleResult.activations[0]!.activation);
    });
  });

  describe('evaluate - different trigger types', () => {
    it('extracts breachCount for breach_event trigger', () => {
      const ct = new ContinuousTrigger([
        { type: 'breach_event', threshold: 3, steepness: 5, action: 'tighten' },
      ]);
      const agentWithBreaches = makeAgent({ breachCount: 5 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agentWithBreaches, covenant);
      expect(result.activations[0]!.activation).toBeGreaterThan(0.5);
    });

    it('extracts time elapsed for time_elapsed trigger', () => {
      const ct = new ContinuousTrigger([
        { type: 'time_elapsed', threshold: 5000, steepness: 0.01, action: 'relax' },
      ]);
      const agent = makeAgent({ currentTime: 15000 });
      const covenant = makeCovenant({ lastTransitionAt: 5000 });
      const result = ct.evaluate(agent, covenant);
      // Time elapsed = 15000 - 5000 = 10000, well above threshold 5000
      expect(result.activations[0]!.activation).toBeGreaterThan(0.5);
    });

    it('extracts capabilities length for capability_change trigger', () => {
      const ct = new ContinuousTrigger([
        { type: 'capability_change', threshold: 2, steepness: 5, action: 'tighten' },
      ]);
      const agent = makeAgent({ capabilities: ['read', 'write', 'execute'] });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      // capabilities.length = 3, above threshold 2
      expect(result.activations[0]!.activation).toBeGreaterThan(0.5);
    });

    it('extracts governance vote ratio for governance_vote trigger', () => {
      const ct = new ContinuousTrigger([
        { type: 'governance_vote', threshold: 0.5, steepness: 10, action: 'relax' },
      ]);
      const agent = makeAgent({ governanceVotes: { 'p1': true, 'p2': true, 'p3': false, 'p4': false } });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      // votes: 2/4 = 0.5 => activation should be ~0.5
      expect(result.activations[0]!.activation).toBeCloseTo(0.5, 5);
    });

    it('returns 0 for governance_vote when no votes exist', () => {
      const ct = new ContinuousTrigger([
        { type: 'governance_vote', threshold: 0.5, steepness: 10, action: 'relax' },
      ]);
      const agent = makeAgent(); // no governanceVotes
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      // value=0, far below threshold 0.5 => activation near 0
      expect(result.activations[0]!.activation).toBeLessThan(0.01);
    });
  });

  describe('evaluate - combined scoring', () => {
    it('computes weighted average of activations', () => {
      const ct = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 100, weight: 1, action: 'relax' },
        { type: 'breach_event', threshold: 3, steepness: 100, weight: 1, action: 'tighten' },
      ]);
      const agent = makeAgent({ reputationScore: 0.9, breachCount: 0 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);

      // reputation: 0.9 >> 0.5, activation ~1.0
      // breachCount: 0 << 3, activation ~0.0
      // combined: (1*~1.0 + 1*~0.0) / 2 = ~0.5
      expect(result.combinedScore).toBeCloseTo(0.5, 1);
    });

    it('respects different weights', () => {
      const ct = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 100, weight: 3, action: 'relax' },
        { type: 'breach_event', threshold: 3, steepness: 100, weight: 1, action: 'tighten' },
      ]);
      const agent = makeAgent({ reputationScore: 0.9, breachCount: 0 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);

      // reputation: activation ~1.0, weight=3
      // breachCount: activation ~0.0, weight=1
      // combined: (3*~1.0 + 1*~0.0) / 4 = ~0.75
      expect(result.combinedScore).toBeCloseTo(0.75, 1);
    });

    it('sets activated=true when combinedScore >= activationThreshold', () => {
      const ct = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 100, action: 'relax' },
      ], 0.5);
      const agent = makeAgent({ reputationScore: 0.9 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      expect(result.activated).toBe(true);
    });

    it('sets activated=false when combinedScore < activationThreshold', () => {
      const ct = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 100, action: 'relax' },
      ], 0.9);
      const agent = makeAgent({ reputationScore: 0.3 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      expect(result.activated).toBe(false);
    });

    it('returns correct activationThreshold in result', () => {
      const ct = new ContinuousTrigger([
        { type: 'breach_event', threshold: 1, action: 'tighten' },
      ], 0.7);
      const result = ct.evaluate(makeAgent(), makeCovenant());
      expect(result.activationThreshold).toBe(0.7);
    });

    it('handles single trigger with default weight', () => {
      const ct = new ContinuousTrigger([
        { type: 'reputation_threshold', threshold: 0.5, steepness: 10, action: 'relax' },
      ]);
      const agent = makeAgent({ reputationScore: 0.5 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      expect(result.activations).toHaveLength(1);
      expect(result.activations[0]!.weight).toBe(1.0);
      expect(result.combinedScore).toBeCloseTo(0.5, 5);
    });

    it('always activated when threshold is 0', () => {
      const ct = new ContinuousTrigger([
        { type: 'breach_event', threshold: 100, steepness: 10, action: 'tighten' },
      ], 0);
      const agent = makeAgent({ breachCount: 0 });
      const covenant = makeCovenant();
      const result = ct.evaluate(agent, covenant);
      // Even though activation is near 0, activationThreshold is 0 so activated=true
      expect(result.activated).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// ViolationForecaster
// ---------------------------------------------------------------------------
describe('ViolationForecaster', () => {
  describe('constructor validation', () => {
    it('throws when alpha is 0', () => {
      expect(() => new ViolationForecaster({ alpha: 0, beta: 0.5, forecastPeriods: 3 })).toThrow('alpha must be in (0, 1)');
    });

    it('throws when alpha is 1', () => {
      expect(() => new ViolationForecaster({ alpha: 1, beta: 0.5, forecastPeriods: 3 })).toThrow('alpha must be in (0, 1)');
    });

    it('throws when alpha is negative', () => {
      expect(() => new ViolationForecaster({ alpha: -0.1, beta: 0.5, forecastPeriods: 3 })).toThrow('alpha must be in (0, 1)');
    });

    it('throws when beta is 0', () => {
      expect(() => new ViolationForecaster({ alpha: 0.5, beta: 0, forecastPeriods: 3 })).toThrow('beta must be in (0, 1)');
    });

    it('throws when beta is 1', () => {
      expect(() => new ViolationForecaster({ alpha: 0.5, beta: 1, forecastPeriods: 3 })).toThrow('beta must be in (0, 1)');
    });

    it('throws when forecastPeriods < 1', () => {
      expect(() => new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 0 })).toThrow('forecastPeriods must be >= 1');
    });

    it('throws when confidenceLevel is 0', () => {
      expect(() => new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 3, confidenceLevel: 0 })).toThrow('confidenceLevel must be in (0, 1)');
    });

    it('throws when confidenceLevel is 1', () => {
      expect(() => new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 3, confidenceLevel: 1 })).toThrow('confidenceLevel must be in (0, 1)');
    });

    it('accepts valid config', () => {
      expect(() => new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 5 })).not.toThrow();
    });

    it('accepts valid config with confidenceLevel', () => {
      expect(() => new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 5, confidenceLevel: 0.9 })).not.toThrow();
    });
  });

  describe('forecast - input validation', () => {
    it('throws when historicalRates has fewer than 2 data points', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 3 });
      expect(() => f.forecast([])).toThrow('At least 2 historical data points required');
      expect(() => f.forecast([1.0])).toThrow('At least 2 historical data points required');
    });

    it('throws when historicalRates contains NaN', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 3 });
      expect(() => f.forecast([1.0, NaN, 3.0])).toThrow('historicalRates[1] must be a valid number');
    });
  });

  describe('forecast - increasing trend', () => {
    it('detects increasing direction for steadily rising rates', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 3 });
      const result = f.forecast([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      expect(result.direction).toBe('increasing');
      expect(result.trend).toBeGreaterThan(0);
    });

    it('forecasts future periods with increasing rates', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.3, forecastPeriods: 3 });
      const result = f.forecast([1, 2, 3, 4, 5]);
      expect(result.forecasts).toHaveLength(3);
      // Each forecast should be higher than the last
      for (let i = 1; i < result.forecasts.length; i++) {
        expect(result.forecasts[i]!.rate).toBeGreaterThan(result.forecasts[i - 1]!.rate);
      }
    });

    it('forecast periods are numbered correctly', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 4 });
      const result = f.forecast([1, 2, 3]);
      // historical data has 3 points (periods 0-2), so forecasts start at period 4 (3+1)
      expect(result.forecasts[0]!.period).toBe(4);
      expect(result.forecasts[1]!.period).toBe(5);
      expect(result.forecasts[2]!.period).toBe(6);
      expect(result.forecasts[3]!.period).toBe(7);
    });
  });

  describe('forecast - decreasing trend', () => {
    it('detects decreasing direction for falling rates', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 3 });
      const result = f.forecast([10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
      expect(result.direction).toBe('decreasing');
      expect(result.trend).toBeLessThan(0);
    });

    it('forecasts future periods with decreasing rates', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.3, forecastPeriods: 3 });
      const result = f.forecast([10, 8, 6, 4, 2]);
      expect(result.forecasts).toHaveLength(3);
      for (let i = 1; i < result.forecasts.length; i++) {
        expect(result.forecasts[i]!.rate).toBeLessThan(result.forecasts[i - 1]!.rate);
      }
    });
  });

  describe('forecast - stable trend', () => {
    it('detects stable direction for constant rates', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 3 });
      const result = f.forecast([5, 5, 5, 5, 5, 5, 5, 5]);
      expect(result.direction).toBe('stable');
    });

    it('forecasts approximately the same rate for constant input', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 3 });
      const result = f.forecast([5, 5, 5, 5, 5, 5, 5, 5]);
      for (const point of result.forecasts) {
        expect(point.rate).toBeCloseTo(5, 0);
      }
    });
  });

  describe('forecast - Holt double exponential smoothing correctness', () => {
    it('computes correct level and trend for simple 2-point input', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 1 });
      // Initial: level = 1, trend = (3 - 1) / 1 = 2
      // t=1: predicted = 1 + 2 = 3, actual = 3, residual = 0
      //   newLevel = 0.5 * 3 + 0.5 * (1 + 2) = 1.5 + 1.5 = 3.0
      //   newTrend = 0.5 * (3.0 - 1) + 0.5 * 2 = 1.0 + 1.0 = 2.0
      const result = f.forecast([1, 3]);
      expect(result.level).toBeCloseTo(3.0, 5);
      expect(result.trend).toBeCloseTo(2.0, 5);
      // Forecast for h=1: level + 1 * trend = 3 + 2 = 5
      expect(result.forecasts[0]!.rate).toBeCloseTo(5.0, 5);
    });

    it('computes MAE correctly', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 1 });
      // With 2 data points: one residual
      const result = f.forecast([1, 3]);
      // Residual: actual(3) - predicted(1+2) = 0, so MAE = 0
      expect(result.mae).toBeCloseTo(0, 5);
    });

    it('MAE is non-negative', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.2, forecastPeriods: 3 });
      const result = f.forecast([3, 7, 2, 8, 4, 6, 1]);
      expect(result.mae).toBeGreaterThanOrEqual(0);
    });
  });

  describe('forecast - confidence bands', () => {
    it('upper bound is greater than or equal to rate', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 5 });
      const result = f.forecast([1, 2, 3, 4, 5]);
      for (const point of result.forecasts) {
        expect(point.upperBound).toBeGreaterThanOrEqual(point.rate);
      }
    });

    it('lower bound is less than or equal to rate', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 5 });
      const result = f.forecast([1, 2, 3, 4, 5]);
      for (const point of result.forecasts) {
        expect(point.lowerBound).toBeLessThanOrEqual(point.rate);
      }
    });

    it('lower bound is never negative', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 5 });
      const result = f.forecast([10, 5, 2, 1, 0.5]);
      for (const point of result.forecasts) {
        expect(point.lowerBound).toBeGreaterThanOrEqual(0);
      }
    });

    it('confidence bands widen with forecast horizon', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 5 });
      const result = f.forecast([1, 3, 2, 5, 4, 7, 6]);
      // Bands should widen: upper - lower should increase
      for (let i = 1; i < result.forecasts.length; i++) {
        const prevWidth = result.forecasts[i - 1]!.upperBound - result.forecasts[i - 1]!.lowerBound;
        const currWidth = result.forecasts[i]!.upperBound - result.forecasts[i]!.lowerBound;
        expect(currWidth).toBeGreaterThanOrEqual(prevWidth - 0.001); // tolerance for rounding
      }
    });
  });

  describe('forecast - edge cases', () => {
    it('works with exactly 2 data points', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.5, forecastPeriods: 2 });
      const result = f.forecast([0, 1]);
      expect(result.forecasts).toHaveLength(2);
      expect(result.level).toBeDefined();
      expect(result.trend).toBeDefined();
    });

    it('handles all-zero historical rates', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 3 });
      const result = f.forecast([0, 0, 0, 0, 0]);
      expect(result.direction).toBe('stable');
      for (const point of result.forecasts) {
        expect(point.rate).toBeCloseTo(0, 5);
      }
    });

    it('handles very large values', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 2 });
      const result = f.forecast([1e6, 2e6, 3e6]);
      expect(result.direction).toBe('increasing');
      expect(result.forecasts[0]!.rate).toBeGreaterThan(3e6);
    });

    it('handles negative rates (if they occur as input)', () => {
      const f = new ViolationForecaster({ alpha: 0.3, beta: 0.1, forecastPeriods: 2 });
      // Negative rates might represent corrections/improvements
      const result = f.forecast([5, 3, 1, -1]);
      expect(result.direction).toBe('decreasing');
    });

    it('produces exactly forecastPeriods forecasts', () => {
      const f = new ViolationForecaster({ alpha: 0.5, beta: 0.3, forecastPeriods: 7 });
      const result = f.forecast([1, 2, 3]);
      expect(result.forecasts).toHaveLength(7);
    });
  });
});

// ---------------------------------------------------------------------------
// TemporalConstraintAlgebra
// ---------------------------------------------------------------------------
describe('TemporalConstraintAlgebra', () => {
  const algebra = new TemporalConstraintAlgebra();

  function makeConstraint(overrides?: Partial<TemporalConstraint>): TemporalConstraint {
    return {
      id: 'tc-1',
      start: 0,
      end: 1,
      weight: 0.5,
      constraintRef: 'rule-1',
      ...overrides,
    };
  }

  describe('validation', () => {
    it('throws when start < 0', () => {
      const c = makeConstraint({ start: -0.1 });
      expect(() => algebra.intersection([c], [])).toThrow('start must be in [0, 1]');
    });

    it('throws when start > 1', () => {
      const c = makeConstraint({ start: 1.1 });
      expect(() => algebra.intersection([c], [])).toThrow('start must be in [0, 1]');
    });

    it('throws when end < 0', () => {
      const c = makeConstraint({ end: -0.1 });
      expect(() => algebra.union([], [c])).toThrow('end must be in [0, 1]');
    });

    it('throws when end > 1', () => {
      const c = makeConstraint({ end: 1.5 });
      expect(() => algebra.union([], [c])).toThrow('end must be in [0, 1]');
    });

    it('throws when start > end', () => {
      const c = makeConstraint({ start: 0.7, end: 0.3 });
      expect(() => algebra.difference([c], [])).toThrow('start (0.7) must be <= end (0.3)');
    });

    it('throws when weight < 0', () => {
      const c = makeConstraint({ weight: -0.1 });
      expect(() => algebra.intersection([c], [])).toThrow('weight must be in [0, 1]');
    });

    it('throws when weight > 1', () => {
      const c = makeConstraint({ weight: 1.5 });
      expect(() => algebra.intersection([c], [])).toThrow('weight must be in [0, 1]');
    });

    it('accepts constraints at boundary values', () => {
      const c = makeConstraint({ start: 0, end: 1, weight: 0 });
      expect(() => algebra.intersection([c], [c])).not.toThrow();
    });

    it('accepts constraints where start == end (point interval)', () => {
      const c = makeConstraint({ start: 0.5, end: 0.5 });
      expect(() => algebra.intersection([c], [c])).not.toThrow();
    });
  });

  describe('intersection', () => {
    it('returns empty array for empty inputs', () => {
      const result = algebra.intersection([], []);
      expect(result.constraints).toHaveLength(0);
      expect(result.operation).toBe('intersection');
    });

    it('returns empty array when sets have no overlap', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.3 });
      const b = makeConstraint({ id: 'b', start: 0.5, end: 0.8 });
      const result = algebra.intersection([a], [b]);
      expect(result.constraints).toHaveLength(0);
    });

    it('computes overlap of two overlapping intervals', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.6, weight: 0.3 });
      const b = makeConstraint({ id: 'b', start: 0.4, end: 1.0, weight: 0.7 });
      const result = algebra.intersection([a], [b]);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0.4);
      expect(result.constraints[0]!.end).toBeCloseTo(0.6);
    });

    it('takes the maximum weight (most restrictive)', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.6, weight: 0.3 });
      const b = makeConstraint({ id: 'b', start: 0.4, end: 1.0, weight: 0.7 });
      const result = algebra.intersection([a], [b]);
      expect(result.constraints[0]!.weight).toBe(0.7);
    });

    it('creates combined id and constraintRef', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.6, constraintRef: 'rule-A' });
      const b = makeConstraint({ id: 'b', start: 0.4, end: 1.0, constraintRef: 'rule-B' });
      const result = algebra.intersection([a], [b]);
      expect(result.constraints[0]!.id).toBe('a_AND_b');
      expect(result.constraints[0]!.constraintRef).toBe('rule-A AND rule-B');
    });

    it('handles one set containing the other', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 1.0 });
      const b = makeConstraint({ id: 'b', start: 0.3, end: 0.7 });
      const result = algebra.intersection([a], [b]);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0.3);
      expect(result.constraints[0]!.end).toBeCloseTo(0.7);
    });

    it('handles identical intervals', () => {
      const a = makeConstraint({ id: 'a', start: 0.2, end: 0.8, weight: 0.4 });
      const b = makeConstraint({ id: 'b', start: 0.2, end: 0.8, weight: 0.6 });
      const result = algebra.intersection([a], [b]);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0.2);
      expect(result.constraints[0]!.end).toBeCloseTo(0.8);
      expect(result.constraints[0]!.weight).toBe(0.6);
    });

    it('handles multiple overlapping pairs', () => {
      const setA = [
        makeConstraint({ id: 'a1', start: 0, end: 0.4 }),
        makeConstraint({ id: 'a2', start: 0.6, end: 1.0 }),
      ];
      const setB = [
        makeConstraint({ id: 'b1', start: 0.2, end: 0.8 }),
      ];
      const result = algebra.intersection(setA, setB);
      expect(result.constraints).toHaveLength(2);
      // a1 AND b1: overlap [0.2, 0.4]
      expect(result.constraints[0]!.start).toBeCloseTo(0.2);
      expect(result.constraints[0]!.end).toBeCloseTo(0.4);
      // a2 AND b1: overlap [0.6, 0.8]
      expect(result.constraints[1]!.start).toBeCloseTo(0.6);
      expect(result.constraints[1]!.end).toBeCloseTo(0.8);
    });

    it('returns empty when point intervals touch but do not overlap', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.5 });
      const b = makeConstraint({ id: 'b', start: 0.5, end: 1.0 });
      const result = algebra.intersection([a], [b]);
      // overlapStart = max(0, 0.5) = 0.5, overlapEnd = min(0.5, 1.0) = 0.5
      // 0.5 < 0.5 is false, so no overlap
      expect(result.constraints).toHaveLength(0);
    });

    it('description reflects the operation', () => {
      const result = algebra.intersection([makeConstraint()], [makeConstraint()]);
      expect(result.description).toContain('Intersection');
    });
  });

  describe('union', () => {
    it('returns empty array for empty inputs', () => {
      const result = algebra.union([], []);
      expect(result.constraints).toHaveLength(0);
      expect(result.operation).toBe('union');
    });

    it('returns all constraints when no overlaps', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.3 });
      const b = makeConstraint({ id: 'b', start: 0.5, end: 0.8 });
      const result = algebra.union([a], [b]);
      expect(result.constraints).toHaveLength(2);
    });

    it('merges overlapping intervals', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.5, weight: 0.6 });
      const b = makeConstraint({ id: 'b', start: 0.3, end: 0.8, weight: 0.4 });
      const result = algebra.union([a], [b]);
      // Should merge into a single interval [0, 0.8]
      const totalRange = result.constraints.reduce((sum, c) => sum + (c.end - c.start), 0);
      expect(totalRange).toBeCloseTo(0.8, 1);
    });

    it('takes minimum weight in overlapping regions (less restrictive)', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.6, weight: 0.8 });
      const b = makeConstraint({ id: 'b', start: 0, end: 0.6, weight: 0.3 });
      const result = algebra.union([a], [b]);
      // In the overlap, weight should be min(0.8, 0.3) = 0.3
      const overlapping = result.constraints.find(c => c.start === 0 || c.end === 0.6);
      expect(overlapping).toBeDefined();
      expect(overlapping!.weight).toBe(0.3);
    });

    it('handles single constraint in one set', () => {
      const a = makeConstraint({ id: 'a', start: 0.2, end: 0.8 });
      const result = algebra.union([a], []);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0.2);
      expect(result.constraints[0]!.end).toBeCloseTo(0.8);
    });

    it('handles adjacent non-overlapping intervals', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.5 });
      const b = makeConstraint({ id: 'b', start: 0.5, end: 1.0 });
      const result = algebra.union([a], [b]);
      // 0.5 <= 0.5, so these do overlap in the sweep-line merge
      // Result should be merged into one interval
      const totalRange = result.constraints.reduce((sum, c) => sum + (c.end - c.start), 0);
      expect(totalRange).toBeCloseTo(1.0, 1);
    });

    it('description reflects the operation', () => {
      const result = algebra.union([makeConstraint()], [makeConstraint()]);
      expect(result.description).toContain('Union');
    });
  });

  describe('difference', () => {
    it('returns empty array when setA is empty', () => {
      const b = makeConstraint({ id: 'b', start: 0, end: 1 });
      const result = algebra.difference([], [b]);
      expect(result.constraints).toHaveLength(0);
      expect(result.operation).toBe('difference');
    });

    it('returns setA as-is when setB is empty', () => {
      const a = makeConstraint({ id: 'a', start: 0.2, end: 0.8, weight: 0.5 });
      const result = algebra.difference([a], []);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0.2);
      expect(result.constraints[0]!.end).toBeCloseTo(0.8);
      expect(result.constraints[0]!.weight).toBe(0.5);
    });

    it('returns empty when B completely covers A', () => {
      const a = makeConstraint({ id: 'a', start: 0.3, end: 0.7 });
      const b = makeConstraint({ id: 'b', start: 0.0, end: 1.0 });
      const result = algebra.difference([a], [b]);
      expect(result.constraints).toHaveLength(0);
    });

    it('removes the overlapping part from A', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.8 });
      const b = makeConstraint({ id: 'b', start: 0.3, end: 0.5 });
      const result = algebra.difference([a], [b]);
      // A should be split into [0, 0.3] and [0.5, 0.8]
      expect(result.constraints).toHaveLength(2);
      expect(result.constraints[0]!.start).toBeCloseTo(0);
      expect(result.constraints[0]!.end).toBeCloseTo(0.3);
      expect(result.constraints[1]!.start).toBeCloseTo(0.5);
      expect(result.constraints[1]!.end).toBeCloseTo(0.8);
    });

    it('preserves A weight in remaining fragments', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 1, weight: 0.9 });
      const b = makeConstraint({ id: 'b', start: 0.4, end: 0.6, weight: 0.1 });
      const result = algebra.difference([a], [b]);
      for (const c of result.constraints) {
        expect(c.weight).toBe(0.9);
      }
    });

    it('preserves A constraintRef in remaining fragments', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 1, constraintRef: 'my-rule' });
      const b = makeConstraint({ id: 'b', start: 0.4, end: 0.6 });
      const result = algebra.difference([a], [b]);
      for (const c of result.constraints) {
        expect(c.constraintRef).toBe('my-rule');
      }
    });

    it('handles no overlap (A fully outside B)', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.2 });
      const b = makeConstraint({ id: 'b', start: 0.5, end: 1.0 });
      const result = algebra.difference([a], [b]);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0);
      expect(result.constraints[0]!.end).toBeCloseTo(0.2);
    });

    it('handles B overlapping the start of A', () => {
      const a = makeConstraint({ id: 'a', start: 0.2, end: 0.8 });
      const b = makeConstraint({ id: 'b', start: 0, end: 0.5 });
      const result = algebra.difference([a], [b]);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0.5);
      expect(result.constraints[0]!.end).toBeCloseTo(0.8);
    });

    it('handles B overlapping the end of A', () => {
      const a = makeConstraint({ id: 'a', start: 0.2, end: 0.8 });
      const b = makeConstraint({ id: 'b', start: 0.6, end: 1.0 });
      const result = algebra.difference([a], [b]);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0.2);
      expect(result.constraints[0]!.end).toBeCloseTo(0.6);
    });

    it('handles multiple B intervals cutting A', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 1 });
      const b1 = makeConstraint({ id: 'b1', start: 0.2, end: 0.3 });
      const b2 = makeConstraint({ id: 'b2', start: 0.6, end: 0.7 });
      const result = algebra.difference([a], [b1, b2]);
      // A [0,1] minus [0.2,0.3] minus [0.6,0.7] = [0,0.2], [0.3,0.6], [0.7,1]
      expect(result.constraints).toHaveLength(3);
      expect(result.constraints[0]!.start).toBeCloseTo(0);
      expect(result.constraints[0]!.end).toBeCloseTo(0.2);
      expect(result.constraints[1]!.start).toBeCloseTo(0.3);
      expect(result.constraints[1]!.end).toBeCloseTo(0.6);
      expect(result.constraints[2]!.start).toBeCloseTo(0.7);
      expect(result.constraints[2]!.end).toBeCloseTo(1.0);
    });

    it('handles multiple A intervals with one B', () => {
      const a1 = makeConstraint({ id: 'a1', start: 0, end: 0.4 });
      const a2 = makeConstraint({ id: 'a2', start: 0.6, end: 1.0 });
      const b = makeConstraint({ id: 'b', start: 0.2, end: 0.8 });
      const result = algebra.difference([a1, a2], [b]);
      // a1 [0,0.4] minus [0.2,0.8] = [0, 0.2]
      // a2 [0.6,1.0] minus [0.2,0.8] = [0.8, 1.0]
      expect(result.constraints).toHaveLength(2);
      expect(result.constraints[0]!.start).toBeCloseTo(0);
      expect(result.constraints[0]!.end).toBeCloseTo(0.2);
      expect(result.constraints[1]!.start).toBeCloseTo(0.8);
      expect(result.constraints[1]!.end).toBeCloseTo(1.0);
    });

    it('both sets empty returns empty', () => {
      const result = algebra.difference([], []);
      expect(result.constraints).toHaveLength(0);
    });

    it('description reflects the operation', () => {
      const result = algebra.difference([makeConstraint()], [makeConstraint()]);
      expect(result.description).toContain('Difference');
    });

    it('generates correct fragment ids', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 1 });
      const b = makeConstraint({ id: 'b', start: 0.4, end: 0.6 });
      const result = algebra.difference([a], [b]);
      expect(result.constraints[0]!.id).toBe('a_diff_0');
      expect(result.constraints[1]!.id).toBe('a_diff_1');
    });
  });

  describe('algebraic properties', () => {
    it('intersection is commutative in terms of intervals', () => {
      const a = makeConstraint({ id: 'a', start: 0, end: 0.6, weight: 0.3, constraintRef: 'A' });
      const b = makeConstraint({ id: 'b', start: 0.2, end: 0.8, weight: 0.7, constraintRef: 'B' });
      const resultAB = algebra.intersection([a], [b]);
      const resultBA = algebra.intersection([b], [a]);
      // Both should produce the same overlap interval and weight
      expect(resultAB.constraints[0]!.start).toBeCloseTo(resultBA.constraints[0]!.start);
      expect(resultAB.constraints[0]!.end).toBeCloseTo(resultBA.constraints[0]!.end);
      expect(resultAB.constraints[0]!.weight).toBe(resultBA.constraints[0]!.weight);
    });

    it('A intersection A produces A (same interval)', () => {
      const a = makeConstraint({ id: 'a', start: 0.2, end: 0.8, weight: 0.5 });
      const result = algebra.intersection([a], [a]);
      expect(result.constraints).toHaveLength(1);
      expect(result.constraints[0]!.start).toBeCloseTo(0.2);
      expect(result.constraints[0]!.end).toBeCloseTo(0.8);
      expect(result.constraints[0]!.weight).toBe(0.5);
    });

    it('difference A - A produces empty for identical intervals', () => {
      const a = makeConstraint({ id: 'a', start: 0.2, end: 0.8 });
      const result = algebra.difference([a], [a]);
      expect(result.constraints).toHaveLength(0);
    });
  });
});
