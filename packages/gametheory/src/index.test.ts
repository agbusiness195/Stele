import { describe, it, expect } from 'vitest';
import {
  proveHonesty,
  minimumStake,
  minimumDetection,
  expectedCostOfBreach,
  honestyMargin,
  validateParameters,
  repeatedGameEquilibrium,
  coalitionStability,
  mechanismDesign,
  modelPrincipalAgent,
  analyzeTier,
  defineConjecture,
  getStandardConjectures,
  analyzeImpossibilityBounds,
} from './index';
import type { HonestyParameters } from './types';
import type {
  RepeatedGameParams,
  CoalitionValue,
  MechanismDesignParams,
  OperatorPrincipal,
  PrincipalAgentModel,
  AdoptionTier,
  TierAnalysis,
  Conjecture,
  ConjectureStatus,
  ImpossibilityBound,
} from './index';

// ---------------------------------------------------------------------------
// validateParameters
// ---------------------------------------------------------------------------
describe('validateParameters', () => {
  it('accepts valid full parameters', () => {
    expect(() =>
      validateParameters({
        stakeAmount: 100,
        detectionProbability: 0.5,
        reputationValue: 50,
        maxViolationGain: 200,
        coburn: 10,
      }),
    ).not.toThrow();
  });

  it('accepts valid partial parameters', () => {
    expect(() => validateParameters({ stakeAmount: 0 })).not.toThrow();
    expect(() => validateParameters({ detectionProbability: 1 })).not.toThrow();
    expect(() => validateParameters({})).not.toThrow();
  });

  it('accepts boundary values', () => {
    expect(() =>
      validateParameters({
        stakeAmount: 0,
        detectionProbability: 0,
        reputationValue: 0,
        maxViolationGain: 0,
        coburn: 0,
      }),
    ).not.toThrow();
    expect(() => validateParameters({ detectionProbability: 1 })).not.toThrow();
  });

  it('throws on negative stakeAmount', () => {
    expect(() => validateParameters({ stakeAmount: -1 })).toThrow(
      'stakeAmount must be >= 0',
    );
  });

  it('throws on detectionProbability < 0', () => {
    expect(() => validateParameters({ detectionProbability: -0.1 })).toThrow(
      'detectionProbability must be in [0, 1]',
    );
  });

  it('throws on detectionProbability > 1', () => {
    expect(() => validateParameters({ detectionProbability: 1.5 })).toThrow(
      'detectionProbability must be in [0, 1]',
    );
  });

  it('throws on negative reputationValue', () => {
    expect(() => validateParameters({ reputationValue: -10 })).toThrow(
      'reputationValue must be >= 0',
    );
  });

  it('throws on negative maxViolationGain', () => {
    expect(() => validateParameters({ maxViolationGain: -5 })).toThrow(
      'maxViolationGain must be >= 0',
    );
  });

  it('throws on negative coburn', () => {
    expect(() => validateParameters({ coburn: -1 })).toThrow('coburn must be >= 0');
  });
});

// ---------------------------------------------------------------------------
// proveHonesty
// ---------------------------------------------------------------------------
describe('proveHonesty', () => {
  it('returns isDominantStrategy=true when honesty dominates', () => {
    const params: HonestyParameters = {
      stakeAmount: 1000,
      detectionProbability: 0.8,
      reputationValue: 500,
      maxViolationGain: 100,
      coburn: 50,
    };
    const proof = proveHonesty(params);
    // 1000*0.8 + 500 + 50 = 1350 > 100
    expect(proof.isDominantStrategy).toBe(true);
    expect(proof.margin).toBe(1350 - 100);
  });

  it('returns isDominantStrategy=false when dishonesty dominates', () => {
    const params: HonestyParameters = {
      stakeAmount: 10,
      detectionProbability: 0.1,
      reputationValue: 5,
      maxViolationGain: 1000,
      coburn: 2,
    };
    const proof = proveHonesty(params);
    // 10*0.1 + 5 + 2 = 8 < 1000
    expect(proof.isDominantStrategy).toBe(false);
    expect(proof.margin).toBe(8 - 1000);
  });

  it('returns isDominantStrategy=false at exact boundary (margin = 0)', () => {
    // stake*detection + rep + coburn = maxGain
    // 100*0.5 + 30 + 20 = 100
    const params: HonestyParameters = {
      stakeAmount: 100,
      detectionProbability: 0.5,
      reputationValue: 30,
      maxViolationGain: 100,
      coburn: 20,
    };
    const proof = proveHonesty(params);
    expect(proof.margin).toBeCloseTo(0, 10);
    expect(proof.isDominantStrategy).toBe(false);
  });

  it('computes correct requiredStake', () => {
    const params: HonestyParameters = {
      stakeAmount: 500,
      detectionProbability: 0.5,
      reputationValue: 100,
      maxViolationGain: 400,
      coburn: 50,
    };
    const proof = proveHonesty(params);
    // requiredStake = (400 - 100 - 50) / 0.5 = 500
    expect(proof.requiredStake).toBe(500);
  });

  it('computes correct requiredDetection', () => {
    const params: HonestyParameters = {
      stakeAmount: 1000,
      detectionProbability: 0.5,
      reputationValue: 100,
      maxViolationGain: 600,
      coburn: 0,
    };
    const proof = proveHonesty(params);
    // requiredDetection = (600 - 100 - 0) / 1000 = 0.5
    expect(proof.requiredDetection).toBe(0.5);
  });

  it('formula contains structured step-by-step derivation', () => {
    const params: HonestyParameters = {
      stakeAmount: 100,
      detectionProbability: 0.5,
      reputationValue: 50,
      maxViolationGain: 200,
      coburn: 10,
    };
    const proof = proveHonesty(params);
    // total = 100*0.5 + 50 + 10 = 110
    expect(proof.formula).toContain('Expected cost of dishonesty:');
    expect(proof.formula).toContain('stake(100)');
    expect(proof.formula).toContain('detection(0.5)');
    expect(proof.formula).toContain('reputation(50)');
    expect(proof.formula).toContain('coburn(10)');
    expect(proof.formula).toContain('= 110');
    expect(proof.formula).toContain('Maximum gain from violation: 200');
    expect(proof.formula).toContain('Margin: 110 - 200 = -90');
    expect(proof.formula).toContain('not dominant');
  });

  it('formula indicates dominant strategy when honesty wins', () => {
    const params: HonestyParameters = {
      stakeAmount: 1000,
      detectionProbability: 1.0,
      reputationValue: 500,
      maxViolationGain: 100,
      coburn: 100,
    };
    const proof = proveHonesty(params);
    expect(proof.formula).toContain('Honesty is dominant strategy');
    expect(proof.formula).not.toContain('not dominant');
  });

  it('formula indicates not dominant strategy when dishonesty wins', () => {
    const params: HonestyParameters = {
      stakeAmount: 1,
      detectionProbability: 0.01,
      reputationValue: 0,
      maxViolationGain: 10000,
      coburn: 0,
    };
    const proof = proveHonesty(params);
    expect(proof.formula).toContain('Honesty is not dominant strategy');
  });

  it('throws on invalid parameters', () => {
    expect(() =>
      proveHonesty({
        stakeAmount: -1,
        detectionProbability: 0.5,
        reputationValue: 50,
        maxViolationGain: 200,
        coburn: 10,
      }),
    ).toThrow('stakeAmount must be >= 0');
  });

  it('throws on detectionProbability > 1', () => {
    expect(() =>
      proveHonesty({
        stakeAmount: 100,
        detectionProbability: 1.5,
        reputationValue: 50,
        maxViolationGain: 200,
        coburn: 10,
      }),
    ).toThrow('detectionProbability must be in [0, 1]');
  });

  it('handles maxViolationGain = 0 (honesty always dominates)', () => {
    const params: HonestyParameters = {
      stakeAmount: 100,
      detectionProbability: 0.5,
      reputationValue: 50,
      maxViolationGain: 0,
      coburn: 10,
    };
    const proof = proveHonesty(params);
    // total = 100*0.5 + 50 + 10 = 110, margin = 110 - 0 = 110
    expect(proof.isDominantStrategy).toBe(true);
    expect(proof.margin).toBe(110);
  });

  it('handles all-zero parameters', () => {
    const params: HonestyParameters = {
      stakeAmount: 0,
      detectionProbability: 0,
      reputationValue: 0,
      maxViolationGain: 0,
      coburn: 0,
    };
    const proof = proveHonesty(params);
    expect(proof.margin).toBe(0);
    expect(proof.isDominantStrategy).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// minimumStake
// ---------------------------------------------------------------------------
describe('minimumStake', () => {
  it('returns correct minimum stake', () => {
    // (maxGain - rep - coburn) / detection = (400 - 100 - 50) / 0.5 = 500
    const result = minimumStake({
      detectionProbability: 0.5,
      reputationValue: 100,
      maxViolationGain: 400,
      coburn: 50,
    });
    expect(result).toBe(500);
  });

  it('returns 0 when reputation+coburn already exceeds maxGain', () => {
    const result = minimumStake({
      detectionProbability: 0.5,
      reputationValue: 500,
      maxViolationGain: 100,
      coburn: 50,
    });
    expect(result).toBe(0);
  });

  it('returns Infinity when detectionProbability is 0', () => {
    const result = minimumStake({
      detectionProbability: 0,
      reputationValue: 100,
      maxViolationGain: 500,
      coburn: 50,
    });
    expect(result).toBe(Infinity);
  });

  it('returns 0 when maxViolationGain is 0', () => {
    const result = minimumStake({
      detectionProbability: 0.5,
      reputationValue: 100,
      maxViolationGain: 0,
      coburn: 50,
    });
    expect(result).toBe(0);
  });

  it('scales inversely with detectionProbability', () => {
    const high = minimumStake({
      detectionProbability: 0.9,
      reputationValue: 0,
      maxViolationGain: 900,
      coburn: 0,
    });
    const low = minimumStake({
      detectionProbability: 0.1,
      reputationValue: 0,
      maxViolationGain: 900,
      coburn: 0,
    });
    expect(low).toBeGreaterThan(high);
    expect(high).toBe(1000);
    expect(low).toBe(9000);
  });

  it('throws on negative reputationValue', () => {
    expect(() =>
      minimumStake({
        detectionProbability: 0.5,
        reputationValue: -10,
        maxViolationGain: 400,
        coburn: 50,
      }),
    ).toThrow('reputationValue must be >= 0');
  });

  it('throws on detectionProbability > 1', () => {
    expect(() =>
      minimumStake({
        detectionProbability: 2.0,
        reputationValue: 10,
        maxViolationGain: 400,
        coburn: 50,
      }),
    ).toThrow('detectionProbability must be in [0, 1]');
  });
});

// ---------------------------------------------------------------------------
// minimumDetection
// ---------------------------------------------------------------------------
describe('minimumDetection', () => {
  it('returns correct minimum detection probability', () => {
    // (maxGain - rep - coburn) / stake = (600 - 100 - 0) / 1000 = 0.5
    const result = minimumDetection({
      stakeAmount: 1000,
      reputationValue: 100,
      maxViolationGain: 600,
      coburn: 0,
    });
    expect(result).toBe(0.5);
  });

  it('returns 1 when stakeAmount is 0', () => {
    const result = minimumDetection({
      stakeAmount: 0,
      reputationValue: 100,
      maxViolationGain: 500,
      coburn: 50,
    });
    expect(result).toBe(1);
  });

  it('returns 0 when reputation+coburn exceeds maxGain', () => {
    const result = minimumDetection({
      stakeAmount: 1000,
      reputationValue: 500,
      maxViolationGain: 100,
      coburn: 50,
    });
    expect(result).toBe(0);
  });

  it('clamps to 1 when required detection exceeds 1', () => {
    // (10000 - 0 - 0) / 100 = 100 -> clamped to 1
    const result = minimumDetection({
      stakeAmount: 100,
      reputationValue: 0,
      maxViolationGain: 10000,
      coburn: 0,
    });
    expect(result).toBe(1);
  });

  it('returns 0 when maxViolationGain is 0', () => {
    const result = minimumDetection({
      stakeAmount: 1000,
      reputationValue: 0,
      maxViolationGain: 0,
      coburn: 0,
    });
    expect(result).toBe(0);
  });

  it('throws on negative stakeAmount', () => {
    expect(() =>
      minimumDetection({
        stakeAmount: -100,
        reputationValue: 0,
        maxViolationGain: 500,
        coburn: 0,
      }),
    ).toThrow('stakeAmount must be >= 0');
  });

  it('throws on negative maxViolationGain', () => {
    expect(() =>
      minimumDetection({
        stakeAmount: 100,
        reputationValue: 0,
        maxViolationGain: -10,
        coburn: 0,
      }),
    ).toThrow('maxViolationGain must be >= 0');
  });
});

// ---------------------------------------------------------------------------
// expectedCostOfBreach
// ---------------------------------------------------------------------------
describe('expectedCostOfBreach', () => {
  it('returns stake * detection + coburn', () => {
    const params: HonestyParameters = {
      stakeAmount: 1000,
      detectionProbability: 0.5,
      reputationValue: 100,
      maxViolationGain: 500,
      coburn: 25,
    };
    expect(expectedCostOfBreach(params)).toBe(1000 * 0.5 + 25);
  });

  it('returns 0 when stake and coburn are both 0', () => {
    const params: HonestyParameters = {
      stakeAmount: 0,
      detectionProbability: 0.5,
      reputationValue: 100,
      maxViolationGain: 500,
      coburn: 0,
    };
    expect(expectedCostOfBreach(params)).toBe(0);
  });

  it('returns only coburn when detection is 0', () => {
    const params: HonestyParameters = {
      stakeAmount: 1000,
      detectionProbability: 0,
      reputationValue: 100,
      maxViolationGain: 500,
      coburn: 42,
    };
    expect(expectedCostOfBreach(params)).toBe(42);
  });

  it('returns stake + coburn when detection is 1', () => {
    const params: HonestyParameters = {
      stakeAmount: 500,
      detectionProbability: 1.0,
      reputationValue: 100,
      maxViolationGain: 500,
      coburn: 50,
    };
    expect(expectedCostOfBreach(params)).toBe(550);
  });

  it('throws on invalid parameters', () => {
    expect(() =>
      expectedCostOfBreach({
        stakeAmount: -1,
        detectionProbability: 0.5,
        reputationValue: 0,
        maxViolationGain: 0,
        coburn: 0,
      }),
    ).toThrow('stakeAmount must be >= 0');
  });
});

// ---------------------------------------------------------------------------
// honestyMargin
// ---------------------------------------------------------------------------
describe('honestyMargin', () => {
  it('returns positive margin when honesty dominates', () => {
    const params: HonestyParameters = {
      stakeAmount: 1000,
      detectionProbability: 0.8,
      reputationValue: 500,
      maxViolationGain: 100,
      coburn: 50,
    };
    expect(honestyMargin(params)).toBe(1350 - 100);
  });

  it('returns negative margin when dishonesty dominates', () => {
    const params: HonestyParameters = {
      stakeAmount: 10,
      detectionProbability: 0.1,
      reputationValue: 5,
      maxViolationGain: 1000,
      coburn: 2,
    };
    expect(honestyMargin(params)).toBe(8 - 1000);
  });

  it('returns 0 at exact boundary', () => {
    const params: HonestyParameters = {
      stakeAmount: 100,
      detectionProbability: 0.5,
      reputationValue: 30,
      maxViolationGain: 100,
      coburn: 20,
    };
    expect(honestyMargin(params)).toBeCloseTo(0, 10);
  });

  it('matches proveHonesty margin', () => {
    const params: HonestyParameters = {
      stakeAmount: 750,
      detectionProbability: 0.6,
      reputationValue: 200,
      maxViolationGain: 800,
      coburn: 75,
    };
    const proof = proveHonesty(params);
    expect(honestyMargin(params)).toBe(proof.margin);
  });

  it('works with all-zero parameters', () => {
    const params: HonestyParameters = {
      stakeAmount: 0,
      detectionProbability: 0,
      reputationValue: 0,
      maxViolationGain: 0,
      coburn: 0,
    };
    expect(honestyMargin(params)).toBe(0);
  });

  it('throws on negative coburn', () => {
    expect(() =>
      honestyMargin({
        stakeAmount: 100,
        detectionProbability: 0.5,
        reputationValue: 0,
        maxViolationGain: 0,
        coburn: -5,
      }),
    ).toThrow('coburn must be >= 0');
  });
});

// ---------------------------------------------------------------------------
// repeatedGameEquilibrium (Folk Theorem)
// ---------------------------------------------------------------------------
describe('repeatedGameEquilibrium', () => {
  // Classic Prisoner's Dilemma payoffs: T=5, R=3, P=1, S=0
  const classicPD: RepeatedGameParams = {
    cooperatePayoff: 3,
    defectPayoff: 1,
    temptationPayoff: 5,
    suckerPayoff: 0,
    discountFactor: 0.6,
  };

  it('computes correct minDiscountFactor for classic PD', () => {
    // delta_min = (T - R) / (T - P) = (5 - 3) / (5 - 1) = 0.5
    const result = repeatedGameEquilibrium(classicPD);
    expect(result.minDiscountFactor).toBeCloseTo(0.5, 10);
  });

  it('cooperation is sustainable when delta > threshold', () => {
    // delta = 0.6 > 0.5 = delta_min
    const result = repeatedGameEquilibrium(classicPD);
    expect(result.cooperationSustainable).toBe(true);
    expect(result.margin).toBeCloseTo(0.1, 10);
  });

  it('cooperation is not sustainable when delta < threshold', () => {
    const result = repeatedGameEquilibrium({ ...classicPD, discountFactor: 0.3 });
    expect(result.cooperationSustainable).toBe(false);
    expect(result.margin).toBeCloseTo(-0.2, 10);
  });

  it('cooperation is sustainable at exact threshold (margin = 0)', () => {
    const result = repeatedGameEquilibrium({ ...classicPD, discountFactor: 0.5 });
    expect(result.cooperationSustainable).toBe(true);
    expect(result.margin).toBeCloseTo(0, 10);
  });

  it('formula contains structured derivation text', () => {
    const result = repeatedGameEquilibrium(classicPD);
    expect(result.formula).toContain('Folk Theorem threshold');
    expect(result.formula).toContain('sustainable');
    expect(result.actualDiscountFactor).toBe(0.6);
  });

  it('handles asymmetric payoffs correctly', () => {
    // T=10, R=6, P=2, S=0 => delta_min = (10-6)/(10-2) = 4/8 = 0.5
    const result = repeatedGameEquilibrium({
      cooperatePayoff: 6,
      defectPayoff: 2,
      temptationPayoff: 10,
      suckerPayoff: 0,
      discountFactor: 0.75,
    });
    expect(result.minDiscountFactor).toBeCloseTo(0.5, 10);
    expect(result.cooperationSustainable).toBe(true);
  });

  it('throws on invalid payoff ordering (T <= R)', () => {
    expect(() =>
      repeatedGameEquilibrium({
        cooperatePayoff: 5,
        defectPayoff: 1,
        temptationPayoff: 3, // T < R
        suckerPayoff: 0,
        discountFactor: 0.5,
      }),
    ).toThrow('temptationPayoff (3) must be > cooperatePayoff (5)');
  });

  it('throws on invalid payoff ordering (R <= P)', () => {
    expect(() =>
      repeatedGameEquilibrium({
        cooperatePayoff: 1,
        defectPayoff: 3, // P > R
        temptationPayoff: 5,
        suckerPayoff: 0,
        discountFactor: 0.5,
      }),
    ).toThrow('cooperatePayoff (1) must be > defectPayoff (3)');
  });

  it('throws on invalid payoff ordering (P <= S)', () => {
    expect(() =>
      repeatedGameEquilibrium({
        cooperatePayoff: 3,
        defectPayoff: 0, // P <= S
        temptationPayoff: 5,
        suckerPayoff: 0,
        discountFactor: 0.5,
      }),
    ).toThrow('defectPayoff (0) must be > suckerPayoff (0)');
  });

  it('throws on discount factor out of range (0)', () => {
    expect(() =>
      repeatedGameEquilibrium({ ...classicPD, discountFactor: 0 }),
    ).toThrow('discountFactor must be in (0, 1)');
  });

  it('throws on discount factor out of range (1)', () => {
    expect(() =>
      repeatedGameEquilibrium({ ...classicPD, discountFactor: 1 }),
    ).toThrow('discountFactor must be in (0, 1)');
  });

  it('higher temptation requires higher discount factor', () => {
    const lowTemptation = repeatedGameEquilibrium({
      cooperatePayoff: 3,
      defectPayoff: 1,
      temptationPayoff: 4,
      suckerPayoff: 0,
      discountFactor: 0.5,
    });
    const highTemptation = repeatedGameEquilibrium({
      cooperatePayoff: 3,
      defectPayoff: 1,
      temptationPayoff: 8,
      suckerPayoff: 0,
      discountFactor: 0.5,
    });
    expect(highTemptation.minDiscountFactor).toBeGreaterThan(lowTemptation.minDiscountFactor);
  });
});

// ---------------------------------------------------------------------------
// coalitionStability (Core of Cooperative Game Theory)
// ---------------------------------------------------------------------------
describe('coalitionStability', () => {
  it('identifies stable allocation in the core', () => {
    // 3-player game: v({0})=0, v({1})=0, v({2})=0
    // v({0,1})=4, v({0,2})=3, v({1,2})=5, v({0,1,2})=10
    // Allocation: [3, 4, 3] => sum = 10
    // Check: {0,1}=7 >= 4 ok, {0,2}=6 >= 3 ok, {1,2}=7 >= 5 ok
    const coalitionValues: CoalitionValue[] = [
      { coalition: [0], value: 0 },
      { coalition: [1], value: 0 },
      { coalition: [2], value: 0 },
      { coalition: [0, 1], value: 4 },
      { coalition: [0, 2], value: 3 },
      { coalition: [1, 2], value: 5 },
      { coalition: [0, 1, 2], value: 10 },
    ];
    const result = coalitionStability(3, [3, 4, 3], coalitionValues);
    expect(result.isStable).toBe(true);
    expect(result.blockingCoalitions).toHaveLength(0);
  });

  it('identifies unstable allocation with blocking coalitions', () => {
    // Same game, bad allocation: [1, 1, 8]
    // {0,1} allocated=2 < v({0,1})=4 => blocks!
    const coalitionValues: CoalitionValue[] = [
      { coalition: [0], value: 0 },
      { coalition: [1], value: 0 },
      { coalition: [2], value: 0 },
      { coalition: [0, 1], value: 4 },
      { coalition: [0, 2], value: 3 },
      { coalition: [1, 2], value: 5 },
      { coalition: [0, 1, 2], value: 10 },
    ];
    const result = coalitionStability(3, [1, 1, 8], coalitionValues);
    expect(result.isStable).toBe(false);
    expect(result.blockingCoalitions.length).toBeGreaterThan(0);
    // {0,1} should be a blocking coalition
    const blocking01 = result.blockingCoalitions.find(
      bc => bc.coalition.length === 2 && bc.coalition[0] === 0 && bc.coalition[1] === 1,
    );
    expect(blocking01).toBeDefined();
    expect(blocking01!.surplus).toBeCloseTo(2, 10);
  });

  it('computes efficiency correctly', () => {
    const coalitionValues: CoalitionValue[] = [
      { coalition: [0, 1], value: 10 },
    ];
    // allocation sums to 10, grand coalition = 10 => efficiency = 1.0
    const result = coalitionStability(2, [4, 6], coalitionValues);
    expect(result.efficiency).toBeCloseTo(1.0, 10);
  });

  it('handles 2-player game', () => {
    // v({0})=3, v({1})=4, v({0,1})=10
    // Allocation [5,5]: {0}=5>=3 ok, {1}=5>=4 ok => stable
    const result = coalitionStability(2, [5, 5], [
      { coalition: [0], value: 3 },
      { coalition: [1], value: 4 },
      { coalition: [0, 1], value: 10 },
    ]);
    expect(result.isStable).toBe(true);
  });

  it('2-player game with blocking singleton', () => {
    // v({0})=6, v({1})=4, v({0,1})=10
    // Allocation [4,6]: agent 0 gets 4 < v({0})=6 => blocks
    const result = coalitionStability(2, [4, 6], [
      { coalition: [0], value: 6 },
      { coalition: [1], value: 4 },
      { coalition: [0, 1], value: 10 },
    ]);
    expect(result.isStable).toBe(false);
    expect(result.blockingCoalitions[0]!.coalition).toEqual([0]);
  });

  it('formula contains derivation for stable case', () => {
    const result = coalitionStability(2, [5, 5], [
      { coalition: [0], value: 3 },
      { coalition: [1], value: 4 },
      { coalition: [0, 1], value: 10 },
    ]);
    expect(result.formula).toContain('in the core');
  });

  it('formula contains derivation for unstable case', () => {
    const result = coalitionStability(2, [2, 8], [
      { coalition: [0], value: 5 },
      { coalition: [1], value: 3 },
      { coalition: [0, 1], value: 10 },
    ]);
    expect(result.formula).toContain('NOT in the core');
    expect(result.formula).toContain('blocking');
  });

  it('throws on agentCount < 1', () => {
    expect(() => coalitionStability(0, [], [])).toThrow('agentCount must be >= 1');
  });

  it('throws on allocation length mismatch', () => {
    expect(() =>
      coalitionStability(3, [1, 2], [{ coalition: [0, 1, 2], value: 10 }]),
    ).toThrow('allocation length (2) must equal agentCount (3)');
  });

  it('throws when grand coalition is missing', () => {
    expect(() =>
      coalitionStability(2, [5, 5], [{ coalition: [0], value: 3 }]),
    ).toThrow('coalitionValues must include the grand coalition');
  });

  it('defaults unspecified coalition values to 0', () => {
    // Only specify grand coalition; all subsets default to 0
    // Any positive allocation should be stable
    const result = coalitionStability(2, [5, 5], [
      { coalition: [0, 1], value: 10 },
    ]);
    expect(result.isStable).toBe(true);
  });

  it('handles single-agent game (trivially stable)', () => {
    const result = coalitionStability(1, [10], [
      { coalition: [0], value: 10 },
    ]);
    expect(result.isStable).toBe(true);
    expect(result.efficiency).toBeCloseTo(1.0, 10);
  });
});

// ---------------------------------------------------------------------------
// mechanismDesign (Incentive Compatibility)
// ---------------------------------------------------------------------------
describe('mechanismDesign', () => {
  it('computes correct minimum penalty', () => {
    // penalty_min = dishonestGain / detectionProbability = 100 / 0.5 = 200
    const result = mechanismDesign({
      dishonestGain: 100,
      detectionProbability: 0.5,
    });
    expect(result.minimumPenalty).toBeCloseTo(200, 10);
    expect(result.enforceable).toBe(true);
  });

  it('accounts for intrinsic honesty cost', () => {
    // penalty_min = (100 - 30) / 0.5 = 140
    const result = mechanismDesign({
      dishonestGain: 100,
      detectionProbability: 0.5,
      intrinsicHonestyCost: 30,
    });
    expect(result.minimumPenalty).toBeCloseTo(140, 10);
  });

  it('returns 0 penalty when intrinsic cost exceeds gain', () => {
    const result = mechanismDesign({
      dishonestGain: 50,
      detectionProbability: 0.5,
      intrinsicHonestyCost: 100,
    });
    expect(result.minimumPenalty).toBe(0);
    expect(result.enforceable).toBe(true);
    expect(result.formula).toContain('No penalty needed');
  });

  it('returns Infinity when detection is 0 and gain > intrinsic cost', () => {
    const result = mechanismDesign({
      dishonestGain: 100,
      detectionProbability: 0,
    });
    expect(result.minimumPenalty).toBe(Infinity);
    expect(result.enforceable).toBe(false);
    expect(result.formula).toContain('No finite penalty');
  });

  it('enforceable when detection is 0 but intrinsic cost covers gain', () => {
    const result = mechanismDesign({
      dishonestGain: 50,
      detectionProbability: 0,
      intrinsicHonestyCost: 60,
    });
    expect(result.minimumPenalty).toBe(0);
    expect(result.enforceable).toBe(true);
  });

  it('expected penalty equals dishonest gain at minimum penalty', () => {
    const result = mechanismDesign({
      dishonestGain: 100,
      detectionProbability: 0.5,
    });
    // expectedPenalty = 200 * 0.5 = 100 = dishonestGain
    expect(result.expectedPenalty).toBeCloseTo(100, 10);
  });

  it('penalty scales inversely with detection probability', () => {
    const high = mechanismDesign({ dishonestGain: 100, detectionProbability: 0.8 });
    const low = mechanismDesign({ dishonestGain: 100, detectionProbability: 0.2 });
    expect(low.minimumPenalty).toBeGreaterThan(high.minimumPenalty);
    expect(high.minimumPenalty).toBeCloseTo(125, 10);
    expect(low.minimumPenalty).toBeCloseTo(500, 10);
  });

  it('formula contains incentive compatibility constraint', () => {
    const result = mechanismDesign({
      dishonestGain: 100,
      detectionProbability: 0.5,
    });
    expect(result.formula).toContain('Incentive compatibility');
    expect(result.formula).toContain('penalty');
  });

  it('throws on negative dishonestGain', () => {
    expect(() =>
      mechanismDesign({ dishonestGain: -10, detectionProbability: 0.5 }),
    ).toThrow('dishonestGain must be >= 0');
  });

  it('throws on detectionProbability out of range', () => {
    expect(() =>
      mechanismDesign({ dishonestGain: 100, detectionProbability: 1.5 }),
    ).toThrow('detectionProbability must be in [0, 1]');
    expect(() =>
      mechanismDesign({ dishonestGain: 100, detectionProbability: -0.1 }),
    ).toThrow('detectionProbability must be in [0, 1]');
  });

  it('throws on negative intrinsicHonestyCost', () => {
    expect(() =>
      mechanismDesign({
        dishonestGain: 100,
        detectionProbability: 0.5,
        intrinsicHonestyCost: -10,
      }),
    ).toThrow('intrinsicHonestyCost must be >= 0');
  });

  it('handles zero dishonest gain (no penalty needed)', () => {
    const result = mechanismDesign({
      dishonestGain: 0,
      detectionProbability: 0.5,
    });
    expect(result.minimumPenalty).toBe(0);
    expect(result.enforceable).toBe(true);
  });

  it('handles perfect detection (penalty = gain)', () => {
    const result = mechanismDesign({
      dishonestGain: 100,
      detectionProbability: 1.0,
    });
    expect(result.minimumPenalty).toBeCloseTo(100, 10);
  });
});

// ---------------------------------------------------------------------------
// modelPrincipalAgent (Principal-Agent Model)
// ---------------------------------------------------------------------------
describe('modelPrincipalAgent', () => {
  const defaultOperator: OperatorPrincipal = {
    operatorId: 'op-1',
    agentIds: ['agent-a', 'agent-b'],
    totalStake: 10000,
    monitoringBudget: 500,
    liabilityExposure: 5000,
  };

  it('computes agentBreachProbability correctly', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.1,
      detectionRate: 0.8,
      breachCost: 10000,
      monitoringCostPerUnit: 100,
    });
    // 0.1 * (1 - 0.8) = 0.02
    expect(result.agentBreachProbability).toBeCloseTo(0.02, 10);
  });

  it('computes operatorExpectedCost correctly', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.1,
      detectionRate: 0.8,
      breachCost: 10000,
      monitoringCostPerUnit: 100,
    });
    // breachProb * breachCost + monitoringBudget = 0.02 * 10000 + 500 = 700
    expect(result.operatorExpectedCost).toBeCloseTo(700, 10);
  });

  it('sets monitoringEffectiveness to detectionRate', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.1,
      detectionRate: 0.65,
      breachCost: 5000,
      monitoringCostPerUnit: 50,
    });
    expect(result.monitoringEffectiveness).toBe(0.65);
  });

  it('returns incentiveCompatible=true when expectedCost < liabilityExposure', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator, // liabilityExposure: 5000
      agentBreachRate: 0.1,
      detectionRate: 0.8,
      breachCost: 10000,
      monitoringCostPerUnit: 100,
    });
    // expectedCost = 700 < 5000
    expect(result.incentiveCompatible).toBe(true);
  });

  it('returns incentiveCompatible=false when expectedCost >= liabilityExposure', () => {
    const lowLiabilityOperator: OperatorPrincipal = {
      ...defaultOperator,
      liabilityExposure: 100,
      monitoringBudget: 500,
    };
    const result = modelPrincipalAgent({
      operator: lowLiabilityOperator,
      agentBreachRate: 0.5,
      detectionRate: 0.1,
      breachCost: 10000,
      monitoringCostPerUnit: 100,
    });
    // breachProb = 0.5 * 0.9 = 0.45, expectedCost = 0.45 * 10000 + 500 = 5000
    expect(result.operatorExpectedCost).toBeCloseTo(5000, 10);
    expect(result.incentiveCompatible).toBe(false);
  });

  it('computes optimalMonitoringSpend with diminishing returns', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.2,
      detectionRate: 0.5,
      breachCost: 10000,
      monitoringCostPerUnit: 100,
    });
    // sqrt(0.2 * 10000 * 100) - 100 = sqrt(200000) - 100 ≈ 447.21 - 100 = 347.21
    expect(result.optimalMonitoringSpend).toBeCloseTo(
      Math.sqrt(0.2 * 10000 * 100) - 100,
      4,
    );
  });

  it('clamps optimalMonitoringSpend to 0 when formula yields negative', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.001,
      detectionRate: 0.5,
      breachCost: 10,
      monitoringCostPerUnit: 1000,
    });
    // sqrt(0.001 * 10 * 1000) - 1000 = sqrt(10) - 1000 ≈ 3.16 - 1000 < 0, clamped to 0
    expect(result.optimalMonitoringSpend).toBe(0);
  });

  it('returns zero breach probability when detection is perfect', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.5,
      detectionRate: 1.0,
      breachCost: 10000,
      monitoringCostPerUnit: 100,
    });
    // 0.5 * (1 - 1.0) = 0
    expect(result.agentBreachProbability).toBe(0);
  });

  it('returns full breach probability when detection is zero', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.3,
      detectionRate: 0,
      breachCost: 10000,
      monitoringCostPerUnit: 100,
    });
    // 0.3 * (1 - 0) = 0.3
    expect(result.agentBreachProbability).toBeCloseTo(0.3, 10);
  });

  it('preserves the operator reference in the result', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.1,
      detectionRate: 0.5,
      breachCost: 1000,
      monitoringCostPerUnit: 50,
    });
    expect(result.operator).toBe(defaultOperator);
    expect(result.operator.operatorId).toBe('op-1');
    expect(result.operator.agentIds).toEqual(['agent-a', 'agent-b']);
  });

  it('throws on agentBreachRate out of range', () => {
    expect(() =>
      modelPrincipalAgent({
        operator: defaultOperator,
        agentBreachRate: -0.1,
        detectionRate: 0.5,
        breachCost: 1000,
        monitoringCostPerUnit: 50,
      }),
    ).toThrow('agentBreachRate must be in [0, 1]');
    expect(() =>
      modelPrincipalAgent({
        operator: defaultOperator,
        agentBreachRate: 1.5,
        detectionRate: 0.5,
        breachCost: 1000,
        monitoringCostPerUnit: 50,
      }),
    ).toThrow('agentBreachRate must be in [0, 1]');
  });

  it('throws on detectionRate out of range', () => {
    expect(() =>
      modelPrincipalAgent({
        operator: defaultOperator,
        agentBreachRate: 0.1,
        detectionRate: -0.1,
        breachCost: 1000,
        monitoringCostPerUnit: 50,
      }),
    ).toThrow('detectionRate must be in [0, 1]');
    expect(() =>
      modelPrincipalAgent({
        operator: defaultOperator,
        agentBreachRate: 0.1,
        detectionRate: 1.5,
        breachCost: 1000,
        monitoringCostPerUnit: 50,
      }),
    ).toThrow('detectionRate must be in [0, 1]');
  });

  it('throws on negative breachCost', () => {
    expect(() =>
      modelPrincipalAgent({
        operator: defaultOperator,
        agentBreachRate: 0.1,
        detectionRate: 0.5,
        breachCost: -100,
        monitoringCostPerUnit: 50,
      }),
    ).toThrow('breachCost must be >= 0');
  });

  it('throws on negative monitoringCostPerUnit', () => {
    expect(() =>
      modelPrincipalAgent({
        operator: defaultOperator,
        agentBreachRate: 0.1,
        detectionRate: 0.5,
        breachCost: 1000,
        monitoringCostPerUnit: -10,
      }),
    ).toThrow('monitoringCostPerUnit must be >= 0');
  });

  it('handles zero breach rate (no breaches)', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0,
      detectionRate: 0.5,
      breachCost: 10000,
      monitoringCostPerUnit: 100,
    });
    expect(result.agentBreachProbability).toBe(0);
    expect(result.operatorExpectedCost).toBe(defaultOperator.monitoringBudget);
    expect(result.optimalMonitoringSpend).toBe(0);
  });

  it('handles zero breach cost', () => {
    const result = modelPrincipalAgent({
      operator: defaultOperator,
      agentBreachRate: 0.5,
      detectionRate: 0.3,
      breachCost: 0,
      monitoringCostPerUnit: 100,
    });
    expect(result.operatorExpectedCost).toBe(defaultOperator.monitoringBudget);
    expect(result.optimalMonitoringSpend).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// analyzeTier (Three Adoption Tiers)
// ---------------------------------------------------------------------------
describe('analyzeTier', () => {
  // --- Solo tier ---
  it('solo tier: clamps detection to [0.60, 0.70]', () => {
    const low = analyzeTier({
      tier: 'solo',
      baseDetectionRate: 0.3,
      participantCount: 1,
      stake: 1000,
      breachGain: 500,
    });
    expect(low.effectiveDetection).toBe(0.60);
    expect(low.detectionFloor).toBe(0.60);
    expect(low.detectionCeiling).toBe(0.70);

    const high = analyzeTier({
      tier: 'solo',
      baseDetectionRate: 0.99,
      participantCount: 1,
      stake: 1000,
      breachGain: 500,
    });
    expect(high.effectiveDetection).toBe(0.70);

    const mid = analyzeTier({
      tier: 'solo',
      baseDetectionRate: 0.65,
      participantCount: 1,
      stake: 1000,
      breachGain: 500,
    });
    expect(mid.effectiveDetection).toBeCloseTo(0.65, 10);
  });

  it('solo tier: adjustedStake = stake * 1.0', () => {
    const result = analyzeTier({
      tier: 'solo',
      baseDetectionRate: 0.65,
      participantCount: 1,
      stake: 1000,
      breachGain: 500,
    });
    expect(result.adjustedStake).toBe(1000);
  });

  it('solo tier: gameTheoryApplicable is false', () => {
    const result = analyzeTier({
      tier: 'solo',
      baseDetectionRate: 0.65,
      participantCount: 1,
      stake: 1000,
      breachGain: 500,
    });
    expect(result.gameTheoryApplicable).toBe(false);
  });

  // --- Bilateral tier ---
  it('bilateral tier: clamps detection to [0.85, 0.95]', () => {
    const low = analyzeTier({
      tier: 'bilateral',
      baseDetectionRate: 0.5,
      participantCount: 2,
      stake: 1000,
      breachGain: 500,
    });
    expect(low.effectiveDetection).toBe(0.85);

    const high = analyzeTier({
      tier: 'bilateral',
      baseDetectionRate: 0.99,
      participantCount: 2,
      stake: 1000,
      breachGain: 500,
    });
    expect(high.effectiveDetection).toBe(0.95);

    const mid = analyzeTier({
      tier: 'bilateral',
      baseDetectionRate: 0.90,
      participantCount: 2,
      stake: 1000,
      breachGain: 500,
    });
    expect(mid.effectiveDetection).toBeCloseTo(0.90, 10);
  });

  it('bilateral tier: adjustedStake = stake * 1.5', () => {
    const result = analyzeTier({
      tier: 'bilateral',
      baseDetectionRate: 0.90,
      participantCount: 2,
      stake: 1000,
      breachGain: 500,
    });
    expect(result.adjustedStake).toBe(1500);
  });

  it('bilateral tier: gameTheoryApplicable is true', () => {
    const result = analyzeTier({
      tier: 'bilateral',
      baseDetectionRate: 0.90,
      participantCount: 2,
      stake: 1000,
      breachGain: 500,
    });
    expect(result.gameTheoryApplicable).toBe(true);
  });

  // --- Network tier ---
  it('network tier: clamps detection to [0.99, 0.999]', () => {
    const low = analyzeTier({
      tier: 'network',
      baseDetectionRate: 0.5,
      participantCount: 100,
      stake: 1000,
      breachGain: 500,
    });
    expect(low.effectiveDetection).toBe(0.99);

    const high = analyzeTier({
      tier: 'network',
      baseDetectionRate: 1.0,
      participantCount: 100,
      stake: 1000,
      breachGain: 500,
    });
    expect(high.effectiveDetection).toBe(0.999);

    const mid = analyzeTier({
      tier: 'network',
      baseDetectionRate: 0.995,
      participantCount: 100,
      stake: 1000,
      breachGain: 500,
    });
    expect(mid.effectiveDetection).toBeCloseTo(0.995, 10);
  });

  it('network tier: adjustedStake = stake * sqrt(participantCount)', () => {
    const result = analyzeTier({
      tier: 'network',
      baseDetectionRate: 0.995,
      participantCount: 100,
      stake: 1000,
      breachGain: 500,
    });
    // 1000 * sqrt(100) = 1000 * 10 = 10000
    expect(result.adjustedStake).toBe(10000);
  });

  it('network tier: gameTheoryApplicable is true', () => {
    const result = analyzeTier({
      tier: 'network',
      baseDetectionRate: 0.995,
      participantCount: 100,
      stake: 1000,
      breachGain: 500,
    });
    expect(result.gameTheoryApplicable).toBe(true);
  });

  // --- Honest equilibrium ---
  it('honestEquilibrium=true when adjustedStake * detection > breachGain', () => {
    const result = analyzeTier({
      tier: 'bilateral',
      baseDetectionRate: 0.90,
      participantCount: 2,
      stake: 1000,
      breachGain: 500,
    });
    // 1500 * 0.90 = 1350 > 500
    expect(result.honestEquilibrium).toBe(true);
  });

  it('honestEquilibrium=false when adjustedStake * detection <= breachGain', () => {
    const result = analyzeTier({
      tier: 'solo',
      baseDetectionRate: 0.65,
      participantCount: 1,
      stake: 100,
      breachGain: 1000,
    });
    // 100 * 0.65 = 65 < 1000
    expect(result.honestEquilibrium).toBe(false);
  });

  it('honestEquilibrium=false at exact boundary (stake * detection = breachGain)', () => {
    // solo: effective detection clamped to 0.60 (for rate=0.50)
    // adjustedStake = 1000 * 1.0 = 1000
    // 1000 * 0.60 = 600 = breachGain
    const result = analyzeTier({
      tier: 'solo',
      baseDetectionRate: 0.50,
      participantCount: 1,
      stake: 1000,
      breachGain: 600,
    });
    expect(result.honestEquilibrium).toBe(false);
  });

  it('network effect scales stake with participant count', () => {
    const small = analyzeTier({
      tier: 'network',
      baseDetectionRate: 0.995,
      participantCount: 4,
      stake: 1000,
      breachGain: 5000,
    });
    const large = analyzeTier({
      tier: 'network',
      baseDetectionRate: 0.995,
      participantCount: 100,
      stake: 1000,
      breachGain: 5000,
    });
    // sqrt(4) = 2, sqrt(100) = 10
    expect(small.adjustedStake).toBe(2000);
    expect(large.adjustedStake).toBe(10000);
    expect(large.adjustedStake).toBeGreaterThan(small.adjustedStake);
  });

  // --- Validation ---
  it('throws on baseDetectionRate out of range', () => {
    expect(() =>
      analyzeTier({
        tier: 'solo',
        baseDetectionRate: -0.1,
        participantCount: 1,
        stake: 100,
        breachGain: 50,
      }),
    ).toThrow('baseDetectionRate must be in [0, 1]');
    expect(() =>
      analyzeTier({
        tier: 'solo',
        baseDetectionRate: 1.5,
        participantCount: 1,
        stake: 100,
        breachGain: 50,
      }),
    ).toThrow('baseDetectionRate must be in [0, 1]');
  });

  it('throws on participantCount < 1', () => {
    expect(() =>
      analyzeTier({
        tier: 'bilateral',
        baseDetectionRate: 0.9,
        participantCount: 0,
        stake: 100,
        breachGain: 50,
      }),
    ).toThrow('participantCount must be >= 1');
  });

  it('throws on negative stake', () => {
    expect(() =>
      analyzeTier({
        tier: 'solo',
        baseDetectionRate: 0.65,
        participantCount: 1,
        stake: -100,
        breachGain: 50,
      }),
    ).toThrow('stake must be >= 0');
  });

  it('throws on negative breachGain', () => {
    expect(() =>
      analyzeTier({
        tier: 'solo',
        baseDetectionRate: 0.65,
        participantCount: 1,
        stake: 100,
        breachGain: -50,
      }),
    ).toThrow('breachGain must be >= 0');
  });

  it('returns correct tier metadata', () => {
    const result = analyzeTier({
      tier: 'network',
      baseDetectionRate: 0.995,
      participantCount: 50,
      stake: 500,
      breachGain: 200,
    });
    expect(result.tier).toBe('network');
    expect(result.participantCount).toBe(50);
  });
});

// ---------------------------------------------------------------------------
// defineConjecture & getStandardConjectures (Impossibility Conjectures)
// ---------------------------------------------------------------------------
describe('defineConjecture', () => {
  it('creates a conjecture with required fields', () => {
    const c = defineConjecture({
      id: 'test_conjecture',
      name: 'Test Conjecture',
      statement: 'This is a test statement',
      informalArgument: 'Because reasons',
    });
    expect(c.id).toBe('test_conjecture');
    expect(c.name).toBe('Test Conjecture');
    expect(c.statement).toBe('This is a test statement');
    expect(c.informalArgument).toBe('Because reasons');
    expect(c.status).toBe('conjecture');
    expect(c.confidence).toBe(0.5);
    expect(c.implications).toEqual([]);
    expect(c.counterexampleSpace).toBe('');
  });

  it('accepts optional confidence', () => {
    const c = defineConjecture({
      id: 'high_confidence',
      name: 'High Confidence',
      statement: 'Very likely true',
      informalArgument: 'Strong evidence',
      confidence: 0.95,
    });
    expect(c.confidence).toBe(0.95);
  });

  it('accepts optional implications', () => {
    const c = defineConjecture({
      id: 'with_implications',
      name: 'With Implications',
      statement: 'Has implications',
      informalArgument: 'Because',
      implications: ['implication 1', 'implication 2'],
    });
    expect(c.implications).toEqual(['implication 1', 'implication 2']);
  });

  it('accepts optional counterexampleSpace', () => {
    const c = defineConjecture({
      id: 'with_counter',
      name: 'With Counter',
      statement: 'Has counterexample space',
      informalArgument: 'Because',
      counterexampleSpace: 'Look for counterexamples here',
    });
    expect(c.counterexampleSpace).toBe('Look for counterexamples here');
  });

  it('throws on confidence out of range', () => {
    expect(() =>
      defineConjecture({
        id: 'bad',
        name: 'Bad',
        statement: 'Bad',
        informalArgument: 'Bad',
        confidence: -0.1,
      }),
    ).toThrow('confidence must be in [0, 1]');
    expect(() =>
      defineConjecture({
        id: 'bad',
        name: 'Bad',
        statement: 'Bad',
        informalArgument: 'Bad',
        confidence: 1.5,
      }),
    ).toThrow('confidence must be in [0, 1]');
  });

  it('throws on empty id', () => {
    expect(() =>
      defineConjecture({
        id: '',
        name: 'Name',
        statement: 'Statement',
        informalArgument: 'Argument',
      }),
    ).toThrow('id must be a non-empty string');
  });

  it('throws on empty name', () => {
    expect(() =>
      defineConjecture({
        id: 'id',
        name: '',
        statement: 'Statement',
        informalArgument: 'Argument',
      }),
    ).toThrow('name must be a non-empty string');
  });

  it('throws on empty statement', () => {
    expect(() =>
      defineConjecture({
        id: 'id',
        name: 'Name',
        statement: '',
        informalArgument: 'Argument',
      }),
    ).toThrow('statement must be a non-empty string');
  });

  it('throws on empty informalArgument', () => {
    expect(() =>
      defineConjecture({
        id: 'id',
        name: 'Name',
        statement: 'Statement',
        informalArgument: '',
      }),
    ).toThrow('informalArgument must be a non-empty string');
  });

  it('accepts boundary confidence values (0 and 1)', () => {
    const zero = defineConjecture({
      id: 'zero',
      name: 'Zero',
      statement: 'Zero confidence',
      informalArgument: 'Wild guess',
      confidence: 0,
    });
    expect(zero.confidence).toBe(0);

    const one = defineConjecture({
      id: 'one',
      name: 'One',
      statement: 'Full confidence',
      informalArgument: 'Certain',
      confidence: 1,
    });
    expect(one.confidence).toBe(1);
  });
});

describe('getStandardConjectures', () => {
  it('returns exactly 4 conjectures', () => {
    const conjectures = getStandardConjectures();
    expect(conjectures).toHaveLength(4);
  });

  it('returns observation_bound conjecture with correct properties', () => {
    const conjectures = getStandardConjectures();
    const ob = conjectures.find(c => c.id === 'observation_bound');
    expect(ob).toBeDefined();
    expect(ob!.name).toBe('Observation Bound');
    expect(ob!.confidence).toBe(0.85);
    expect(ob!.status).toBe('conjecture');
    expect(ob!.statement).toContain('observation proportional to action space');
    expect(ob!.implications.length).toBeGreaterThan(0);
    expect(ob!.counterexampleSpace.length).toBeGreaterThan(0);
    expect(ob!.informalArgument.length).toBeGreaterThan(0);
  });

  it('returns trust_privacy_tradeoff conjecture with correct properties', () => {
    const conjectures = getStandardConjectures();
    const tp = conjectures.find(c => c.id === 'trust_privacy_tradeoff');
    expect(tp).toBeDefined();
    expect(tp!.name).toBe('Trust-Privacy Tradeoff');
    expect(tp!.confidence).toBe(0.90);
    expect(tp!.status).toBe('informal_argument');
    expect(tp!.statement).toContain('privacy');
    expect(tp!.implications.length).toBeGreaterThan(0);
  });

  it('returns composition_limit conjecture with correct properties', () => {
    const conjectures = getStandardConjectures();
    const cl = conjectures.find(c => c.id === 'composition_limit');
    expect(cl).toBeDefined();
    expect(cl!.name).toBe('Composition Limit');
    expect(cl!.confidence).toBe(0.75);
    expect(cl!.status).toBe('conjecture');
    expect(cl!.statement).toContain('chain length');
    expect(cl!.implications.length).toBeGreaterThan(0);
  });

  it('returns collateralization_theorem conjecture with correct properties', () => {
    const conjectures = getStandardConjectures();
    const ct = conjectures.find(c => c.id === 'collateralization_theorem');
    expect(ct).toBeDefined();
    expect(ct!.name).toBe('Collateralization Theorem');
    expect(ct!.confidence).toBe(0.95);
    expect(ct!.status).toBe('informal_argument');
    expect(ct!.statement).toContain('economic value');
    expect(ct!.implications.length).toBeGreaterThan(0);
  });

  it('all conjectures have unique ids', () => {
    const conjectures = getStandardConjectures();
    const ids = conjectures.map(c => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('all conjectures have confidence in [0, 1]', () => {
    const conjectures = getStandardConjectures();
    for (const c of conjectures) {
      expect(c.confidence).toBeGreaterThanOrEqual(0);
      expect(c.confidence).toBeLessThanOrEqual(1);
    }
  });

  it('returns a new array on each call (no shared state)', () => {
    const a = getStandardConjectures();
    const b = getStandardConjectures();
    expect(a).not.toBe(b);
    expect(a).toEqual(b);
  });
});

// ---------------------------------------------------------------------------
// analyzeImpossibilityBounds (Protocol Level Impossibility Bounds)
// ---------------------------------------------------------------------------
describe('analyzeImpossibilityBounds', () => {
  const defaultParams = {
    actionSpaceSize: 1000,
    observationBudget: 100,
    privacyRequirement: 0.3,
    chainLength: 5,
    collateral: 10000,
  };

  it('returns exactly 4 bounds (one per standard conjecture)', () => {
    const bounds = analyzeImpossibilityBounds(defaultParams);
    expect(bounds).toHaveLength(4);
  });

  it('observation_bound: lowerBound = actionSpaceSize / observationBudget', () => {
    const bounds = analyzeImpossibilityBounds(defaultParams);
    const ob = bounds.find(b => b.conjecture.id === 'observation_bound')!;
    expect(ob.lowerBound).toBeCloseTo(1000 / 100, 10);
    expect(ob.upperBound).toBeUndefined();
  });

  it('trust_privacy_tradeoff: upperBound = 1 - privacyRequirement', () => {
    const bounds = analyzeImpossibilityBounds(defaultParams);
    const tp = bounds.find(b => b.conjecture.id === 'trust_privacy_tradeoff')!;
    expect(tp.upperBound).toBeCloseTo(1 - 0.3, 10);
    expect(tp.lowerBound).toBeUndefined();
  });

  it('composition_limit: upperBound = 1 / chainLength', () => {
    const bounds = analyzeImpossibilityBounds(defaultParams);
    const cl = bounds.find(b => b.conjecture.id === 'composition_limit')!;
    expect(cl.upperBound).toBeCloseTo(1 / 5, 10);
    expect(cl.lowerBound).toBeUndefined();
  });

  it('collateralization_theorem: upperBound = collateral', () => {
    const bounds = analyzeImpossibilityBounds(defaultParams);
    const ct = bounds.find(b => b.conjecture.id === 'collateralization_theorem')!;
    expect(ct.upperBound).toBe(10000);
    expect(ct.lowerBound).toBeUndefined();
  });

  it('observation bound is achievable when budget >= action space', () => {
    const bounds = analyzeImpossibilityBounds({
      ...defaultParams,
      actionSpaceSize: 50,
      observationBudget: 100,
    });
    const ob = bounds.find(b => b.conjecture.id === 'observation_bound')!;
    expect(ob.knownAchievable).toBe(true);
    expect(ob.lowerBound!).toBeLessThanOrEqual(1);
  });

  it('observation bound is not achievable when budget < action space', () => {
    const bounds = analyzeImpossibilityBounds({
      ...defaultParams,
      actionSpaceSize: 1000,
      observationBudget: 100,
    });
    const ob = bounds.find(b => b.conjecture.id === 'observation_bound')!;
    expect(ob.knownAchievable).toBe(false);
    expect(ob.lowerBound!).toBeGreaterThan(1);
  });

  it('trust-privacy: knownAchievable true when privacyRequirement < 1', () => {
    const bounds = analyzeImpossibilityBounds({
      ...defaultParams,
      privacyRequirement: 0.5,
    });
    const tp = bounds.find(b => b.conjecture.id === 'trust_privacy_tradeoff')!;
    expect(tp.knownAchievable).toBe(true);
    expect(tp.upperBound).toBeCloseTo(0.5, 10);
  });

  it('trust-privacy: knownAchievable false when privacyRequirement = 1', () => {
    const bounds = analyzeImpossibilityBounds({
      ...defaultParams,
      privacyRequirement: 1.0,
    });
    const tp = bounds.find(b => b.conjecture.id === 'trust_privacy_tradeoff')!;
    expect(tp.knownAchievable).toBe(false);
    expect(tp.upperBound).toBe(0);
  });

  it('composition: knownAchievable true only for chainLength=1', () => {
    const single = analyzeImpossibilityBounds({
      ...defaultParams,
      chainLength: 1,
    });
    const cl1 = single.find(b => b.conjecture.id === 'composition_limit')!;
    expect(cl1.knownAchievable).toBe(true);
    expect(cl1.upperBound).toBe(1);

    const multi = analyzeImpossibilityBounds({
      ...defaultParams,
      chainLength: 3,
    });
    const cl3 = multi.find(b => b.conjecture.id === 'composition_limit')!;
    expect(cl3.knownAchievable).toBe(false);
    expect(cl3.upperBound).toBeCloseTo(1 / 3, 10);
  });

  it('collateralization: knownAchievable true when collateral > 0', () => {
    const bounds = analyzeImpossibilityBounds(defaultParams);
    const ct = bounds.find(b => b.conjecture.id === 'collateralization_theorem')!;
    expect(ct.knownAchievable).toBe(true);
  });

  it('collateralization: knownAchievable false when collateral = 0', () => {
    const bounds = analyzeImpossibilityBounds({
      ...defaultParams,
      collateral: 0,
    });
    const ct = bounds.find(b => b.conjecture.id === 'collateralization_theorem')!;
    expect(ct.knownAchievable).toBe(false);
    expect(ct.upperBound).toBe(0);
  });

  it('tightness estimates are in [0, 1]', () => {
    const bounds = analyzeImpossibilityBounds(defaultParams);
    for (const b of bounds) {
      expect(b.tightnessEstimate).toBeGreaterThanOrEqual(0);
      expect(b.tightnessEstimate).toBeLessThanOrEqual(1);
    }
  });

  it('each bound has a valid conjecture reference', () => {
    const bounds = analyzeImpossibilityBounds(defaultParams);
    const standardIds = getStandardConjectures().map(c => c.id);
    for (const b of bounds) {
      expect(standardIds).toContain(b.conjecture.id);
      expect(b.conjecture.name.length).toBeGreaterThan(0);
      expect(b.conjecture.statement.length).toBeGreaterThan(0);
    }
  });

  // --- Validation ---
  it('throws on negative actionSpaceSize', () => {
    expect(() =>
      analyzeImpossibilityBounds({ ...defaultParams, actionSpaceSize: -1 }),
    ).toThrow('actionSpaceSize must be >= 0');
  });

  it('throws on observationBudget <= 0', () => {
    expect(() =>
      analyzeImpossibilityBounds({ ...defaultParams, observationBudget: 0 }),
    ).toThrow('observationBudget must be > 0');
    expect(() =>
      analyzeImpossibilityBounds({ ...defaultParams, observationBudget: -10 }),
    ).toThrow('observationBudget must be > 0');
  });

  it('throws on privacyRequirement out of range', () => {
    expect(() =>
      analyzeImpossibilityBounds({ ...defaultParams, privacyRequirement: -0.1 }),
    ).toThrow('privacyRequirement must be in [0, 1]');
    expect(() =>
      analyzeImpossibilityBounds({ ...defaultParams, privacyRequirement: 1.5 }),
    ).toThrow('privacyRequirement must be in [0, 1]');
  });

  it('throws on chainLength < 1', () => {
    expect(() =>
      analyzeImpossibilityBounds({ ...defaultParams, chainLength: 0 }),
    ).toThrow('chainLength must be >= 1');
  });

  it('throws on negative collateral', () => {
    expect(() =>
      analyzeImpossibilityBounds({ ...defaultParams, collateral: -100 }),
    ).toThrow('collateral must be >= 0');
  });

  it('handles large action space relative to budget', () => {
    const bounds = analyzeImpossibilityBounds({
      actionSpaceSize: 1_000_000,
      observationBudget: 10,
      privacyRequirement: 0.5,
      chainLength: 1,
      collateral: 100,
    });
    const ob = bounds.find(b => b.conjecture.id === 'observation_bound')!;
    expect(ob.lowerBound).toBe(100000);
    expect(ob.knownAchievable).toBe(false);
    expect(ob.tightnessEstimate).toBeCloseTo(0.00001, 8);
  });

  it('handles zero privacy requirement', () => {
    const bounds = analyzeImpossibilityBounds({
      ...defaultParams,
      privacyRequirement: 0,
    });
    const tp = bounds.find(b => b.conjecture.id === 'trust_privacy_tradeoff')!;
    expect(tp.upperBound).toBe(1);
    expect(tp.knownAchievable).toBe(true);
  });

  it('handles long chain length', () => {
    const bounds = analyzeImpossibilityBounds({
      ...defaultParams,
      chainLength: 100,
    });
    const cl = bounds.find(b => b.conjecture.id === 'composition_limit')!;
    expect(cl.upperBound).toBeCloseTo(0.01, 10);
    expect(cl.knownAchievable).toBe(false);
  });
});
