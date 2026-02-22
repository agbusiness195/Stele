import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createTrustGate,
  evaluateAccess,
  calculateRevenueLift,
} from './trust-gate';
import type { TrustGateConfig, AccessLevel, GateDecision } from './trust-gate';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Small epsilon for floating-point boundary tests. */
const EPSILON = 1e-10;

// ─── createTrustGate ──────────────────────────────────────────────────────────

describe('createTrustGate', () => {
  it('returns sensible defaults when called with no arguments', () => {
    const gate = createTrustGate();
    expect(gate.minimumTrustScore).toBe(0.5);
    expect(gate.premiumThreshold).toBe(0.9);
    expect(gate.gracePeriodMs).toBe(86400000);
    expect(gate.bypassTokens).toEqual([]);
  });

  it('allows partial overrides', () => {
    const gate = createTrustGate({ minimumTrustScore: 0.3 });
    expect(gate.minimumTrustScore).toBe(0.3);
    expect(gate.premiumThreshold).toBe(0.9); // still default
  });

  it('accepts an empty bypass token array explicitly', () => {
    const gate = createTrustGate({ bypassTokens: [] });
    expect(gate.bypassTokens).toEqual([]);
  });

  it('preserves all overrides', () => {
    const gate = createTrustGate({
      minimumTrustScore: 0.1,
      premiumThreshold: 0.95,
      gracePeriodMs: 1000,
      bypassTokens: ['tok-a', 'tok-b'],
    });
    expect(gate.minimumTrustScore).toBe(0.1);
    expect(gate.premiumThreshold).toBe(0.95);
    expect(gate.gracePeriodMs).toBe(1000);
    expect(gate.bypassTokens).toEqual(['tok-a', 'tok-b']);
  });
});

// ─── evaluateAccess: threshold boundary tests ─────────────────────────────────

describe('evaluateAccess', () => {
  // ── Exact boundary: minimumTrustScore (0.5) ─────────────────────────

  describe('minimumTrustScore boundary (default 0.5)', () => {
    const gate = createTrustGate();

    it('grants basic access when trust score is exactly 0.5', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-boundary-min',
        trustScore: 0.5,
      });
      expect(decision.accessLevel).toBe('basic');
      expect(decision.rateLimit).toBe(10);
    });

    it('denies access when trust score is just below 0.5', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-below-min',
        trustScore: 0.5 - EPSILON,
      });
      expect(decision.accessLevel).toBe('denied');
      expect(decision.rateLimit).toBe(0);
    });

    it('grants basic access when trust score is just above 0.5', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-above-min',
        trustScore: 0.5 + EPSILON,
      });
      expect(decision.accessLevel).toBe('basic');
      expect(decision.rateLimit).toBe(10);
    });
  });

  // ── Exact boundary: standard threshold (0.7) ───────────────────────

  describe('standard threshold boundary (0.7)', () => {
    const gate = createTrustGate();

    it('grants standard access when trust score is exactly 0.7', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-boundary-std',
        trustScore: 0.7,
      });
      expect(decision.accessLevel).toBe('standard');
      expect(decision.rateLimit).toBe(100);
    });

    it('grants basic access when trust score is just below 0.7', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-below-std',
        trustScore: 0.7 - EPSILON,
      });
      expect(decision.accessLevel).toBe('basic');
      expect(decision.rateLimit).toBe(10);
    });

    it('grants standard access when trust score is just above 0.7', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-above-std',
        trustScore: 0.7 + EPSILON,
      });
      expect(decision.accessLevel).toBe('standard');
      expect(decision.rateLimit).toBe(100);
    });
  });

  // ── Exact boundary: premiumThreshold (0.9) ─────────────────────────

  describe('premiumThreshold boundary (default 0.9)', () => {
    const gate = createTrustGate();

    it('grants premium access when trust score is exactly 0.9', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-boundary-premium',
        trustScore: 0.9,
      });
      expect(decision.accessLevel).toBe('premium');
      expect(decision.rateLimit).toBe(1000);
    });

    it('grants standard access when trust score is just below 0.9', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-below-premium',
        trustScore: 0.9 - EPSILON,
      });
      expect(decision.accessLevel).toBe('standard');
      expect(decision.rateLimit).toBe(100);
    });

    it('grants premium access when trust score is just above 0.9', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-above-premium',
        trustScore: 0.9 + EPSILON,
      });
      expect(decision.accessLevel).toBe('premium');
      expect(decision.rateLimit).toBe(1000);
    });
  });

  // ── Extreme trust score values ─────────────────────────────────────

  describe('extreme trust score values', () => {
    const gate = createTrustGate();

    it('denies access for trust score of 0', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-zero',
        trustScore: 0,
      });
      expect(decision.accessLevel).toBe('denied');
      expect(decision.rateLimit).toBe(0);
    });

    it('grants premium access for trust score of 1.0', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-perfect',
        trustScore: 1.0,
      });
      expect(decision.accessLevel).toBe('premium');
      expect(decision.rateLimit).toBe(1000);
    });

    it('denies access for negative trust score', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-negative',
        trustScore: -0.1,
      });
      expect(decision.accessLevel).toBe('denied');
    });

    it('grants premium access for trust score above 1.0', () => {
      const decision = evaluateAccess(gate, {
        agentId: 'agent-over',
        trustScore: 1.5,
      });
      expect(decision.accessLevel).toBe('premium');
    });
  });

  // ── Custom thresholds ──────────────────────────────────────────────

  describe('custom threshold configuration', () => {
    it('uses custom minimumTrustScore', () => {
      const gate = createTrustGate({ minimumTrustScore: 0.3 });

      const decision = evaluateAccess(gate, {
        agentId: 'agent-custom',
        trustScore: 0.3,
      });
      expect(decision.accessLevel).toBe('basic');

      const denied = evaluateAccess(gate, {
        agentId: 'agent-custom-low',
        trustScore: 0.29,
      });
      expect(denied.accessLevel).toBe('denied');
    });

    it('uses custom premiumThreshold', () => {
      const gate = createTrustGate({ premiumThreshold: 0.8 });

      const premium = evaluateAccess(gate, {
        agentId: 'agent-custom-premium',
        trustScore: 0.8,
      });
      expect(premium.accessLevel).toBe('premium');

      const standard = evaluateAccess(gate, {
        agentId: 'agent-custom-standard',
        trustScore: 0.79,
      });
      expect(standard.accessLevel).toBe('standard');
    });
  });

  // ── Grace period ───────────────────────────────────────────────────

  describe('grace period', () => {
    it('grants basic access during grace period even with low trust score', () => {
      const gate = createTrustGate({ gracePeriodMs: 60000 });
      const now = Date.now();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-new',
        trustScore: 0.1,
        registeredAt: now - 30000, // 30s ago, still within 60s grace period
      });
      expect(decision.accessLevel).toBe('basic');
      expect(decision.reason).toContain('grace period');
    });

    it('denies access after grace period expires with low trust score', () => {
      const gate = createTrustGate({ gracePeriodMs: 60000 });
      const now = Date.now();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-expired',
        trustScore: 0.1,
        registeredAt: now - 120000, // 2 minutes ago, past 60s grace period
      });
      expect(decision.accessLevel).toBe('denied');
    });

    it('does NOT grant grace period when registeredAt + gracePeriodMs equals now exactly', () => {
      // The implementation uses strictly-greater-than: registeredAt + gracePeriodMs > now
      // So when registeredAt + gracePeriodMs === now, the agent is NOT in the grace period.
      const gate = createTrustGate({ gracePeriodMs: 60000 });
      const now = Date.now();

      // Mock Date.now so that registeredAt + gracePeriodMs === now
      const mockNow = vi.spyOn(Date, 'now').mockReturnValue(now);

      const decision = evaluateAccess(gate, {
        agentId: 'agent-exact-grace',
        trustScore: 0.1,
        registeredAt: now - 60000, // exactly at the boundary
      });

      // registeredAt + gracePeriodMs = (now - 60000) + 60000 = now
      // condition: now > now is false, so NOT in grace period
      expect(decision.accessLevel).toBe('denied');

      mockNow.mockRestore();
    });

    it('grants grace period when registeredAt + gracePeriodMs is 1ms after now', () => {
      const gate = createTrustGate({ gracePeriodMs: 60000 });
      const now = Date.now();

      const mockNow = vi.spyOn(Date, 'now').mockReturnValue(now);

      const decision = evaluateAccess(gate, {
        agentId: 'agent-1ms-grace',
        trustScore: 0.1,
        registeredAt: now - 59999, // registeredAt + 60000 = now + 1 > now
      });
      expect(decision.accessLevel).toBe('basic');
      expect(decision.reason).toContain('grace period');

      mockNow.mockRestore();
    });

    it('grace period does not upgrade access beyond what score earns if score is high', () => {
      // Grace period only helps when trust score < minimumTrustScore.
      // An agent with a good trust score during grace period gets their normal tier.
      const gate = createTrustGate({ gracePeriodMs: 60000 });
      const now = Date.now();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-good-new',
        trustScore: 0.95,
        registeredAt: now - 30000,
      });
      // Score 0.95 >= 0.9 premiumThreshold, so premium
      expect(decision.accessLevel).toBe('premium');
    });

    it('grace period applies only when registeredAt is provided', () => {
      const gate = createTrustGate({ gracePeriodMs: 60000 });

      const decision = evaluateAccess(gate, {
        agentId: 'agent-no-reg',
        trustScore: 0.1,
        // no registeredAt
      });
      expect(decision.accessLevel).toBe('denied');
    });

    it('grace period with zero duration never grants grace', () => {
      const gate = createTrustGate({ gracePeriodMs: 0 });
      const now = Date.now();

      const mockNow = vi.spyOn(Date, 'now').mockReturnValue(now);

      const decision = evaluateAccess(gate, {
        agentId: 'agent-zero-grace',
        trustScore: 0.1,
        registeredAt: now, // registeredAt + 0 = now, not > now
      });
      expect(decision.accessLevel).toBe('denied');

      mockNow.mockRestore();
    });
  });

  // ── Bypass tokens ──────────────────────────────────────────────────

  describe('bypass tokens', () => {
    it('grants premium access with a valid bypass token', () => {
      const gate = createTrustGate({ bypassTokens: ['test-token'] });

      const decision = evaluateAccess(gate, {
        agentId: 'agent-bypass',
        trustScore: 0.0,
        bypassToken: 'test-token',
      });
      expect(decision.accessLevel).toBe('premium');
      expect(decision.rateLimit).toBe(1000);
      expect(decision.reason).toContain('bypass token');
    });

    it('does not grant bypass for an invalid token', () => {
      const gate = createTrustGate({ bypassTokens: ['valid-token'] });

      const decision = evaluateAccess(gate, {
        agentId: 'agent-bad-bypass',
        trustScore: 0.0,
        bypassToken: 'wrong-token',
      });
      expect(decision.accessLevel).toBe('denied');
    });

    it('does not grant bypass when bypassTokens array is empty', () => {
      const gate = createTrustGate({ bypassTokens: [] });

      const decision = evaluateAccess(gate, {
        agentId: 'agent-no-bypass',
        trustScore: 0.0,
        bypassToken: 'some-token',
      });
      expect(decision.accessLevel).toBe('denied');
    });

    it('does not grant bypass when bypassToken param is undefined', () => {
      const gate = createTrustGate({ bypassTokens: ['test-token'] });

      const decision = evaluateAccess(gate, {
        agentId: 'agent-no-token',
        trustScore: 0.0,
      });
      expect(decision.accessLevel).toBe('denied');
    });

    it('does not grant bypass when bypassToken param is empty string', () => {
      const gate = createTrustGate({ bypassTokens: ['test-token'] });

      const decision = evaluateAccess(gate, {
        agentId: 'agent-empty-token',
        trustScore: 0.0,
        bypassToken: '',
      });
      // Empty string is falsy, so bypass check is skipped
      expect(decision.accessLevel).toBe('denied');
    });

    it('bypass token takes priority over all other checks', () => {
      const gate = createTrustGate({ bypassTokens: ['master-key'] });

      // Even with a high trust score and grace period, bypass path takes priority
      const decision = evaluateAccess(gate, {
        agentId: 'agent-bypass-priority',
        trustScore: 0.95,
        registeredAt: Date.now(),
        bypassToken: 'master-key',
      });
      expect(decision.accessLevel).toBe('premium');
      expect(decision.reason).toContain('bypass token');
    });

    it('handles multiple bypass tokens correctly', () => {
      const gate = createTrustGate({
        bypassTokens: ['token-a', 'token-b', 'token-c'],
      });

      const decisionA = evaluateAccess(gate, {
        agentId: 'agent-a',
        trustScore: 0,
        bypassToken: 'token-a',
      });
      expect(decisionA.accessLevel).toBe('premium');

      const decisionC = evaluateAccess(gate, {
        agentId: 'agent-c',
        trustScore: 0,
        bypassToken: 'token-c',
      });
      expect(decisionC.accessLevel).toBe('premium');

      const decisionD = evaluateAccess(gate, {
        agentId: 'agent-d',
        trustScore: 0,
        bypassToken: 'token-d',
      });
      expect(decisionD.accessLevel).toBe('denied');
    });
  });

  // ── Decision metadata ──────────────────────────────────────────────

  describe('decision metadata', () => {
    it('includes the correct agentId in the decision', () => {
      const gate = createTrustGate();

      const decision = evaluateAccess(gate, {
        agentId: 'my-unique-agent',
        trustScore: 0.6,
      });
      expect(decision.agentId).toBe('my-unique-agent');
    });

    it('includes the trust score in the decision', () => {
      const gate = createTrustGate();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-score',
        trustScore: 0.75,
      });
      expect(decision.trustScore).toBe(0.75);
    });

    it('sets expiresAt to approximately 1 hour from now', () => {
      const gate = createTrustGate();
      const before = Date.now();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-ttl',
        trustScore: 0.6,
      });

      const after = Date.now();
      const ONE_HOUR = 3600000;

      expect(decision.expiresAt).toBeGreaterThanOrEqual(before + ONE_HOUR);
      expect(decision.expiresAt).toBeLessThanOrEqual(after + ONE_HOUR);
    });

    it('includes a human-readable reason for denied access', () => {
      const gate = createTrustGate();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-denied',
        trustScore: 0.3,
      });
      expect(decision.reason).toContain('below minimum threshold');
      expect(decision.reason).toContain('0.3');
      expect(decision.reason).toContain('0.5');
    });

    it('includes a human-readable reason for premium access', () => {
      const gate = createTrustGate();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-premium',
        trustScore: 0.95,
      });
      expect(decision.reason).toContain('premium');
    });

    it('includes a human-readable reason for standard access', () => {
      const gate = createTrustGate();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-standard',
        trustScore: 0.75,
      });
      expect(decision.reason).toContain('standard');
    });

    it('includes a human-readable reason for basic access', () => {
      const gate = createTrustGate();

      const decision = evaluateAccess(gate, {
        agentId: 'agent-basic',
        trustScore: 0.55,
      });
      expect(decision.reason).toContain('basic');
    });
  });

  // ── Tier progression sweep ─────────────────────────────────────────

  describe('tier progression sweep', () => {
    const gate = createTrustGate();

    const cases: Array<{ score: number; expected: AccessLevel }> = [
      { score: 0.0, expected: 'denied' },
      { score: 0.25, expected: 'denied' },
      { score: 0.49, expected: 'denied' },
      { score: 0.499999999, expected: 'denied' },
      { score: 0.5, expected: 'basic' },
      { score: 0.55, expected: 'basic' },
      { score: 0.6, expected: 'basic' },
      { score: 0.69, expected: 'basic' },
      { score: 0.699999999, expected: 'basic' },
      { score: 0.7, expected: 'standard' },
      { score: 0.75, expected: 'standard' },
      { score: 0.8, expected: 'standard' },
      { score: 0.85, expected: 'standard' },
      { score: 0.899999999, expected: 'standard' },
      { score: 0.9, expected: 'premium' },
      { score: 0.95, expected: 'premium' },
      { score: 1.0, expected: 'premium' },
    ];

    for (const { score, expected } of cases) {
      it(`trust score ${score} -> ${expected}`, () => {
        const decision = evaluateAccess(gate, {
          agentId: `sweep-${score}`,
          trustScore: score,
        });
        expect(decision.accessLevel).toBe(expected);
      });
    }
  });
});

// ─── calculateRevenueLift ─────────────────────────────────────────────────────

describe('calculateRevenueLift', () => {
  it('returns zero revenue with 0 total agents', () => {
    const result = calculateRevenueLift({
      totalAgents: 0,
      nobulexAdoptionRate: 0.5,
      premiumRate: 0.5,
      premiumPriceMultiplier: 3,
    });
    expect(result.totalRevenue).toBe(0);
    expect(result.nobulexRevenue).toBe(0);
    expect(result.liftPercentage).toBe(0);
  });

  it('returns baseline revenue with 0% Nobulex adoption', () => {
    const result = calculateRevenueLift({
      totalAgents: 100,
      nobulexAdoptionRate: 0,
      premiumRate: 0.5,
      premiumPriceMultiplier: 3,
    });
    // All agents are non-Nobulex at 1x each
    expect(result.totalRevenue).toBe(100);
    expect(result.nobulexRevenue).toBe(0);
    // liftPercentage = ((0 - 100) / 100) * 100 = -100
    expect(result.liftPercentage).toBe(-100);
  });

  it('returns baseline revenue with 100% Nobulex adoption and 0% premium', () => {
    const result = calculateRevenueLift({
      totalAgents: 100,
      nobulexAdoptionRate: 1.0,
      premiumRate: 0,
      premiumPriceMultiplier: 3,
    });
    // All agents are Nobulex standard at 1x each
    expect(result.totalRevenue).toBe(100);
    expect(result.nobulexRevenue).toBe(100);
    // liftPercentage = ((100 - 100) / 100) * 100 = 0
    expect(result.liftPercentage).toBe(0);
  });

  it('calculates positive lift with premium multiplier', () => {
    const result = calculateRevenueLift({
      totalAgents: 100,
      nobulexAdoptionRate: 1.0,
      premiumRate: 1.0,
      premiumPriceMultiplier: 3,
    });
    // All 100 agents are Nobulex premium at 3x each
    expect(result.totalRevenue).toBe(300);
    expect(result.nobulexRevenue).toBe(300);
    // liftPercentage = ((300 - 100) / 100) * 100 = 200
    expect(result.liftPercentage).toBe(200);
  });

  it('handles partial Nobulex adoption and partial premium rate', () => {
    const result = calculateRevenueLift({
      totalAgents: 1000,
      nobulexAdoptionRate: 0.5,
      premiumRate: 0.2,
      premiumPriceMultiplier: 5,
    });
    // 500 Nobulex agents, 500 non-Nobulex agents
    // 100 premium agents (500 * 0.2), 400 standard Nobulex agents
    // nonNobulexRevenue = 500 * 1 = 500
    // standardRevenue = 400 * 1 = 400
    // premiumRevenue = 100 * 5 = 500
    // nobulexRevenue = 400 + 500 = 900
    // totalRevenue = 500 + 900 = 1400
    // baseRevenue = 1000
    // liftPercentage = ((900 - 1000) / 1000) * 100 = -10
    expect(result.totalRevenue).toBe(1400);
    expect(result.nobulexRevenue).toBe(900);
    expect(result.liftPercentage).toBe(-10);
  });

  it('returns 0 lift percentage when base revenue is 0', () => {
    const result = calculateRevenueLift({
      totalAgents: 0,
      nobulexAdoptionRate: 1.0,
      premiumRate: 1.0,
      premiumPriceMultiplier: 10,
    });
    expect(result.liftPercentage).toBe(0);
  });

  it('handles premiumPriceMultiplier of 1 (no uplift)', () => {
    const result = calculateRevenueLift({
      totalAgents: 100,
      nobulexAdoptionRate: 1.0,
      premiumRate: 1.0,
      premiumPriceMultiplier: 1,
    });
    // All agents at 1x, so nobulexRevenue = 100, base = 100, lift = 0
    expect(result.totalRevenue).toBe(100);
    expect(result.nobulexRevenue).toBe(100);
    expect(result.liftPercentage).toBe(0);
  });

  it('handles a single agent', () => {
    const result = calculateRevenueLift({
      totalAgents: 1,
      nobulexAdoptionRate: 1.0,
      premiumRate: 1.0,
      premiumPriceMultiplier: 10,
    });
    expect(result.totalRevenue).toBe(10);
    expect(result.nobulexRevenue).toBe(10);
    // liftPercentage = ((10 - 1) / 1) * 100 = 900
    expect(result.liftPercentage).toBe(900);
  });

  it('handles fractional agent counts correctly', () => {
    // In real usage totalAgents is likely an integer, but the math works with fractions
    const result = calculateRevenueLift({
      totalAgents: 3,
      nobulexAdoptionRate: 1 / 3,
      premiumRate: 1.0,
      premiumPriceMultiplier: 2,
    });
    // nobulexAgents = 1, nonNobulex = 2
    // premiumAgents = 1, standardNobulex = 0
    // nonNobulexRevenue = 2, premiumRevenue = 2, nobulexRevenue = 2
    // totalRevenue = 4, base = 3
    // liftPercentage = ((2 - 3) / 3) * 100 = -33.333...
    expect(result.totalRevenue).toBeCloseTo(4);
    expect(result.nobulexRevenue).toBeCloseTo(2);
    expect(result.liftPercentage).toBeCloseTo(-33.3333, 2);
  });
});
