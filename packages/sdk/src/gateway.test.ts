import { describe, it, expect } from 'vitest';
import {
  createGateway,
  isResourceAllowed,
  processRequest,
  aggregateMetrics,
} from './gateway.js';
import type { GatewayConfig, GatewayRequest, GatewayResponse } from './gateway.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(overrides?: Partial<GatewayRequest>): GatewayRequest {
  return {
    agentId: 'agent-1',
    resource: '/data',
    action: 'read',
    trustScore: 0.9,
    hasCovenant: true,
    hasIdentity: true,
    timestamp: Date.now(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// createGateway
// ---------------------------------------------------------------------------

describe('createGateway', () => {
  it('returns sensible defaults when called with no arguments', () => {
    const gw = createGateway();
    expect(gw.requireCovenant).toBe(true);
    expect(gw.requireIdentity).toBe(true);
    expect(gw.requireMinimumTrust).toBe(0.0);
    expect(gw.logAllRequests).toBe(true);
    expect(gw.rateLimitPerMinute).toBe(60);
    expect(gw.allowedResources).toEqual(['*']);
    expect(gw.blockedResources).toEqual([]);
  });

  it('merges partial overrides with defaults', () => {
    const gw = createGateway({ requireCovenant: false, rateLimitPerMinute: 100 });
    expect(gw.requireCovenant).toBe(false);
    expect(gw.rateLimitPerMinute).toBe(100);
    // Non-overridden defaults remain
    expect(gw.requireIdentity).toBe(true);
    expect(gw.allowedResources).toEqual(['*']);
  });

  it('accepts an empty partial config', () => {
    const gw = createGateway({});
    expect(gw.requireCovenant).toBe(true);
    expect(gw.allowedResources).toEqual(['*']);
  });

  it('allows setting requireMinimumTrust to zero explicitly', () => {
    const gw = createGateway({ requireMinimumTrust: 0 });
    expect(gw.requireMinimumTrust).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// isResourceAllowed — Resource Path Matching
// ---------------------------------------------------------------------------

describe('isResourceAllowed', () => {
  describe('exact match only (no partial matching)', () => {
    it('allows an exact match in the allowed list', () => {
      const gw = createGateway({ allowedResources: ['/api/users'] });
      expect(isResourceAllowed(gw, '/api/users')).toBe(true);
    });

    it('denies a resource that is a prefix of an allowed resource (no partial match)', () => {
      const gw = createGateway({ allowedResources: ['/api/users'] });
      // "/api" is a prefix of "/api/users" but not an exact match or child
      expect(isResourceAllowed(gw, '/api')).toBe(false);
    });

    it('denies a resource that only shares a common prefix with allowed', () => {
      const gw = createGateway({ allowedResources: ['/api/users'] });
      // "/api/usersettings" starts with "/api/users" but NOT "/api/users/"
      expect(isResourceAllowed(gw, '/api/usersettings')).toBe(false);
    });

    it('allows a sub-path under an allowed resource via startsWith + "/"', () => {
      const gw = createGateway({ allowedResources: ['/api/users'] });
      expect(isResourceAllowed(gw, '/api/users/123')).toBe(true);
    });

    it('denies a completely unrelated resource', () => {
      const gw = createGateway({ allowedResources: ['/api/users'] });
      expect(isResourceAllowed(gw, '/admin/settings')).toBe(false);
    });

    it('treats resources as case-sensitive', () => {
      const gw = createGateway({ allowedResources: ['/Api/Users'] });
      expect(isResourceAllowed(gw, '/api/users')).toBe(false);
      expect(isResourceAllowed(gw, '/Api/Users')).toBe(true);
    });
  });

  describe('wildcard "*" allowing all resources', () => {
    it('allows any resource when allowedResources contains "*"', () => {
      const gw = createGateway({ allowedResources: ['*'] });
      expect(isResourceAllowed(gw, '/anything')).toBe(true);
      expect(isResourceAllowed(gw, '/deeply/nested/path')).toBe(true);
      expect(isResourceAllowed(gw, '')).toBe(true);
    });

    it('allows all when "*" is among other entries', () => {
      const gw = createGateway({ allowedResources: ['/specific', '*'] });
      expect(isResourceAllowed(gw, '/unrelated')).toBe(true);
    });

    it('denies everything when allowedResources is empty (no wildcard)', () => {
      const gw = createGateway({ allowedResources: [] });
      expect(isResourceAllowed(gw, '/data')).toBe(false);
      expect(isResourceAllowed(gw, '/')).toBe(false);
    });
  });

  describe('blocked resources take precedence over allowed', () => {
    it('blocks exact match even when wildcard allows all', () => {
      const gw = createGateway({
        allowedResources: ['*'],
        blockedResources: ['/secrets'],
      });
      expect(isResourceAllowed(gw, '/secrets')).toBe(false);
    });

    it('blocks sub-paths of a blocked resource', () => {
      const gw = createGateway({
        allowedResources: ['*'],
        blockedResources: ['/admin'],
      });
      expect(isResourceAllowed(gw, '/admin/panel')).toBe(false);
      expect(isResourceAllowed(gw, '/admin/panel/settings')).toBe(false);
    });

    it('does not block a resource that merely shares a prefix with blocked', () => {
      const gw = createGateway({
        allowedResources: ['*'],
        blockedResources: ['/admin'],
      });
      // "/administrator" starts with "/admin" but NOT "/admin/"
      expect(isResourceAllowed(gw, '/administrator')).toBe(true);
    });

    it('blocks when resource is in both allowed and blocked lists', () => {
      const gw = createGateway({
        allowedResources: ['/data', '/secrets'],
        blockedResources: ['/secrets'],
      });
      expect(isResourceAllowed(gw, '/secrets')).toBe(false);
      expect(isResourceAllowed(gw, '/data')).toBe(true);
    });

    it('blocks with multiple blocked resources', () => {
      const gw = createGateway({
        allowedResources: ['*'],
        blockedResources: ['/secrets', '/admin', '/internal'],
      });
      expect(isResourceAllowed(gw, '/secrets')).toBe(false);
      expect(isResourceAllowed(gw, '/admin')).toBe(false);
      expect(isResourceAllowed(gw, '/internal')).toBe(false);
      expect(isResourceAllowed(gw, '/public')).toBe(true);
    });
  });

  describe('empty resource strings', () => {
    it('allows empty string when wildcard is set', () => {
      const gw = createGateway({ allowedResources: ['*'] });
      expect(isResourceAllowed(gw, '')).toBe(true);
    });

    it('denies empty string when no wildcard and no matching allowed resource', () => {
      const gw = createGateway({ allowedResources: ['/data'] });
      expect(isResourceAllowed(gw, '')).toBe(false);
    });

    it('allows empty string when empty string is explicitly in allowed list', () => {
      const gw = createGateway({ allowedResources: [''] });
      expect(isResourceAllowed(gw, '')).toBe(true);
    });

    it('blocks empty string when empty string is in blocked list', () => {
      const gw = createGateway({
        allowedResources: ['*'],
        blockedResources: [''],
      });
      expect(isResourceAllowed(gw, '')).toBe(false);
    });
  });

  describe('special resource path patterns', () => {
    it('handles root path "/"', () => {
      const gw = createGateway({ allowedResources: ['/'] });
      expect(isResourceAllowed(gw, '/')).toBe(true);
      // Sub-paths under "/" are allowed since "/".startsWith("/") + "/" is "//"
      // Actually "/data".startsWith("/" + "/") is "/data".startsWith("//") which is false
      // So only exact "/" is matched, not every sub-path
      expect(isResourceAllowed(gw, '/data')).toBe(false);
    });

    it('handles deeply nested paths', () => {
      const gw = createGateway({ allowedResources: ['/a/b/c/d/e'] });
      expect(isResourceAllowed(gw, '/a/b/c/d/e')).toBe(true);
      expect(isResourceAllowed(gw, '/a/b/c/d/e/f')).toBe(true);
      expect(isResourceAllowed(gw, '/a/b/c/d')).toBe(false);
    });

    it('handles resources with special characters', () => {
      const gw = createGateway({ allowedResources: ['/data?query=1'] });
      expect(isResourceAllowed(gw, '/data?query=1')).toBe(true);
      expect(isResourceAllowed(gw, '/data?query=2')).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// processRequest — Request Processing
// ---------------------------------------------------------------------------

describe('processRequest', () => {
  describe('identity verification', () => {
    it('denies when identity is required but not provided', () => {
      const gw = createGateway({ requireIdentity: true });
      const req = makeRequest({ hasIdentity: false });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Identity verification required');
      expect(res.appliedRules).toContain('identity-required');
    });

    it('allows when identity is not required even if not provided', () => {
      const gw = createGateway({ requireIdentity: false, requireCovenant: false });
      const req = makeRequest({ hasIdentity: false });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
    });

    it('identity check is applied before covenant check', () => {
      const gw = createGateway({ requireIdentity: true, requireCovenant: true });
      const req = makeRequest({ hasIdentity: false, hasCovenant: false });
      const res = processRequest(gw, req);
      // Should fail on identity first
      expect(res.reason).toContain('Identity');
      expect(res.appliedRules).toContain('identity-required');
      expect(res.appliedRules).not.toContain('covenant-required');
    });
  });

  describe('covenant presence', () => {
    it('denies when covenant is required but not provided', () => {
      const gw = createGateway({ requireCovenant: true });
      const req = makeRequest({ hasCovenant: false });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Active covenant required');
      expect(res.appliedRules).toContain('covenant-required');
    });

    it('allows when covenant is not required even if not provided', () => {
      const gw = createGateway({ requireCovenant: false, requireIdentity: false });
      const req = makeRequest({ hasCovenant: false });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
    });
  });

  describe('trust score minimum', () => {
    it('denies when trust score is below the minimum', () => {
      const gw = createGateway({ requireMinimumTrust: 0.8 });
      const req = makeRequest({ trustScore: 0.5 });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Trust score 0.5 below minimum 0.8');
      expect(res.appliedRules).toContain('trust-score-minimum');
    });

    it('allows when trust score equals the minimum exactly', () => {
      const gw = createGateway({ requireMinimumTrust: 0.7 });
      const req = makeRequest({ trustScore: 0.7 });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
    });

    it('allows when trust score exceeds the minimum', () => {
      const gw = createGateway({ requireMinimumTrust: 0.5 });
      const req = makeRequest({ trustScore: 0.9 });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
    });

    it('skips trust check when requireMinimumTrust is 0', () => {
      const gw = createGateway({ requireMinimumTrust: 0 });
      const req = makeRequest({ trustScore: 0 });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
      expect(res.appliedRules).not.toContain('trust-score-minimum');
    });

    it('treats undefined trust score as 0', () => {
      const gw = createGateway({ requireMinimumTrust: 0.5 });
      const req = makeRequest({ trustScore: undefined });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Trust score 0 below minimum 0.5');
    });
  });

  describe('unknown agent trust levels (no trustScore)', () => {
    it('denies unknown agents when a minimum trust is configured', () => {
      const gw = createGateway({ requireMinimumTrust: 0.1 });
      const req = makeRequest({ trustScore: undefined, agentId: 'unknown-agent' });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Trust score 0 below minimum');
    });

    it('allows unknown agents when no minimum trust is required', () => {
      const gw = createGateway({ requireMinimumTrust: 0 });
      const req = makeRequest({ trustScore: undefined, agentId: 'unknown-agent' });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
    });

    it('denies unknown agents with zero trust score when minimum is positive', () => {
      const gw = createGateway({ requireMinimumTrust: 0.01 });
      const req = makeRequest({ trustScore: 0, agentId: 'zero-trust-agent' });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
    });
  });

  describe('resource access control', () => {
    it('denies access to a blocked resource', () => {
      const gw = createGateway({
        allowedResources: ['*'],
        blockedResources: ['/secrets'],
      });
      const req = makeRequest({ resource: '/secrets' });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Resource /secrets is not allowed');
      expect(res.appliedRules).toContain('resource-access');
    });

    it('allows access to a non-blocked resource', () => {
      const gw = createGateway({
        allowedResources: ['*'],
        blockedResources: ['/secrets'],
      });
      const req = makeRequest({ resource: '/data' });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
    });

    it('denies when resource is not in allowed list', () => {
      const gw = createGateway({ allowedResources: ['/api'] });
      const req = makeRequest({ resource: '/admin' });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Resource /admin is not allowed');
    });
  });

  describe('rule application order', () => {
    it('applies all four rules for a fully-passing request', () => {
      const gw = createGateway({ requireMinimumTrust: 0.5 });
      const req = makeRequest({ trustScore: 0.9 });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
      expect(res.appliedRules).toEqual([
        'identity-required',
        'covenant-required',
        'trust-score-minimum',
        'resource-access',
      ]);
    });

    it('stops at identity check when identity fails', () => {
      const gw = createGateway({ requireMinimumTrust: 0.5 });
      const req = makeRequest({ hasIdentity: false });
      const res = processRequest(gw, req);
      expect(res.appliedRules).toEqual(['identity-required']);
    });

    it('stops at covenant check when covenant fails', () => {
      const gw = createGateway({ requireMinimumTrust: 0.5 });
      const req = makeRequest({ hasCovenant: false });
      const res = processRequest(gw, req);
      expect(res.appliedRules).toEqual(['identity-required', 'covenant-required']);
    });

    it('stops at trust check when trust score fails', () => {
      const gw = createGateway({ requireMinimumTrust: 0.99 });
      const req = makeRequest({ trustScore: 0.1 });
      const res = processRequest(gw, req);
      expect(res.appliedRules).toEqual([
        'identity-required',
        'covenant-required',
        'trust-score-minimum',
      ]);
    });
  });

  describe('response metadata', () => {
    it('generates unique request IDs for each call', () => {
      const gw = createGateway();
      const req = makeRequest();
      const res1 = processRequest(gw, req);
      const res2 = processRequest(gw, req);
      expect(res1.requestId).not.toBe(res2.requestId);
    });

    it('request ID follows the expected format', () => {
      const gw = createGateway();
      const req = makeRequest();
      const res = processRequest(gw, req);
      expect(res.requestId).toMatch(/^gw-\d+-\d+$/);
    });

    it('latencyMs is a non-negative number', () => {
      const gw = createGateway();
      const req = makeRequest({ timestamp: Date.now() });
      const res = processRequest(gw, req);
      expect(res.latencyMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('rate limiting simulation with multiple requests', () => {
    it('processes multiple sequential requests from the same agent', () => {
      const gw = createGateway({ rateLimitPerMinute: 2 });
      const responses: GatewayResponse[] = [];
      for (let i = 0; i < 5; i++) {
        const req = makeRequest({ agentId: 'agent-rapid' });
        responses.push(processRequest(gw, req));
      }
      // Note: the current implementation does not track state between calls,
      // so all requests pass. This verifies no crash occurs under rapid calls.
      expect(responses).toHaveLength(5);
      for (const res of responses) {
        expect(res.allowed).toBe(true);
        expect(res.requestId).toBeTruthy();
      }
    });

    it('all requests get distinct request IDs even in rapid succession', () => {
      const gw = createGateway();
      const ids = new Set<string>();
      for (let i = 0; i < 20; i++) {
        const req = makeRequest();
        const res = processRequest(gw, req);
        ids.add(res.requestId);
      }
      expect(ids.size).toBe(20);
    });
  });

  describe('combined edge cases', () => {
    it('denies when all checks fail (identity is checked first)', () => {
      const gw = createGateway({
        requireIdentity: true,
        requireCovenant: true,
        requireMinimumTrust: 0.9,
        blockedResources: ['/data'],
      });
      const req = makeRequest({
        hasIdentity: false,
        hasCovenant: false,
        trustScore: 0,
        resource: '/data',
      });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
      // Should stop at identity
      expect(res.reason).toContain('Identity');
    });

    it('gateway with all checks disabled allows any request', () => {
      const gw = createGateway({
        requireIdentity: false,
        requireCovenant: false,
        requireMinimumTrust: 0,
        allowedResources: ['*'],
        blockedResources: [],
      });
      const req = makeRequest({
        hasIdentity: false,
        hasCovenant: false,
        trustScore: undefined,
      });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
      expect(res.reason).toBe('All gateway checks passed');
    });

    it('allows request with empty resource when wildcard is active', () => {
      const gw = createGateway({ allowedResources: ['*'] });
      const req = makeRequest({ resource: '' });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(true);
    });

    it('denies request with empty resource when blocked', () => {
      const gw = createGateway({
        allowedResources: ['*'],
        blockedResources: [''],
      });
      const req = makeRequest({ resource: '' });
      const res = processRequest(gw, req);
      expect(res.allowed).toBe(false);
    });
  });
});

// ---------------------------------------------------------------------------
// aggregateMetrics
// ---------------------------------------------------------------------------

describe('aggregateMetrics', () => {
  it('returns zeroes for an empty response array', () => {
    const metrics = aggregateMetrics([]);
    expect(metrics.totalRequests).toBe(0);
    expect(metrics.allowedRequests).toBe(0);
    expect(metrics.deniedRequests).toBe(0);
    expect(metrics.averageLatencyMs).toBe(0);
    expect(metrics.topDenialReasons).toEqual({});
  });

  it('counts allowed and denied requests correctly', () => {
    const responses: GatewayResponse[] = [
      { allowed: true, reason: 'ok', requestId: 'r1', latencyMs: 10, appliedRules: [] },
      { allowed: false, reason: 'no identity', requestId: 'r2', latencyMs: 5, appliedRules: [] },
      { allowed: true, reason: 'ok', requestId: 'r3', latencyMs: 8, appliedRules: [] },
      { allowed: false, reason: 'no identity', requestId: 'r4', latencyMs: 3, appliedRules: [] },
      { allowed: false, reason: 'blocked', requestId: 'r5', latencyMs: 2, appliedRules: [] },
    ];
    const metrics = aggregateMetrics(responses);
    expect(metrics.totalRequests).toBe(5);
    expect(metrics.allowedRequests).toBe(2);
    expect(metrics.deniedRequests).toBe(3);
  });

  it('computes average latency correctly', () => {
    const responses: GatewayResponse[] = [
      { allowed: true, reason: 'ok', requestId: 'r1', latencyMs: 10, appliedRules: [] },
      { allowed: true, reason: 'ok', requestId: 'r2', latencyMs: 20, appliedRules: [] },
      { allowed: true, reason: 'ok', requestId: 'r3', latencyMs: 30, appliedRules: [] },
    ];
    const metrics = aggregateMetrics(responses);
    expect(metrics.averageLatencyMs).toBe(20);
  });

  it('groups denial reasons correctly', () => {
    const responses: GatewayResponse[] = [
      { allowed: false, reason: 'no identity', requestId: 'r1', latencyMs: 1, appliedRules: [] },
      { allowed: false, reason: 'no identity', requestId: 'r2', latencyMs: 1, appliedRules: [] },
      { allowed: false, reason: 'blocked', requestId: 'r3', latencyMs: 1, appliedRules: [] },
      { allowed: true, reason: 'ok', requestId: 'r4', latencyMs: 1, appliedRules: [] },
    ];
    const metrics = aggregateMetrics(responses);
    expect(metrics.topDenialReasons).toEqual({
      'no identity': 2,
      'blocked': 1,
    });
  });

  it('does not count allowed responses in denial reasons', () => {
    const responses: GatewayResponse[] = [
      { allowed: true, reason: 'All gateway checks passed', requestId: 'r1', latencyMs: 1, appliedRules: [] },
      { allowed: true, reason: 'All gateway checks passed', requestId: 'r2', latencyMs: 1, appliedRules: [] },
    ];
    const metrics = aggregateMetrics(responses);
    expect(metrics.topDenialReasons).toEqual({});
    expect(metrics.deniedRequests).toBe(0);
  });

  it('handles all-denied scenario', () => {
    const gw = createGateway({ requireIdentity: true });
    const responses: GatewayResponse[] = [];
    for (let i = 0; i < 3; i++) {
      responses.push(processRequest(gw, makeRequest({ hasIdentity: false })));
    }
    const metrics = aggregateMetrics(responses);
    expect(metrics.totalRequests).toBe(3);
    expect(metrics.allowedRequests).toBe(0);
    expect(metrics.deniedRequests).toBe(3);
    expect(metrics.topDenialReasons['Identity verification required but not provided']).toBe(3);
  });

  it('integrates end-to-end: process requests then aggregate', () => {
    const gw = createGateway({
      requireMinimumTrust: 0.5,
      allowedResources: ['*'],
      blockedResources: ['/secrets'],
    });

    const responses: GatewayResponse[] = [
      // Allowed: good trust, good resource
      processRequest(gw, makeRequest({ trustScore: 0.9, resource: '/data' })),
      // Denied: low trust
      processRequest(gw, makeRequest({ trustScore: 0.2, resource: '/data' })),
      // Denied: blocked resource
      processRequest(gw, makeRequest({ trustScore: 0.9, resource: '/secrets' })),
      // Allowed: good trust, good resource
      processRequest(gw, makeRequest({ trustScore: 0.7, resource: '/api' })),
    ];

    const metrics = aggregateMetrics(responses);
    expect(metrics.totalRequests).toBe(4);
    expect(metrics.allowedRequests).toBe(2);
    expect(metrics.deniedRequests).toBe(2);
    expect(Object.keys(metrics.topDenialReasons)).toHaveLength(2);
  });
});
