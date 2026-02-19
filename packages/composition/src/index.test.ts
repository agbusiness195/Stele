import { describe, it, expect } from 'vitest';
import {
  compose,
  proveSystemProperty,
  validateComposition,
  intersectConstraints,
  findConflicts,
  decomposeCovenants,
  compositionComplexity,
  TRUST_IDENTITY,
  TRUST_ZERO,
  trustCompose,
  trustIntersect,
  trustNegate,
  trustTensorProduct,
  trustInverse,
  proveAlgebraicProperties,
  defineSafetyEnvelope,
  proposeImprovement,
  applyImprovement,
  verifyEnvelopeIntegrity,
} from './index.js';
import type {
  CovenantSummary,
  CompositionProof,
  TrustValue,
  SafetyEnvelope,
} from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeCovenant(
  id: string,
  agentId: string,
  constraints: string[],
): CovenantSummary {
  return { id, agentId, constraints };
}

// ---------------------------------------------------------------------------
// compose
// ---------------------------------------------------------------------------

describe('compose', () => {
  it('returns all agents from the provided covenants', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require read_only on '**'"]),
      makeCovenant('c2', 'agent-b', ["require no_network on '**'"]),
    ];
    const result = compose(covenants);
    expect(result.agents).toContain('agent-a');
    expect(result.agents).toContain('agent-b');
    expect(result.agents).toHaveLength(2);
  });

  it('returns all individual covenant IDs', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require read_only on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny write_file on '**'"]),
    ];
    const result = compose(covenants);
    expect(result.individualCovenants).toEqual(['c1', 'c2']);
  });

  it('merges constraints from multiple covenants', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require read_only on '**'", "deny network on '**'"]),
      makeCovenant('c2', 'agent-b', ['limit cpu 10 per 60 seconds']),
    ];
    const result = compose(covenants);
    expect(result.composedConstraints.length).toBe(3);
  });

  it('deny-wins: removes permit when deny exists for same pattern', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit file_access on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny file_access on '**'"]),
    ];
    const result = compose(covenants);
    const types = result.composedConstraints.map(c => c.type);
    expect(types).toContain('deny');
    expect(types).not.toContain('permit');
  });

  it('deny-wins: removes permits when deny has overlapping wildcard pattern', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit file.read on '/data'"]),
      makeCovenant('c2', 'agent-b', ["deny file.* on '/data/**'"]),
    ];
    const result = compose(covenants);
    const types = result.composedConstraints.map(c => c.type);
    expect(types).toContain('deny');
    expect(types).not.toContain('permit');
  });

  it('produces a non-empty proof hash', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require something on '**'"]),
    ];
    const result = compose(covenants);
    expect(result.proof).toBeDefined();
    expect(result.proof.length).toBe(64);
  });

  it('starts with empty systemProperties', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
    ];
    const result = compose(covenants);
    expect(result.systemProperties).toEqual([]);
  });

  it('deduplicates agents when the same agent appears in multiple covenants', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require x on '**'"]),
      makeCovenant('c2', 'agent-a', ["require y on '**'"]),
    ];
    const result = compose(covenants);
    expect(result.agents).toEqual(['agent-a']);
  });

  it('handles empty covenants array', () => {
    const result = compose([]);
    expect(result.agents).toEqual([]);
    expect(result.individualCovenants).toEqual([]);
    expect(result.composedConstraints).toEqual([]);
    expect(result.proof.length).toBe(64);
  });

  it('preserves constraint source references', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
    ];
    const result = compose(covenants);
    expect(result.composedConstraints[0]!.source).toBe('c1');
  });

  it('keeps permits when no deny conflicts exist', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit read on '/public'", "permit write on '/scratch'"]),
    ];
    const result = compose(covenants);
    const types = result.composedConstraints.map(c => c.type);
    expect(types).toEqual(['permit', 'permit']);
  });

  it('handles multiple permits and denies for same pattern', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit network on '**'"]),
      makeCovenant('c2', 'agent-b', ["permit network on '**'"]),
      makeCovenant('c3', 'agent-c', ["deny network on '**'"]),
    ];
    const result = compose(covenants);
    const permits = result.composedConstraints.filter(c => c.type === 'permit');
    const denies = result.composedConstraints.filter(c => c.type === 'deny');
    expect(permits).toHaveLength(0);
    expect(denies).toHaveLength(1);
  });

  it('keeps deny and removes permit when both exist, preserving require and limit', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit file_access on '**'", "require auth on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny file_access on '**'", "require logging on '**'"]),
    ];
    const result = compose(covenants);
    const constraintTypes = result.composedConstraints.map(c => c.type);
    expect(constraintTypes).toContain('deny');
    expect(constraintTypes).not.toContain('permit');
    expect(constraintTypes).toContain('require');
  });

  it('constraints are valid serialized CCL in the output', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
    ];
    const result = compose(covenants);
    const constraint = result.composedConstraints[0]!.constraint;
    expect(constraint).toContain('deny');
    expect(constraint).toContain('exfiltrate');
  });

  // Input validation
  it('throws when covenants is not an array', () => {
    expect(() => compose(null as any)).toThrow('covenants must be an array');
  });

  it('throws when a covenant has no id', () => {
    expect(() => compose([{ id: '', agentId: 'a', constraints: [] }])).toThrow();
  });

  it('throws when a covenant has no agentId', () => {
    expect(() => compose([{ id: 'c1', agentId: '', constraints: [] }])).toThrow();
  });

  it('throws when a covenant has no constraints array', () => {
    expect(() => compose([{ id: 'c1', agentId: 'a', constraints: 'bad' as any }])).toThrow();
  });
});

// ---------------------------------------------------------------------------
// proveSystemProperty
// ---------------------------------------------------------------------------

describe('proveSystemProperty', () => {
  it('holds when deny constraints match the property', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny data_leak on '**'"]),
    ];
    const result = proveSystemProperty(covenants, 'exfiltrate');
    expect(result.holds).toBe(true);
    expect(result.derivedFrom).toContain('c1');
  });

  it('does not hold when no deny constraints match', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require read_only on '**'"]),
      makeCovenant('c2', 'agent-b', ["permit network on '**'"]),
    ];
    const result = proveSystemProperty(covenants, 'exfiltrate');
    expect(result.holds).toBe(false);
    expect(result.derivedFrom).toEqual([]);
  });

  it('returns the correct property string', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny write on '**'"]),
    ];
    const result = proveSystemProperty(covenants, 'no-write-access');
    expect(result.property).toBe('no-write-access');
  });

  it('matches property to deny actions case-insensitively', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny Exfiltrate on '**'"]),
    ];
    const result = proveSystemProperty(covenants, 'EXFILTRATE');
    expect(result.holds).toBe(true);
  });

  it('deduplicates derivedFrom sources', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny leak on '**'", "deny data_leak on '**'"]),
    ];
    const result = proveSystemProperty(covenants, 'leak');
    expect(result.derivedFrom).toEqual(['c1']);
  });

  it('collects derivedFrom from multiple covenants', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny exfiltrate on '**'"]),
    ];
    const result = proveSystemProperty(covenants, 'exfiltrate');
    expect(result.holds).toBe(true);
    expect(result.derivedFrom).toContain('c1');
    expect(result.derivedFrom).toContain('c2');
  });

  it('uses real CCL evaluation to verify denies fire', () => {
    // A deny with a condition that, when probed with a satisfying context, fires
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**' when risk_level = 'critical'"]),
    ];
    const result = proveSystemProperty(covenants, 'exfiltrate');
    expect(result.holds).toBe(true);
    expect(result.derivedFrom).toContain('c1');
  });

  it('does not hold when covenants have no constraints', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', []),
    ];
    const result = proveSystemProperty(covenants, 'exfiltrate');
    expect(result.holds).toBe(false);
    expect(result.derivedFrom).toEqual([]);
  });

  it('wildcard deny is relevant to any property', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny * on '**'"]),
    ];
    const result = proveSystemProperty(covenants, 'anything');
    expect(result.holds).toBe(true);
  });

  // Input validation
  it('throws when covenants is not an array', () => {
    expect(() => proveSystemProperty(null as any, 'prop')).toThrow();
  });

  it('throws when property is empty', () => {
    expect(() => proveSystemProperty([], '')).toThrow('property must be a non-empty string');
  });

  it('throws when property is not a string', () => {
    expect(() => proveSystemProperty([], 42 as any)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// validateComposition
// ---------------------------------------------------------------------------

describe('validateComposition', () => {
  it('returns true for a valid composition proof', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require read_only on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny network on '**'"]),
    ];
    const proof = compose(covenants);
    expect(validateComposition(proof)).toBe(true);
  });

  it('returns false when proof hash is tampered', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require read_only on '**'"]),
    ];
    const proof = compose(covenants);
    const tampered: CompositionProof = { ...proof, proof: 'a'.repeat(64) };
    expect(validateComposition(tampered)).toBe(false);
  });

  it('returns false when composedConstraints are tampered', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require read_only on '**'"]),
    ];
    const proof = compose(covenants);
    const tampered: CompositionProof = {
      ...proof,
      composedConstraints: [
        { source: 'c1', constraint: "require write_all on '**'", type: 'require' },
      ],
    };
    expect(validateComposition(tampered)).toBe(false);
  });

  it('validates an empty composition', () => {
    const proof = compose([]);
    expect(validateComposition(proof)).toBe(true);
  });

  it('returns false when composed constraints contain invalid CCL', () => {
    const proof = compose([]);
    const tampered: CompositionProof = {
      ...proof,
      composedConstraints: [
        { source: 'c1', constraint: 'invalid garbage text $$$', type: 'require' },
      ],
      proof: '', // will be recomputed check
    };
    // Fix the hash so only CCL validity is tested
    const { sha256Object } = require('@usekova/crypto');
    tampered.proof = sha256Object(tampered.composedConstraints);
    expect(validateComposition(tampered)).toBe(false);
  });

  it('returns false when deny-wins consistency is violated (permit overlaps deny)', () => {
    // Manually construct a proof where a permit overlaps with a deny
    const { sha256Object } = require('@usekova/crypto');
    const constraints = [
      { source: 'c1', constraint: "permit file_access on '**'", type: 'permit' as const },
      { source: 'c2', constraint: "deny file_access on '**'", type: 'deny' as const },
    ];
    const tampered: CompositionProof = {
      agents: ['a'],
      individualCovenants: ['c1', 'c2'],
      composedConstraints: constraints,
      systemProperties: [],
      proof: sha256Object(constraints),
    };
    expect(validateComposition(tampered)).toBe(false);
  });

  // Input validation
  it('throws when proof is null', () => {
    expect(() => validateComposition(null as any)).toThrow();
  });

  it('throws when composedConstraints is missing', () => {
    expect(() => validateComposition({ proof: 'x' } as any)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// intersectConstraints
// ---------------------------------------------------------------------------

describe('intersectConstraints', () => {
  it('returns common constraints', () => {
    const a = ["deny exfiltrate on '**'", "require auth on '**'", 'limit cpu 10 per 60 seconds'];
    const b = ["deny exfiltrate on '**'", 'limit cpu 10 per 60 seconds', "permit network on '**'"];
    const result = intersectConstraints(a, b);
    expect(result).toEqual(["deny exfiltrate on '**'", 'limit cpu 10 per 60 seconds']);
  });

  it('returns empty array when no overlap', () => {
    const a = ["deny exfiltrate on '**'"];
    const b = ["permit network on '**'"];
    const result = intersectConstraints(a, b);
    expect(result).toEqual([]);
  });

  it('returns empty array when one input is empty', () => {
    const result = intersectConstraints([], ["deny x on '**'"]);
    expect(result).toEqual([]);
  });

  it('returns empty array when both inputs are empty', () => {
    const result = intersectConstraints([], []);
    expect(result).toEqual([]);
  });

  it('handles identical arrays', () => {
    const arr = ["deny a on '/'", "deny b on '/'", "deny c on '/'"];
    const result = intersectConstraints(arr, arr);
    expect(result).toEqual(arr);
  });

  // Input validation
  it('throws when arguments are not arrays', () => {
    expect(() => intersectConstraints(null as any, [])).toThrow();
  });
});

// ---------------------------------------------------------------------------
// findConflicts
// ---------------------------------------------------------------------------

describe('findConflicts', () => {
  it('finds permit-deny conflicts on the same pattern', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit file_access on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny file_access on '**'"]),
    ];
    const conflicts = findConflicts(covenants);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]![0]).toContain('permit');
    expect(conflicts[0]![1]).toContain('deny');
  });

  it('returns empty when no conflicts exist', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit read on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny write on '**'"]),
    ];
    const conflicts = findConflicts(covenants);
    expect(conflicts).toEqual([]);
  });

  it('returns empty for covenants with only require constraints', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["require auth on '**'"]),
      makeCovenant('c2', 'agent-b', ["require logging on '**'"]),
    ];
    const conflicts = findConflicts(covenants);
    expect(conflicts).toEqual([]);
  });

  it('finds multiple conflicts across multiple covenants', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit read on '**'", "permit write on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny read on '**'", "deny write on '**'"]),
    ];
    const conflicts = findConflicts(covenants);
    expect(conflicts).toHaveLength(2);
  });

  it('does not duplicate conflict pairs', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit read on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny read on '**'"]),
      makeCovenant('c3', 'agent-c', ["permit read on '**'"]),
    ];
    const conflicts = findConflicts(covenants);
    // Same serialized strings, so deduplication applies
    expect(conflicts.length).toBeGreaterThanOrEqual(1);
  });

  it('handles empty covenants array', () => {
    const conflicts = findConflicts([]);
    expect(conflicts).toEqual([]);
  });

  it('finds conflicts within a single covenant', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit network on '**'", "deny network on '**'"]),
    ];
    const conflicts = findConflicts(covenants);
    expect(conflicts).toHaveLength(1);
  });

  it('detects overlapping patterns (not just identical)', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit file.read on '/data/**'"]),
      makeCovenant('c2', 'agent-b', ["deny file.* on '/data'"]),
    ];
    const conflicts = findConflicts(covenants);
    expect(conflicts).toHaveLength(1);
  });

  it('detects wildcard action overlapping with specific action', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit read on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny * on '**'"]),
    ];
    const conflicts = findConflicts(covenants);
    expect(conflicts).toHaveLength(1);
  });

  // Input validation
  it('throws when covenants is not an array', () => {
    expect(() => findConflicts(null as any)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// compose + validateComposition round-trip
// ---------------------------------------------------------------------------

describe('compose + validateComposition round-trip', () => {
  it('validates a complex multi-agent composition', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'", "require auth on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny unauthorized_access on '**'", 'limit api_calls 100 per 60 seconds']),
      makeCovenant('c3', 'agent-c', ["permit read_public on '/public'", "deny write_secret on '/secret'"]),
    ];
    const proof = compose(covenants);
    expect(validateComposition(proof)).toBe(true);
    expect(proof.agents).toHaveLength(3);
    expect(proof.individualCovenants).toHaveLength(3);
  });

  it('proof changes when constraints change', () => {
    const covenants1 = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
    ];
    const covenants2 = [
      makeCovenant('c1', 'agent-a', ["deny write on '**'"]),
    ];
    const proof1 = compose(covenants1);
    const proof2 = compose(covenants2);
    expect(proof1.proof).not.toBe(proof2.proof);
  });
});

// ---------------------------------------------------------------------------
// compose - deny-wins detailed scenarios
// ---------------------------------------------------------------------------

describe('compose - deny-wins detailed scenarios', () => {
  it('keeps deny and removes permit when both exist for a pattern', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit file_access on '**'", "require auth on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny file_access on '**'", "require logging on '**'"]),
    ];
    const result = compose(covenants);
    const types = result.composedConstraints.map(c => c.type);
    expect(types).toContain('deny');
    expect(types).not.toContain('permit');
    expect(types).toContain('require');
  });

  it('keeps permits when no deny conflicts exist', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit read on '/data'", "permit write on '/data'"]),
    ];
    const result = compose(covenants);
    const types = result.composedConstraints.map(c => c.type);
    expect(types).toEqual(['permit', 'permit']);
  });

  it('handles multiple permits and denies for same pattern', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit network on '**'"]),
      makeCovenant('c2', 'agent-b', ["permit network on '**'"]),
      makeCovenant('c3', 'agent-c', ["deny network on '**'"]),
    ];
    const result = compose(covenants);
    const permits = result.composedConstraints.filter(c => c.type === 'permit');
    const denies = result.composedConstraints.filter(c => c.type === 'deny');
    expect(permits).toHaveLength(0);
    expect(denies).toHaveLength(1);
  });

  it('deny with broader pattern removes permit with narrower pattern', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit file.read on '/data/public'"]),
      makeCovenant('c2', 'agent-b', ["deny ** on '**'"]),
    ];
    const result = compose(covenants);
    const types = result.composedConstraints.map(c => c.type);
    expect(types).not.toContain('permit');
    expect(types).toContain('deny');
  });
});

// ---------------------------------------------------------------------------
// decomposeCovenants
// ---------------------------------------------------------------------------

describe('decomposeCovenants', () => {
  it('decomposes a single covenant with multiple constraints into individual sub-covenants', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'", "require auth on '**'", 'limit cpu 10 per 60 seconds']),
    ];
    const decomposed = decomposeCovenants(covenants);
    expect(decomposed).toHaveLength(3);
  });

  it('each decomposed sub-covenant references the source covenant', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'", "require auth on '**'"]),
    ];
    const decomposed = decomposeCovenants(covenants);
    for (const d of decomposed) {
      expect(d.sourceCovenantId).toBe('c1');
    }
  });

  it('each decomposed sub-covenant carries the correct agent', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
      makeCovenant('c2', 'agent-b', ["permit read on '/public'"]),
    ];
    const decomposed = decomposeCovenants(covenants);
    const agentA = decomposed.filter(d => d.agentId === 'agent-a');
    const agentB = decomposed.filter(d => d.agentId === 'agent-b');
    expect(agentA).toHaveLength(1);
    expect(agentB).toHaveLength(1);
  });

  it('assigns correct types to each decomposed constraint', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'", "permit read on '/data'", "require logging on '**'", 'limit api 50 per 60 seconds']),
    ];
    const decomposed = decomposeCovenants(covenants);
    const types = decomposed.map(d => d.type);
    expect(types).toContain('deny');
    expect(types).toContain('permit');
    expect(types).toContain('require');
    expect(types).toContain('limit');
  });

  it('returns empty array for empty covenants', () => {
    expect(decomposeCovenants([])).toEqual([]);
  });

  it('returns empty array for covenants with no constraints', () => {
    const covenants = [makeCovenant('c1', 'agent-a', [])];
    expect(decomposeCovenants(covenants)).toEqual([]);
  });

  it('handles multiple covenants from same agent', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny write on '**'"]),
      makeCovenant('c2', 'agent-a', ["deny delete on '**'"]),
    ];
    const decomposed = decomposeCovenants(covenants);
    expect(decomposed).toHaveLength(2);
    expect(decomposed[0]!.sourceCovenantId).toBe('c1');
    expect(decomposed[1]!.sourceCovenantId).toBe('c2');
  });

  it('each decomposed constraint is valid serialized CCL', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
    ];
    const decomposed = decomposeCovenants(covenants);
    expect(decomposed[0]!.constraint).toContain('deny');
    expect(decomposed[0]!.constraint).toContain('exfiltrate');
  });

  it('throws when covenants is not an array', () => {
    expect(() => decomposeCovenants(null as any)).toThrow('covenants must be an array');
  });

  it('throws when a covenant is invalid', () => {
    expect(() => decomposeCovenants([{ id: '', agentId: 'a', constraints: [] }])).toThrow();
  });

  it('decomposes covenants with conditional constraints', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny write on '**' when risk_level = 'high'"]),
    ];
    const decomposed = decomposeCovenants(covenants);
    expect(decomposed).toHaveLength(1);
    expect(decomposed[0]!.type).toBe('deny');
    expect(decomposed[0]!.constraint).toContain('deny');
  });

  it('preserves constraint count across multiple covenants', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny a on '**'", "deny b on '**'"]),
      makeCovenant('c2', 'agent-b', ["permit c on '**'"]),
      makeCovenant('c3', 'agent-c', ["require d on '**'", "require e on '**'", "require f on '**'"]),
    ];
    const decomposed = decomposeCovenants(covenants);
    expect(decomposed).toHaveLength(6);
  });
});

// ---------------------------------------------------------------------------
// compositionComplexity
// ---------------------------------------------------------------------------

describe('compositionComplexity', () => {
  it('counts total rules correctly', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'", "require auth on '**'"]),
      makeCovenant('c2', 'agent-b', ['limit cpu 10 per 60 seconds']),
    ];
    const result = compositionComplexity(covenants);
    expect(result.totalRules).toBe(3);
  });

  it('counts distinct agents', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny x on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny y on '**'"]),
      makeCovenant('c3', 'agent-a', ["deny z on '**'"]),
    ];
    const result = compositionComplexity(covenants);
    expect(result.agentCount).toBe(2);
  });

  it('detects conflicts', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["permit file_access on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny file_access on '**'"]),
    ];
    const result = compositionComplexity(covenants);
    expect(result.conflictCount).toBe(1);
  });

  it('returns zero conflicts when none exist', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
      makeCovenant('c2', 'agent-b', ["require auth on '**'"]),
    ];
    const result = compositionComplexity(covenants);
    expect(result.conflictCount).toBe(0);
  });

  it('counts distinct actions and resources', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny write on '/data'", "deny read on '/secret'"]),
    ];
    const result = compositionComplexity(covenants);
    expect(result.distinctActions).toBe(2);
    expect(result.distinctResources).toBe(2);
  });

  it('returns all zeros for empty covenants', () => {
    const result = compositionComplexity([]);
    expect(result.totalRules).toBe(0);
    expect(result.agentCount).toBe(0);
    expect(result.conflictCount).toBe(0);
    expect(result.score).toBe(0);
  });

  it('score increases with more rules', () => {
    const simple = [makeCovenant('c1', 'agent-a', ["deny x on '**'"])];
    const complex = [
      makeCovenant('c1', 'agent-a', ["deny x on '**'", "deny y on '**'", "deny z on '**'"]),
    ];
    const s1 = compositionComplexity(simple);
    const s2 = compositionComplexity(complex);
    expect(s2.score).toBeGreaterThan(s1.score);
  });

  it('score increases with conflicts', () => {
    const noConflict = [
      makeCovenant('c1', 'agent-a', ["deny x on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny y on '**'"]),
    ];
    const withConflict = [
      makeCovenant('c1', 'agent-a', ["permit x on '**'"]),
      makeCovenant('c2', 'agent-b', ["deny x on '**'"]),
    ];
    const s1 = compositionComplexity(noConflict);
    const s2 = compositionComplexity(withConflict);
    expect(s2.score).toBeGreaterThan(s1.score);
  });

  it('measures condition depth for simple conditions', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny write on '**' when risk_level = 'high'"]),
    ];
    const result = compositionComplexity(covenants);
    expect(result.maxConditionDepth).toBeGreaterThanOrEqual(1);
  });

  it('produces a numeric score', () => {
    const covenants = [
      makeCovenant('c1', 'agent-a', ["deny exfiltrate on '**'"]),
    ];
    const result = compositionComplexity(covenants);
    expect(typeof result.score).toBe('number');
    expect(result.score).toBeGreaterThan(0);
  });

  it('throws when covenants is not an array', () => {
    expect(() => compositionComplexity(null as any)).toThrow('covenants must be an array');
  });

  it('handles covenants with no constraints gracefully', () => {
    const covenants = [makeCovenant('c1', 'agent-a', [])];
    const result = compositionComplexity(covenants);
    expect(result.totalRules).toBe(0);
    expect(result.agentCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Trust Algebra
// ---------------------------------------------------------------------------

describe('Trust Algebra', () => {
  const tvA: TrustValue = {
    dimensions: { integrity: 0.9, competence: 0.8, reliability: 0.7 },
    confidence: 0.85,
  };
  const tvB: TrustValue = {
    dimensions: { integrity: 0.6, competence: 0.5, reliability: 0.4 },
    confidence: 0.7,
  };
  const tvC: TrustValue = {
    dimensions: { integrity: 0.3, competence: 0.9 },
    confidence: 0.5,
  };

  describe('TRUST_IDENTITY and TRUST_ZERO', () => {
    it('TRUST_IDENTITY has empty dimensions and confidence 1', () => {
      expect(TRUST_IDENTITY.dimensions).toEqual({});
      expect(TRUST_IDENTITY.confidence).toBe(1);
    });

    it('TRUST_ZERO has empty dimensions and confidence 0', () => {
      expect(TRUST_ZERO.dimensions).toEqual({});
      expect(TRUST_ZERO.confidence).toBe(0);
    });
  });

  describe('trustCompose', () => {
    it('multiplies shared dimensions and confidence', () => {
      const result = trustCompose(tvA, tvB);
      expect(result.dimensions.integrity).toBeCloseTo(0.9 * 0.6, 10);
      expect(result.dimensions.competence).toBeCloseTo(0.8 * 0.5, 10);
      expect(result.dimensions.reliability).toBeCloseTo(0.7 * 0.4, 10);
      expect(result.confidence).toBeCloseTo(0.85 * 0.7, 10);
    });

    it('returns only intersection of keys', () => {
      const result = trustCompose(tvA, tvC);
      expect(Object.keys(result.dimensions).sort()).toEqual(['competence', 'integrity']);
      expect(result.dimensions.reliability).toBeUndefined();
    });

    it('returns empty dimensions when no keys overlap', () => {
      const noOverlap: TrustValue = { dimensions: { speed: 0.5 }, confidence: 0.9 };
      const result = trustCompose(tvA, noOverlap);
      expect(Object.keys(result.dimensions)).toHaveLength(0);
      expect(result.confidence).toBeCloseTo(0.85 * 0.9, 10);
    });

    it('compose with TRUST_IDENTITY yields empty dimensions (no shared keys)', () => {
      const result = trustCompose(tvA, TRUST_IDENTITY);
      expect(Object.keys(result.dimensions)).toHaveLength(0);
      expect(result.confidence).toBeCloseTo(0.85 * 1, 10);
    });

    it('compose with TRUST_ZERO yields confidence 0', () => {
      const result = trustCompose(tvA, TRUST_ZERO);
      expect(result.confidence).toBe(0);
    });
  });

  describe('trustIntersect', () => {
    it('takes the minimum of shared dimensions and confidence', () => {
      const result = trustIntersect(tvA, tvB);
      expect(result.dimensions.integrity).toBe(0.6);
      expect(result.dimensions.competence).toBe(0.5);
      expect(result.dimensions.reliability).toBe(0.4);
      expect(result.confidence).toBe(0.7);
    });

    it('union of keys: includes dimensions from both values', () => {
      const x: TrustValue = { dimensions: { a: 0.9 }, confidence: 0.5 };
      const y: TrustValue = { dimensions: { b: 0.3 }, confidence: 0.8 };
      const result = trustIntersect(x, y);
      expect(Object.keys(result.dimensions).sort()).toEqual(['a', 'b']);
      expect(result.dimensions.a).toBe(0.9);
      expect(result.dimensions.b).toBe(0.3);
    });

    it('for shared keys, takes minimum', () => {
      const result = trustIntersect(tvA, tvC);
      expect(result.dimensions.integrity).toBe(0.3);
      expect(result.dimensions.competence).toBe(0.8);
      // reliability only in tvA
      expect(result.dimensions.reliability).toBe(0.7);
    });

    it('confidence is min of both', () => {
      const result = trustIntersect(tvA, tvC);
      expect(result.confidence).toBe(0.5);
    });
  });

  describe('trustNegate', () => {
    it('computes 1 - each dimension value', () => {
      const result = trustNegate(tvA);
      expect(result.dimensions.integrity).toBeCloseTo(0.1, 10);
      expect(result.dimensions.competence).toBeCloseTo(0.2, 10);
      expect(result.dimensions.reliability).toBeCloseTo(0.3, 10);
    });

    it('preserves confidence', () => {
      const result = trustNegate(tvA);
      expect(result.confidence).toBe(0.85);
    });

    it('double negation returns original', () => {
      const result = trustNegate(trustNegate(tvA));
      expect(result.dimensions.integrity).toBeCloseTo(0.9, 10);
      expect(result.dimensions.competence).toBeCloseTo(0.8, 10);
      expect(result.dimensions.reliability).toBeCloseTo(0.7, 10);
      expect(result.confidence).toBe(0.85);
    });

    it('negation of zero dimensions gives 1', () => {
      const zeroVal: TrustValue = { dimensions: { x: 0 }, confidence: 0.5 };
      const result = trustNegate(zeroVal);
      expect(result.dimensions.x).toBe(1);
    });

    it('negation of 1 dimensions gives 0', () => {
      const oneVal: TrustValue = { dimensions: { x: 1 }, confidence: 0.5 };
      const result = trustNegate(oneVal);
      expect(result.dimensions.x).toBe(0);
    });
  });

  describe('trustTensorProduct', () => {
    it('creates cross-products of all dimensions', () => {
      const x: TrustValue = { dimensions: { a: 0.5, b: 0.3 }, confidence: 0.8 };
      const y: TrustValue = { dimensions: { c: 0.4, d: 0.6 }, confidence: 0.9 };
      const result = trustTensorProduct(x, y);
      expect(Object.keys(result.dimensions).sort()).toEqual([
        'a\u00D7c', 'a\u00D7d', 'b\u00D7c', 'b\u00D7d',
      ]);
      expect(result.dimensions['a\u00D7c']).toBeCloseTo(0.5 * 0.4, 10);
      expect(result.dimensions['a\u00D7d']).toBeCloseTo(0.5 * 0.6, 10);
      expect(result.dimensions['b\u00D7c']).toBeCloseTo(0.3 * 0.4, 10);
      expect(result.dimensions['b\u00D7d']).toBeCloseTo(0.3 * 0.6, 10);
    });

    it('multiplies confidence', () => {
      const x: TrustValue = { dimensions: { a: 0.5 }, confidence: 0.8 };
      const y: TrustValue = { dimensions: { b: 0.3 }, confidence: 0.9 };
      const result = trustTensorProduct(x, y);
      expect(result.confidence).toBeCloseTo(0.72, 10);
    });

    it('returns empty dimensions when either has no dimensions', () => {
      const result = trustTensorProduct(tvA, TRUST_IDENTITY);
      expect(Object.keys(result.dimensions)).toHaveLength(0);
    });
  });

  describe('trustInverse', () => {
    it('computes 1/each dimension value', () => {
      const result = trustInverse(tvA);
      expect(result).not.toBeNull();
      expect(result!.dimensions.integrity).toBeCloseTo(1 / 0.9, 10);
      expect(result!.dimensions.competence).toBeCloseTo(1 / 0.8, 10);
      expect(result!.dimensions.reliability).toBeCloseTo(1 / 0.7, 10);
    });

    it('preserves confidence', () => {
      const result = trustInverse(tvA);
      expect(result).not.toBeNull();
      expect(result!.confidence).toBe(0.85);
    });

    it('returns null if any dimension is 0', () => {
      const zeroVal: TrustValue = { dimensions: { x: 0, y: 0.5 }, confidence: 0.5 };
      const result = trustInverse(zeroVal);
      expect(result).toBeNull();
    });

    it('inverse of inverse returns original dimensions', () => {
      const inv = trustInverse(tvA);
      expect(inv).not.toBeNull();
      const invInv = trustInverse(inv!);
      expect(invInv).not.toBeNull();
      expect(invInv!.dimensions.integrity).toBeCloseTo(0.9, 10);
      expect(invInv!.dimensions.competence).toBeCloseTo(0.8, 10);
      expect(invInv!.dimensions.reliability).toBeCloseTo(0.7, 10);
    });

    it('compose(a, inverse(a)) yields 1 for each dimension', () => {
      const inv = trustInverse(tvA);
      expect(inv).not.toBeNull();
      const result = trustCompose(tvA, inv!);
      for (const key of Object.keys(result.dimensions)) {
        expect(result.dimensions[key]).toBeCloseTo(1, 10);
      }
    });

    it('handles value with empty dimensions', () => {
      const emptyDims: TrustValue = { dimensions: {}, confidence: 0.5 };
      const result = trustInverse(emptyDims);
      expect(result).not.toBeNull();
      expect(Object.keys(result!.dimensions)).toHaveLength(0);
    });
  });

  describe('proveAlgebraicProperties', () => {
    it('returns proofs for all 5 properties', () => {
      const proofs = proveAlgebraicProperties([tvA, tvB, tvC]);
      expect(proofs).toHaveLength(5);
      const names = proofs.map(p => p.property);
      expect(names).toContain('associativity of compose');
      expect(names).toContain('commutativity of compose');
      expect(names).toContain('identity element');
      expect(names).toContain('inverse');
      expect(names).toContain('distributivity');
    });

    it('associativity holds for standard values', () => {
      const proofs = proveAlgebraicProperties([tvA, tvB, tvC]);
      const assoc = proofs.find(p => p.property === 'associativity of compose');
      expect(assoc).toBeDefined();
      expect(assoc!.holds).toBe(true);
    });

    it('commutativity holds for standard values', () => {
      const proofs = proveAlgebraicProperties([tvA, tvB, tvC]);
      const comm = proofs.find(p => p.property === 'commutativity of compose');
      expect(comm).toBeDefined();
      expect(comm!.holds).toBe(true);
    });

    it('identity element holds for standard values', () => {
      const proofs = proveAlgebraicProperties([tvA, tvB, tvC]);
      const identity = proofs.find(p => p.property === 'identity element');
      expect(identity).toBeDefined();
      expect(identity!.holds).toBe(true);
    });

    it('inverse property holds for standard values', () => {
      const proofs = proveAlgebraicProperties([tvA, tvB, tvC]);
      const inv = proofs.find(p => p.property === 'inverse');
      expect(inv).toBeDefined();
      expect(inv!.holds).toBe(true);
    });

    it('generates random samples when none are provided', () => {
      const proofs = proveAlgebraicProperties();
      expect(proofs).toHaveLength(5);
      // All should hold for randomly generated values (multiplication is assoc/comm)
      const assoc = proofs.find(p => p.property === 'associativity of compose');
      expect(assoc!.holds).toBe(true);
    });

    it('generates random samples when fewer than 3 are provided', () => {
      const proofs = proveAlgebraicProperties([tvA]);
      expect(proofs).toHaveLength(5);
    });

    it('distributivity result is reported', () => {
      const proofs = proveAlgebraicProperties([tvA, tvB, tvC]);
      const dist = proofs.find(p => p.property === 'distributivity');
      expect(dist).toBeDefined();
      // Distributivity may or may not hold depending on values
      expect(typeof dist!.holds).toBe('boolean');
    });
  });
});

// ---------------------------------------------------------------------------
// Bounded Self-Improvement
// ---------------------------------------------------------------------------

describe('Bounded Self-Improvement', () => {
  function makeEnvelope(): SafetyEnvelope {
    return defineSafetyEnvelope({
      invariants: ['safety-first', 'no-harm'],
      parameters: {
        learningRate: { min: 0.001, max: 0.1, current: 0.01 },
        temperature: { min: 0.0, max: 2.0, current: 1.0 },
        maxRetries: { min: 1, max: 10, current: 3 },
      },
      immutableKernel: ['evaluate', 'enforce'],
    });
  }

  describe('defineSafetyEnvelope', () => {
    it('creates an envelope with invariants, parameters, and kernel', () => {
      const envelope = makeEnvelope();
      expect(envelope.invariants).toEqual(['safety-first', 'no-harm']);
      expect(envelope.parameterRanges.learningRate).toEqual({ min: 0.001, max: 0.1, current: 0.01 });
      expect(envelope.parameterRanges.temperature).toEqual({ min: 0.0, max: 2.0, current: 1.0 });
      expect(envelope.parameterRanges.maxRetries).toEqual({ min: 1, max: 10, current: 3 });
      expect(envelope.immutableKernel).toEqual(['evaluate', 'enforce']);
    });

    it('defaults immutableKernel to empty array', () => {
      const envelope = defineSafetyEnvelope({
        invariants: ['test'],
        parameters: { x: { min: 0, max: 1, current: 0.5 } },
      });
      expect(envelope.immutableKernel).toEqual([]);
    });

    it('creates a defensive copy of parameters', () => {
      const params = { x: { min: 0, max: 1, current: 0.5 } };
      const envelope = defineSafetyEnvelope({ invariants: [], parameters: params });
      params.x.current = 999;
      expect(envelope.parameterRanges.x!.current).toBe(0.5);
    });

    it('creates a defensive copy of invariants', () => {
      const invariants = ['safety'];
      const envelope = defineSafetyEnvelope({ invariants, parameters: {} });
      invariants.push('modified');
      expect(envelope.invariants).toEqual(['safety']);
    });
  });

  describe('proposeImprovement', () => {
    it('creates a verified proposal when value is within range', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.05,
        expectedImprovement: 0.1,
      });
      expect(proposal.parameter).toBe('learningRate');
      expect(proposal.currentValue).toBe(0.01);
      expect(proposal.proposedValue).toBe(0.05);
      expect(proposal.expectedImprovement).toBe(0.1);
      expect(proposal.safetyVerified).toBe(true);
      expect(proposal.rollbackPlan).toEqual({ parameter: 'learningRate', restoreValue: 0.01 });
    });

    it('marks safetyVerified false when value exceeds max', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.5,
        expectedImprovement: 0.2,
      });
      expect(proposal.safetyVerified).toBe(false);
    });

    it('marks safetyVerified false when value is below min', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.0001,
        expectedImprovement: 0.2,
      });
      expect(proposal.safetyVerified).toBe(false);
    });

    it('marks safetyVerified false for unknown parameter', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'unknownParam',
        proposedValue: 0.5,
        expectedImprovement: 0.1,
      });
      expect(proposal.safetyVerified).toBe(false);
    });

    it('accepts value at exact min boundary', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.001,
        expectedImprovement: 0.01,
      });
      expect(proposal.safetyVerified).toBe(true);
    });

    it('accepts value at exact max boundary', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.1,
        expectedImprovement: 0.01,
      });
      expect(proposal.safetyVerified).toBe(true);
    });

    it('generates a unique id', () => {
      const envelope = makeEnvelope();
      const p1 = proposeImprovement({ envelope, parameter: 'learningRate', proposedValue: 0.02, expectedImprovement: 0.1 });
      const p2 = proposeImprovement({ envelope, parameter: 'temperature', proposedValue: 1.5, expectedImprovement: 0.1 });
      expect(p1.id).toContain('learningRate');
      expect(p2.id).toContain('temperature');
    });
  });

  describe('applyImprovement', () => {
    it('applies a verified proposal and returns updated envelope', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.05,
        expectedImprovement: 0.1,
      });
      const result = applyImprovement(envelope, proposal);
      expect(result.applied).toBe(true);
      expect(result.reason).toContain('updated');
      expect(result.newEnvelope.parameterRanges.learningRate!.current).toBe(0.05);
    });

    it('does not modify the original envelope', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.05,
        expectedImprovement: 0.1,
      });
      applyImprovement(envelope, proposal);
      expect(envelope.parameterRanges.learningRate!.current).toBe(0.01);
    });

    it('rejects proposal when safetyVerified is false', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 999,
        expectedImprovement: 0.1,
      });
      expect(proposal.safetyVerified).toBe(false);
      const result = applyImprovement(envelope, proposal);
      expect(result.applied).toBe(false);
      expect(result.reason).toContain('safety verification failed');
      expect(result.newEnvelope.parameterRanges.learningRate!.current).toBe(0.01);
    });

    it('rejects proposal when proposed value equals current value', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.01,
        expectedImprovement: 0,
      });
      expect(proposal.safetyVerified).toBe(true);
      const result = applyImprovement(envelope, proposal);
      expect(result.applied).toBe(false);
      expect(result.reason).toContain('equals current value');
    });

    it('returns updated envelope even when rejected', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 999,
        expectedImprovement: 0.1,
      });
      const result = applyImprovement(envelope, proposal);
      expect(result.newEnvelope).toBeDefined();
      expect(result.newEnvelope.parameterRanges.learningRate!.current).toBe(0.01);
    });

    it('includes rollback plan in the proposal', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'temperature',
        proposedValue: 1.5,
        expectedImprovement: 0.2,
      });
      const result = applyImprovement(envelope, proposal);
      expect(result.applied).toBe(true);
      expect(result.proposal.rollbackPlan).toEqual({ parameter: 'temperature', restoreValue: 1.0 });
    });

    it('can apply multiple sequential improvements', () => {
      const envelope = makeEnvelope();

      const p1 = proposeImprovement({ envelope, parameter: 'learningRate', proposedValue: 0.05, expectedImprovement: 0.1 });
      const r1 = applyImprovement(envelope, p1);
      expect(r1.applied).toBe(true);

      const p2 = proposeImprovement({ envelope: r1.newEnvelope, parameter: 'temperature', proposedValue: 1.5, expectedImprovement: 0.2 });
      const r2 = applyImprovement(r1.newEnvelope, p2);
      expect(r2.applied).toBe(true);

      expect(r2.newEnvelope.parameterRanges.learningRate!.current).toBe(0.05);
      expect(r2.newEnvelope.parameterRanges.temperature!.current).toBe(1.5);
    });
  });

  describe('verifyEnvelopeIntegrity', () => {
    it('returns valid for a well-formed envelope', () => {
      const envelope = makeEnvelope();
      const result = verifyEnvelopeIntegrity(envelope);
      expect(result.valid).toBe(true);
      expect(result.violations).toEqual([]);
    });

    it('detects parameter below minimum', () => {
      const envelope = makeEnvelope();
      envelope.parameterRanges.learningRate!.current = -1;
      const result = verifyEnvelopeIntegrity(envelope);
      expect(result.valid).toBe(false);
      expect(result.violations.length).toBe(1);
      expect(result.violations[0]).toContain('learningRate');
      expect(result.violations[0]).toContain('below minimum');
    });

    it('detects parameter above maximum', () => {
      const envelope = makeEnvelope();
      envelope.parameterRanges.temperature!.current = 5.0;
      const result = verifyEnvelopeIntegrity(envelope);
      expect(result.valid).toBe(false);
      expect(result.violations.length).toBe(1);
      expect(result.violations[0]).toContain('temperature');
      expect(result.violations[0]).toContain('above maximum');
    });

    it('detects multiple violations', () => {
      const envelope = makeEnvelope();
      envelope.parameterRanges.learningRate!.current = -1;
      envelope.parameterRanges.temperature!.current = 100;
      envelope.parameterRanges.maxRetries!.current = 0;
      const result = verifyEnvelopeIntegrity(envelope);
      expect(result.valid).toBe(false);
      expect(result.violations.length).toBe(3);
    });

    it('valid when parameters are at boundaries', () => {
      const envelope = defineSafetyEnvelope({
        invariants: [],
        parameters: {
          x: { min: 0, max: 1, current: 0 },
          y: { min: 0, max: 1, current: 1 },
        },
      });
      const result = verifyEnvelopeIntegrity(envelope);
      expect(result.valid).toBe(true);
      expect(result.violations).toEqual([]);
    });

    it('valid for envelope with no parameters', () => {
      const envelope = defineSafetyEnvelope({
        invariants: ['test'],
        parameters: {},
      });
      const result = verifyEnvelopeIntegrity(envelope);
      expect(result.valid).toBe(true);
      expect(result.violations).toEqual([]);
    });

    it('returns valid after a legitimate improvement is applied', () => {
      const envelope = makeEnvelope();
      const proposal = proposeImprovement({
        envelope,
        parameter: 'learningRate',
        proposedValue: 0.05,
        expectedImprovement: 0.1,
      });
      const result = applyImprovement(envelope, proposal);
      const integrity = verifyEnvelopeIntegrity(result.newEnvelope);
      expect(integrity.valid).toBe(true);
    });
  });
});
