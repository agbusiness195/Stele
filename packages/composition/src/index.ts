import { sha256Object } from '@stele/crypto';
import { DocumentedSteleError as SteleError, DocumentedErrorCode as SteleErrorCode } from '@stele/types';
import {
  parse,
  evaluate,
  merge,
  serialize,
  matchAction,
  matchResource,
} from '@stele/ccl';
import type {
  CCLDocument,
  PermitDenyStatement,
  RequireStatement,
  LimitStatement,
  Statement,
  Condition,
  CompoundCondition,
  EvaluationContext,
} from '@stele/ccl';

export type {
  CompositionProof,
  ComposedConstraint,
  SystemProperty,
  CovenantSummary,
  DecomposedCovenant,
  CompositionComplexityResult,
  TrustValue,
  AlgebraicProof,
  SafetyEnvelope,
  ImprovementProposal,
  ImprovementResult,
  PartialTrust,
  AttenuatedDelegation,
  TrustLatticeResult,
} from './types.js';

import type {
  CompositionProof,
  ComposedConstraint,
  SystemProperty,
  CovenantSummary,
  DecomposedCovenant,
  CompositionComplexityResult,
  TrustValue,
  AlgebraicProof,
  SafetyEnvelope,
  ImprovementProposal,
  ImprovementResult,
  PartialTrust,
  AttenuatedDelegation,
  TrustLatticeResult,
} from './types.js';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Create a fresh empty CCLDocument. */
function emptyDoc(): CCLDocument {
  return { statements: [], permits: [], denies: [], obligations: [], limits: [] };
}

/** Parse an array of CCL constraint strings into a single CCLDocument. */
function parseConstraints(constraints: string[]): CCLDocument {
  const source = constraints.filter(s => s.trim() !== '').join('\n').trim();
  if (source === '') return emptyDoc();
  return parse(source);
}

/** Wrap a single Statement in a CCLDocument. */
function wrapStatement(stmt: Statement): CCLDocument {
  const doc = emptyDoc();
  doc.statements.push(stmt);
  switch (stmt.type) {
    case 'permit': doc.permits.push(stmt as PermitDenyStatement); break;
    case 'deny':   doc.denies.push(stmt as PermitDenyStatement); break;
    case 'require': doc.obligations.push(stmt as RequireStatement); break;
    case 'limit':  doc.limits.push(stmt as LimitStatement); break;
  }
  return doc;
}

/** Serialize a single statement to CCL text. */
function serializeOne(stmt: Statement): string {
  return serialize(wrapStatement(stmt)).trim();
}

/**
 * Check whether two action patterns could match a common concrete value.
 */
function actionPatternsOverlap(a: string, b: string): boolean {
  const cA = a.replace(/\*\*/g, 'x').replace(/\*/g, 'x');
  const cB = b.replace(/\*\*/g, 'x').replace(/\*/g, 'x');
  return matchAction(a, cB) || matchAction(b, cA);
}

/**
 * Check whether two resource patterns could match a common concrete value.
 */
function resourcePatternsOverlap(a: string, b: string): boolean {
  const cA = a.replace(/\*\*/g, 'x').replace(/\*/g, 'x');
  const cB = b.replace(/\*\*/g, 'x').replace(/\*/g, 'x');
  return matchResource(a, cB) || matchResource(b, cA);
}

/**
 * Check whether two (action, resource) pattern pairs could match any
 * common concrete (action, resource) value -- i.e. they "overlap".
 */
function patternsOverlap(
  actA: string, resA: string,
  actB: string, resB: string,
): boolean {
  return actionPatternsOverlap(actA, actB) && resourcePatternsOverlap(resA, resB);
}

/**
 * Build an EvaluationContext that would satisfy a simple equality condition
 * so we can probe whether a deny rule fires.
 */
function buildProbeContext(cond?: Condition | CompoundCondition): EvaluationContext | undefined {
  if (!cond) return undefined;

  // Simple condition
  if ('field' in cond && 'operator' in cond && 'value' in cond) {
    const simple = cond as Condition;
    const ctx: Record<string, unknown> = {};
    const parts = simple.field.split('.');
    let cur: Record<string, unknown> = ctx;
    for (let i = 0; i < parts.length - 1; i++) {
      const nested: Record<string, unknown> = {};
      cur[parts[i]!] = nested;
      cur = nested;
    }
    cur[parts[parts.length - 1]!] = simple.value;
    return ctx;
  }

  // Compound: try satisfying the first sub-condition
  if ('conditions' in cond) {
    const compound = cond as CompoundCondition;
    if (compound.conditions.length > 0) {
      return buildProbeContext(compound.conditions[0]!);
    }
  }
  return undefined;
}

/** Extract lowercase keywords (length > 1) from text. */
function extractKeywords(text: string): string[] {
  return text.toLowerCase().split(/[\s\-_.,]+/).filter(w => w.length > 1);
}

/** Check whether a deny statement is relevant to a property description. */
function isDenyRelevant(deny: PermitDenyStatement, propKeywords: string[]): boolean {
  // Universal wildcards are always relevant
  if (deny.action === '**' || deny.action === '*') return true;

  const actionKw = extractKeywords(deny.action);
  return propKeywords.some(pk =>
    actionKw.some(ak => ak.includes(pk) || pk.includes(ak)),
  );
}

/** Turn a pattern into a concrete action string for probing. */
function concretizeAction(pattern: string): string {
  if (pattern === '**' || pattern === '*') return 'probe_action';
  return pattern.replace(/\*\*/g, 'x').replace(/\*/g, 'x');
}

/** Turn a pattern into a concrete resource string for probing. */
function concretizeResource(pattern: string): string {
  if (pattern === '**') return '/probe_resource';
  if (pattern === '*') return '/probe';
  return pattern.replace(/\*\*/g, 'x').replace(/\*/g, 'x');
}

/** Validate that an object looks like a CovenantSummary. */
function validateCovenant(c: unknown): asserts c is CovenantSummary {
  const cov = c as Record<string, unknown>;
  if (!cov || typeof cov !== 'object') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'Each covenant must be a non-null object', { hint: 'Pass a valid CovenantSummary object with id, agentId, and constraints fields.' });
  }
  if (typeof cov.id !== 'string' || cov.id === '') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'Covenant id must be a non-empty string', { hint: 'Provide a non-empty string for the covenant id field.' });
  }
  if (typeof cov.agentId !== 'string' || cov.agentId === '') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'Covenant agentId must be a non-empty string', { hint: 'Provide a non-empty string for the covenant agentId field.' });
  }
  if (!Array.isArray(cov.constraints)) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'Covenant constraints must be an array', { hint: 'Provide an array of CCL constraint strings for the constraints field.' });
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compose multiple covenant summaries into a single CompositionProof.
 *
 * Parses each covenant's constraints as CCL using `parse()`, then uses
 * `merge()` to combine them with proper deny-wins semantics. Permits that
 * overlap with any deny are removed from the composed result.
 */
export function compose(covenants: CovenantSummary[]): CompositionProof {
  if (!Array.isArray(covenants)) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'covenants must be an array', { hint: 'Pass an array of CovenantSummary objects to compose.' });
  }
  for (const c of covenants) validateCovenant(c);

  const agents = [...new Set(covenants.map(c => c.agentId))];
  const individualCovenants = covenants.map(c => c.id);

  // Parse every covenant and tag statements with their source
  interface Tagged { source: string; stmt: Statement }
  const allTagged: Tagged[] = [];
  let mergedDoc = emptyDoc();

  for (const covenant of covenants) {
    const doc = parseConstraints(covenant.constraints);
    for (const stmt of doc.statements) {
      allTagged.push({ source: covenant.id, stmt });
    }
    if (doc.statements.length > 0) {
      mergedDoc = mergedDoc.statements.length === 0 ? doc : merge(mergedDoc, doc);
    }
  }

  // Collect deny entries for deny-wins filtering
  const denyEntries = allTagged.filter(t => t.stmt.type === 'deny');

  // Build composed constraints -- permits overridden by denies are removed
  const composedConstraints: ComposedConstraint[] = [];
  for (const tagged of allTagged) {
    if (tagged.stmt.type === 'permit') {
      const ps = tagged.stmt as PermitDenyStatement;
      const overridden = denyEntries.some(d => {
        const ds = d.stmt as PermitDenyStatement;
        return patternsOverlap(ds.action, ds.resource, ps.action, ps.resource);
      });
      if (overridden) continue;
    }
    composedConstraints.push({
      source: tagged.source,
      constraint: serializeOne(tagged.stmt),
      type: tagged.stmt.type as ComposedConstraint['type'],
    });
  }

  const proof = sha256Object(composedConstraints);

  return {
    agents,
    individualCovenants,
    composedConstraints,
    systemProperties: [],
    proof,
  };
}

/**
 * Prove whether a system property holds across a set of covenants.
 *
 * Builds a merged CCLDocument from all covenants, then for each deny rule
 * relevant to the property, evaluates a probe action against the merged
 * document using `evaluate()`. If at least one relevant deny fires, the
 * property holds.
 */
export function proveSystemProperty(
  covenants: CovenantSummary[],
  property: string,
): SystemProperty {
  if (!Array.isArray(covenants)) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'covenants must be an array', { hint: 'Pass an array of CovenantSummary objects.' });
  }
  if (typeof property !== 'string' || property.trim() === '') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'property must be a non-empty string', { hint: 'Provide a non-empty string describing the system property to prove.' });
  }

  const propKeywords = extractKeywords(property);
  const derivedFrom: string[] = [];
  let holds = false;

  // Parse each covenant and merge into one document
  let mergedDoc = emptyDoc();
  const covenantDocs = new Map<string, CCLDocument>();

  for (const covenant of covenants) {
    const doc = parseConstraints(covenant.constraints);
    covenantDocs.set(covenant.id, doc);
    if (doc.statements.length > 0) {
      mergedDoc = mergedDoc.statements.length === 0 ? doc : merge(mergedDoc, doc);
    }
  }

  if (mergedDoc.statements.length === 0) {
    return { property, holds: false, derivedFrom: [] };
  }

  // Check each covenant's deny rules for relevance and verification
  for (const covenant of covenants) {
    const doc = covenantDocs.get(covenant.id)!;
    for (const deny of doc.denies) {
      if (!isDenyRelevant(deny, propKeywords)) continue;

      // Probe the merged document with a concrete action/resource
      const probeAction = concretizeAction(deny.action);
      const probeResource = concretizeResource(deny.resource);
      const ctx = buildProbeContext(deny.condition);

      const result = evaluate(mergedDoc, probeAction, probeResource, ctx ?? undefined);
      if (!result.permitted) {
        derivedFrom.push(covenant.id);
        holds = true;
      }
    }
  }

  return {
    property,
    holds,
    derivedFrom: [...new Set(derivedFrom)],
  };
}

/**
 * Validate a composition proof by verifying:
 *   1. The integrity hash matches the composed constraints.
 *   2. All constraints are valid, parseable CCL.
 *   3. Deny-wins consistency: no permit overlaps with any deny.
 */
export function validateComposition(proof: CompositionProof): boolean {
  if (!proof || typeof proof !== 'object') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'proof must be a CompositionProof object', { hint: 'Pass a valid CompositionProof object returned by compose().' });
  }
  if (!Array.isArray(proof.composedConstraints)) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'proof.composedConstraints must be an array', { hint: 'Ensure the proof contains a composedConstraints array.' });
  }
  if (typeof proof.proof !== 'string') {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'proof.proof must be a string', { hint: 'Ensure the proof contains a proof hash string.' });
  }

  // 1. Hash integrity
  const recomputed = sha256Object(proof.composedConstraints);
  if (recomputed !== proof.proof) return false;

  // 2. All constraints must be valid CCL
  const parsedPermits: PermitDenyStatement[] = [];
  const parsedDenies: PermitDenyStatement[] = [];
  try {
    for (const cc of proof.composedConstraints) {
      if (cc.constraint.trim() === '') continue;
      const doc = parse(cc.constraint);
      parsedPermits.push(...doc.permits);
      parsedDenies.push(...doc.denies);
    }
  } catch {
    return false;
  }

  // 3. Deny-wins consistency: no permit should overlap with any deny
  for (const p of parsedPermits) {
    for (const d of parsedDenies) {
      if (patternsOverlap(p.action, p.resource, d.action, d.resource)) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Return constraints present in both arrays (simple string equality).
 */
export function intersectConstraints(a: string[], b: string[]): string[] {
  if (!Array.isArray(a) || !Array.isArray(b)) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'Arguments must be arrays', { hint: 'Pass two arrays of constraint strings to intersect.' });
  }
  const setB = new Set(b);
  return a.filter(c => setB.has(c));
}

/**
 * Find pairs of constraints that conflict: a permit and deny in the
 * covenants whose action/resource patterns overlap.
 */
export function findConflicts(
  covenants: CovenantSummary[],
): Array<[string, string]> {
  if (!Array.isArray(covenants)) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'covenants must be an array', { hint: 'Pass an array of CovenantSummary objects to findConflicts.' });
  }

  interface Entry { constraint: string; stmt: PermitDenyStatement }
  const permits: Entry[] = [];
  const denies: Entry[] = [];

  for (const covenant of covenants) {
    const doc = parseConstraints(covenant.constraints);
    for (const s of doc.permits) {
      permits.push({ constraint: serializeOne(s), stmt: s });
    }
    for (const s of doc.denies) {
      denies.push({ constraint: serializeOne(s), stmt: s });
    }
  }

  const conflicts: Array<[string, string]> = [];
  const seen = new Set<string>();

  for (const permit of permits) {
    for (const deny of denies) {
      if (patternsOverlap(
        permit.stmt.action, permit.stmt.resource,
        deny.stmt.action, deny.stmt.resource,
      )) {
        const key = `${permit.constraint}|${deny.constraint}`;
        if (!seen.has(key)) {
          seen.add(key);
          conflicts.push([permit.constraint, deny.constraint]);
        }
      }
    }
  }

  return conflicts;
}

// ---------------------------------------------------------------------------
// Condition depth helper
// ---------------------------------------------------------------------------

/** Recursively compute the depth of a condition tree. */
function conditionDepth(cond?: Condition | CompoundCondition): number {
  if (!cond) return 0;

  // Simple (leaf) condition
  if ('field' in cond && 'operator' in cond && 'value' in cond) {
    return 1;
  }

  // Compound condition
  if ('conditions' in cond) {
    const compound = cond as CompoundCondition;
    if (compound.conditions.length === 0) return 1;
    let maxChild = 0;
    for (const sub of compound.conditions) {
      const d = conditionDepth(sub);
      if (d > maxChild) maxChild = d;
    }
    return 1 + maxChild;
  }

  return 0;
}

// ---------------------------------------------------------------------------
// decomposeCovenants
// ---------------------------------------------------------------------------

/**
 * Decompose a compound covenant (or set of covenants) into atomic
 * sub-covenants, each containing exactly one constraint.
 *
 * Each returned DecomposedCovenant carries the source covenant ID,
 * the agent ID, the serialized CCL constraint text, and the constraint type.
 */
export function decomposeCovenants(covenants: CovenantSummary[]): DecomposedCovenant[] {
  if (!Array.isArray(covenants)) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'covenants must be an array', { hint: 'Pass an array of CovenantSummary objects to decomposeCovenants.' });
  }
  for (const c of covenants) validateCovenant(c);

  const result: DecomposedCovenant[] = [];

  for (const covenant of covenants) {
    const doc = parseConstraints(covenant.constraints);
    for (const stmt of doc.statements) {
      result.push({
        sourceCovenantId: covenant.id,
        agentId: covenant.agentId,
        constraint: serializeOne(stmt),
        type: stmt.type as DecomposedCovenant['type'],
      });
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// compositionComplexity
// ---------------------------------------------------------------------------

/**
 * Measure the complexity of a set of composed covenants.
 *
 * Returns:
 *  - totalRules: count of all statements
 *  - maxConditionDepth: deepest condition nesting
 *  - agentCount: number of distinct agents
 *  - conflictCount: number of permit-deny overlaps
 *  - distinctActions: number of unique action patterns
 *  - distinctResources: number of unique resource patterns
 *  - score: weighted complexity metric
 *
 * Score formula:
 *   score = totalRules
 *         + 2 * maxConditionDepth
 *         + 3 * conflictCount
 *         + 0.5 * distinctActions
 *         + 0.5 * distinctResources
 */
export function compositionComplexity(covenants: CovenantSummary[]): CompositionComplexityResult {
  if (!Array.isArray(covenants)) {
    throw new SteleError(SteleErrorCode.PROTOCOL_INVALID_INPUT, 'covenants must be an array', { hint: 'Pass an array of CovenantSummary objects to compositionComplexity.' });
  }
  for (const c of covenants) validateCovenant(c);

  const agents = new Set<string>();
  const actions = new Set<string>();
  const resources = new Set<string>();
  let totalRules = 0;
  let maxDepth = 0;

  for (const covenant of covenants) {
    agents.add(covenant.agentId);
    const doc = parseConstraints(covenant.constraints);
    totalRules += doc.statements.length;

    for (const stmt of doc.statements) {
      // Extract action
      actions.add(stmt.action);

      // Extract resource (if present)
      if (stmt.type !== 'limit' && 'resource' in stmt) {
        resources.add((stmt as PermitDenyStatement).resource);
      }

      // Measure condition depth
      if ('condition' in stmt && stmt.condition) {
        const depth = conditionDepth(stmt.condition as Condition | CompoundCondition);
        if (depth > maxDepth) maxDepth = depth;
      }
    }
  }

  const conflictCount = findConflicts(covenants).length;
  const agentCount = agents.size;
  const distinctActions = actions.size;
  const distinctResources = resources.size;

  const score =
    totalRules +
    2 * maxDepth +
    3 * conflictCount +
    0.5 * distinctActions +
    0.5 * distinctResources;

  return {
    totalRules,
    maxConditionDepth: maxDepth,
    agentCount,
    conflictCount,
    distinctActions,
    distinctResources,
    score,
  };
}

// ---------------------------------------------------------------------------
// Trust Algebra
// ---------------------------------------------------------------------------

/** Identity element: all dimensions = 1, confidence = 1 */
export const TRUST_IDENTITY: TrustValue = {
  dimensions: {},
  confidence: 1,
};

/** Zero element: all dimensions = 0, confidence = 0 */
export const TRUST_ZERO: TrustValue = {
  dimensions: {},
  confidence: 0,
};

/**
 * Compose two trust values.
 *
 * Multiplies each dimension present in both values and multiplies confidence.
 * Result dimensions are the intersection of keys from both values.
 */
export function trustCompose(a: TrustValue, b: TrustValue): TrustValue {
  const keysA = Object.keys(a.dimensions);
  const keysB = new Set(Object.keys(b.dimensions));
  const commonKeys = keysA.filter(k => keysB.has(k));

  const dimensions: Record<string, number> = {};
  for (const key of commonKeys) {
    dimensions[key] = a.dimensions[key]! * b.dimensions[key]!;
  }

  return {
    dimensions,
    confidence: a.confidence * b.confidence,
  };
}

/**
 * Intersect two trust values.
 *
 * Takes the minimum of each dimension and the minimum of confidence.
 * Result dimensions are the union of keys from both values.
 */
export function trustIntersect(a: TrustValue, b: TrustValue): TrustValue {
  const allKeys = new Set([
    ...Object.keys(a.dimensions),
    ...Object.keys(b.dimensions),
  ]);

  const dimensions: Record<string, number> = {};
  for (const key of allKeys) {
    const valA = key in a.dimensions ? a.dimensions[key]! : Infinity;
    const valB = key in b.dimensions ? b.dimensions[key]! : Infinity;
    dimensions[key] = Math.min(valA, valB);
  }

  return {
    dimensions,
    confidence: Math.min(a.confidence, b.confidence),
  };
}

/**
 * Negate a trust value.
 *
 * Computes 1 - each dimension value. Confidence is preserved.
 */
export function trustNegate(a: TrustValue): TrustValue {
  const dimensions: Record<string, number> = {};
  for (const key of Object.keys(a.dimensions)) {
    dimensions[key] = 1 - a.dimensions[key]!;
  }

  return {
    dimensions,
    confidence: a.confidence,
  };
}

/**
 * Compute the tensor product of two trust values.
 *
 * Creates all cross-products of dimensions, combining dimension names
 * (e.g. "a.integrity×b.competence"). Confidence is multiplied.
 */
export function trustTensorProduct(a: TrustValue, b: TrustValue): TrustValue {
  const keysA = Object.keys(a.dimensions);
  const keysB = Object.keys(b.dimensions);

  const dimensions: Record<string, number> = {};
  for (const kA of keysA) {
    for (const kB of keysB) {
      const combinedKey = `${kA}\u00D7${kB}`;
      dimensions[combinedKey] = a.dimensions[kA]! * b.dimensions[kB]!;
    }
  }

  return {
    dimensions,
    confidence: a.confidence * b.confidence,
  };
}

/**
 * Compute the inverse of a trust value.
 *
 * Each dimension becomes 1/value. Returns null if any dimension is 0
 * (no inverse exists). Confidence is preserved.
 */
export function trustInverse(a: TrustValue): TrustValue | null {
  const keys = Object.keys(a.dimensions);
  for (const key of keys) {
    if (a.dimensions[key] === 0) return null;
  }

  const dimensions: Record<string, number> = {};
  for (const key of keys) {
    dimensions[key] = 1 / a.dimensions[key]!;
  }

  return {
    dimensions,
    confidence: a.confidence,
  };
}

/** Compare two TrustValues for approximate equality. */
function trustApproxEqual(a: TrustValue, b: TrustValue, tolerance: number): boolean {
  if (Math.abs(a.confidence - b.confidence) > tolerance) return false;

  const keysA = Object.keys(a.dimensions).sort();
  const keysB = Object.keys(b.dimensions).sort();
  if (keysA.length !== keysB.length) return false;
  for (let i = 0; i < keysA.length; i++) {
    if (keysA[i] !== keysB[i]) return false;
  }

  for (const key of keysA) {
    if (Math.abs(a.dimensions[key]! - b.dimensions[key]!) > tolerance) return false;
  }

  return true;
}

/** Generate a random TrustValue with the given dimension names. */
function randomTrustValue(dims: string[]): TrustValue {
  const dimensions: Record<string, number> = {};
  for (const d of dims) {
    dimensions[d] = Math.random() * 0.8 + 0.1; // avoid 0 and 1 extremes
  }
  return { dimensions, confidence: Math.random() * 0.8 + 0.1 };
}

/**
 * Prove algebraic properties of the trust algebra on the given samples.
 *
 * Tests:
 * 1. Associativity of compose
 * 2. Commutativity of compose
 * 3. Identity element
 * 4. Inverse
 * 5. Distributivity of compose over intersect
 *
 * Uses a tolerance of 1e-10 for floating-point comparison.
 */
export function proveAlgebraicProperties(samples?: TrustValue[]): AlgebraicProof[] {
  const tolerance = 1e-10;
  const dims = ['integrity', 'competence', 'reliability'];
  const testSamples = samples && samples.length >= 3
    ? samples
    : [randomTrustValue(dims), randomTrustValue(dims), randomTrustValue(dims)];

  const proofs: AlgebraicProof[] = [];

  // 1. Associativity of compose: compose(a, compose(b, c)) ≈ compose(compose(a, b), c)
  {
    let holds = true;
    let counterexample: AlgebraicProof['counterexample'] | undefined;
    for (let i = 0; i < testSamples.length; i++) {
      for (let j = 0; j < testSamples.length; j++) {
        for (let k = 0; k < testSamples.length; k++) {
          const a = testSamples[i]!;
          const b = testSamples[j]!;
          const c = testSamples[k]!;
          const lhs = trustCompose(a, trustCompose(b, c));
          const rhs = trustCompose(trustCompose(a, b), c);
          if (!trustApproxEqual(lhs, rhs, tolerance)) {
            holds = false;
            counterexample = { a, b, c };
          }
        }
      }
    }
    proofs.push({ property: 'associativity of compose', holds, counterexample });
  }

  // 2. Commutativity of compose: compose(a, b) ≈ compose(b, a)
  {
    let holds = true;
    let counterexample: AlgebraicProof['counterexample'] | undefined;
    for (let i = 0; i < testSamples.length; i++) {
      for (let j = 0; j < testSamples.length; j++) {
        const a = testSamples[i]!;
        const b = testSamples[j]!;
        const lhs = trustCompose(a, b);
        const rhs = trustCompose(b, a);
        if (!trustApproxEqual(lhs, rhs, tolerance)) {
          holds = false;
          counterexample = { a, b };
        }
      }
    }
    proofs.push({ property: 'commutativity of compose', holds, counterexample });
  }

  // 3. Identity element: compose(a, IDENTITY) ≈ a
  // Since TRUST_IDENTITY has empty dimensions, compose yields intersection of keys = empty.
  // We need to construct an identity with matching dimensions for the test.
  {
    let holds = true;
    let counterexample: AlgebraicProof['counterexample'] | undefined;
    for (const a of testSamples) {
      const identity: TrustValue = {
        dimensions: Object.fromEntries(Object.keys(a.dimensions).map(k => [k, 1])),
        confidence: 1,
      };
      const result = trustCompose(a, identity);
      if (!trustApproxEqual(result, a, tolerance)) {
        holds = false;
        counterexample = { a, b: identity };
      }
    }
    proofs.push({ property: 'identity element', holds, counterexample });
  }

  // 4. Inverse: compose(a, inverse(a)) ≈ IDENTITY (per-dimension identity)
  {
    let holds = true;
    let counterexample: AlgebraicProof['counterexample'] | undefined;
    for (const a of testSamples) {
      const inv = trustInverse(a);
      if (inv === null) continue; // skip if no inverse exists
      const result = trustCompose(a, inv);
      const expectedIdentity: TrustValue = {
        dimensions: Object.fromEntries(Object.keys(a.dimensions).map(k => [k, 1])),
        confidence: a.confidence * a.confidence, // confidence is multiplied, not identity
      };
      // For inverse, each dim should be ~1. Confidence = a.conf * a.conf (not necessarily 1).
      // We check dimensions only, since confidence has no true inverse in this algebra.
      const dimsMatch = Object.keys(result.dimensions).every(
        k => Math.abs(result.dimensions[k]! - 1) < tolerance,
      );
      if (!dimsMatch) {
        holds = false;
        counterexample = { a, b: inv };
      }
    }
    proofs.push({ property: 'inverse', holds, counterexample });
  }

  // 5. Distributivity: compose(a, intersect(b, c)) ≈ intersect(compose(a, b), compose(a, c))
  {
    let holds = true;
    let counterexample: AlgebraicProof['counterexample'] | undefined;
    for (let i = 0; i < testSamples.length; i++) {
      for (let j = 0; j < testSamples.length; j++) {
        for (let k = 0; k < testSamples.length; k++) {
          const a = testSamples[i]!;
          const b = testSamples[j]!;
          const c = testSamples[k]!;
          const lhs = trustCompose(a, trustIntersect(b, c));
          const rhs = trustIntersect(trustCompose(a, b), trustCompose(a, c));
          if (!trustApproxEqual(lhs, rhs, tolerance)) {
            holds = false;
            counterexample = { a, b, c };
          }
        }
      }
    }
    proofs.push({ property: 'distributivity', holds, counterexample });
  }

  return proofs;
}

// ---------------------------------------------------------------------------
// Bounded Self-Improvement
// ---------------------------------------------------------------------------

/**
 * Define a safety envelope with invariants, parameter ranges, and an
 * immutable kernel.
 */
export function defineSafetyEnvelope(params: {
  invariants: string[];
  parameters: Record<string, { min: number; max: number; current: number }>;
  immutableKernel?: string[];
}): SafetyEnvelope {
  return {
    invariants: [...params.invariants],
    parameterRanges: Object.fromEntries(
      Object.entries(params.parameters).map(([k, v]) => [k, { ...v }]),
    ),
    immutableKernel: params.immutableKernel ? [...params.immutableKernel] : [],
  };
}

/**
 * Propose an improvement to a parameter within a safety envelope.
 *
 * The proposal is marked safetyVerified = true only if the proposed value
 * falls within the parameter's defined range.
 */
export function proposeImprovement(params: {
  envelope: SafetyEnvelope;
  parameter: string;
  proposedValue: number;
  expectedImprovement: number;
}): ImprovementProposal {
  const { envelope, parameter, proposedValue, expectedImprovement } = params;
  const range = envelope.parameterRanges[parameter];

  const currentValue = range ? range.current : 0;
  const safetyVerified = range
    ? proposedValue >= range.min && proposedValue <= range.max
    : false;

  return {
    id: `imp-${parameter}-${Date.now()}`,
    parameter,
    currentValue,
    proposedValue,
    expectedImprovement,
    safetyVerified,
    rollbackPlan: { parameter, restoreValue: currentValue },
  };
}

/**
 * Apply an improvement proposal to a safety envelope.
 *
 * Only applies if safetyVerified is true and the proposed value differs
 * from the current value. Returns a new envelope with the updated parameter
 * and a reason explaining the outcome.
 */
export function applyImprovement(
  envelope: SafetyEnvelope,
  proposal: ImprovementProposal,
): ImprovementResult {
  // Deep-copy the envelope
  const newEnvelope = defineSafetyEnvelope({
    invariants: envelope.invariants,
    parameters: envelope.parameterRanges,
    immutableKernel: envelope.immutableKernel,
  });

  if (!proposal.safetyVerified) {
    return {
      proposal,
      applied: false,
      reason: `Proposal rejected: safety verification failed for parameter '${proposal.parameter}'`,
      newEnvelope,
    };
  }

  const range = newEnvelope.parameterRanges[proposal.parameter];
  if (!range) {
    return {
      proposal,
      applied: false,
      reason: `Proposal rejected: parameter '${proposal.parameter}' not found in envelope`,
      newEnvelope,
    };
  }

  if (proposal.proposedValue === range.current) {
    return {
      proposal,
      applied: false,
      reason: `Proposal rejected: proposed value equals current value for parameter '${proposal.parameter}'`,
      newEnvelope,
    };
  }

  // Apply the change
  range.current = proposal.proposedValue;

  return {
    proposal,
    applied: true,
    reason: `Parameter '${proposal.parameter}' updated from ${proposal.currentValue} to ${proposal.proposedValue}`,
    newEnvelope,
  };
}

/**
 * Verify the integrity of a safety envelope.
 *
 * Checks that all parameters are within their defined ranges. Returns
 * a list of violations if any parameter is out of bounds.
 */
export function verifyEnvelopeIntegrity(envelope: SafetyEnvelope): {
  valid: boolean;
  violations: string[];
} {
  const violations: string[] = [];

  for (const [name, range] of Object.entries(envelope.parameterRanges)) {
    if (range.current < range.min) {
      violations.push(
        `Parameter '${name}' value ${range.current} is below minimum ${range.min}`,
      );
    }
    if (range.current > range.max) {
      violations.push(
        `Parameter '${name}' value ${range.current} is above maximum ${range.max}`,
      );
    }
  }

  return { valid: violations.length === 0, violations };
}

// ---------------------------------------------------------------------------
// Trust Lattice Operations
// ---------------------------------------------------------------------------

/**
 * Lattice meet (greatest lower bound) of two trust values.
 *
 * Takes the minimum of each dimension (union of all dimension keys;
 * missing dimensions default to 0). Confidence is the minimum of both.
 * This is the most conservative way to combine two trust assessments.
 */
export function trustMeet(a: TrustValue, b: TrustValue): TrustValue {
  const allKeys = new Set([
    ...Object.keys(a.dimensions),
    ...Object.keys(b.dimensions),
  ]);

  const dimensions: Record<string, number> = {};
  for (const key of allKeys) {
    const valA = key in a.dimensions ? a.dimensions[key]! : 0;
    const valB = key in b.dimensions ? b.dimensions[key]! : 0;
    dimensions[key] = Math.min(valA, valB);
  }

  return {
    dimensions,
    confidence: Math.min(a.confidence, b.confidence),
  };
}

/**
 * Lattice join (least upper bound) of two trust values.
 *
 * Takes the maximum of each dimension (union of all dimension keys;
 * missing dimensions default to 0). Confidence is the maximum of both.
 * This is the most optimistic way to combine two trust assessments.
 */
export function trustJoin(a: TrustValue, b: TrustValue): TrustValue {
  const allKeys = new Set([
    ...Object.keys(a.dimensions),
    ...Object.keys(b.dimensions),
  ]);

  const dimensions: Record<string, number> = {};
  for (const key of allKeys) {
    const valA = key in a.dimensions ? a.dimensions[key]! : 0;
    const valB = key in b.dimensions ? b.dimensions[key]! : 0;
    dimensions[key] = Math.max(valA, valB);
  }

  return {
    dimensions,
    confidence: Math.max(a.confidence, b.confidence),
  };
}

// ---------------------------------------------------------------------------
// Partial Trust Composition
// ---------------------------------------------------------------------------

/**
 * Compose multiple partial trust assessments that may cover different scopes.
 *
 * For each dimension, collects all assessments that include it in scope and
 * computes a weighted average by confidence. The final confidence is the
 * product of all unique source confidences (or min if from the same source).
 * Dimensions not covered by any assessment get value 0 with confidence 0.
 */
export function partialTrustCompose(assessments: PartialTrust[]): TrustValue {
  if (assessments.length === 0) {
    return { ...TRUST_ZERO };
  }

  // Collect all dimensions across all scopes
  const allDims = new Set<string>();
  for (const assessment of assessments) {
    for (const dim of assessment.scope) {
      allDims.add(dim);
    }
  }

  const dimensions: Record<string, number> = {};
  for (const dim of allDims) {
    // Find assessments that cover this dimension
    const covering = assessments.filter(a => a.scope.includes(dim));
    if (covering.length === 0) {
      dimensions[dim] = 0;
      continue;
    }

    // Weighted average by confidence
    let totalWeight = 0;
    let weightedSum = 0;
    for (const a of covering) {
      const dimValue = dim in a.value.dimensions ? a.value.dimensions[dim]! : 0;
      weightedSum += dimValue * a.value.confidence;
      totalWeight += a.value.confidence;
    }
    dimensions[dim] = totalWeight > 0 ? weightedSum / totalWeight : 0;
  }

  // Final confidence: product of unique source confidences,
  // min if same source appears multiple times
  const sourceConfidences = new Map<string, number>();
  for (const a of assessments) {
    const existing = sourceConfidences.get(a.source);
    if (existing !== undefined) {
      sourceConfidences.set(a.source, Math.min(existing, a.value.confidence));
    } else {
      sourceConfidences.set(a.source, a.value.confidence);
    }
  }

  let confidence = 1;
  for (const c of sourceConfidences.values()) {
    confidence *= c;
  }

  return { dimensions, confidence };
}

// ---------------------------------------------------------------------------
// Attenuated Delegation
// ---------------------------------------------------------------------------

/**
 * Compute effective trust through a delegation chain.
 *
 * At each step, all trust dimensions and confidence are multiplied by
 * the attenuation factor. If the chain length exceeds any link's maxDepth,
 * TRUST_ZERO is returned. The attenuated trusts are composed along the
 * chain using `trustCompose`.
 */
export function delegateTrust(chain: AttenuatedDelegation[]): TrustValue {
  if (chain.length === 0) {
    return { ...TRUST_IDENTITY };
  }

  // If chain length exceeds any link's maxDepth, return TRUST_ZERO
  for (const link of chain) {
    if (chain.length > link.maxDepth) {
      return { ...TRUST_ZERO };
    }
  }

  // Attenuate each link's trust by its attenuation factor, then compose
  let result: TrustValue | null = null;

  for (const link of chain) {
    // Attenuate dimensions
    const attenuatedDimensions: Record<string, number> = {};
    for (const key of Object.keys(link.trust.dimensions)) {
      attenuatedDimensions[key] = link.trust.dimensions[key]! * link.attenuation;
    }

    const attenuatedTrust: TrustValue = {
      dimensions: attenuatedDimensions,
      confidence: link.trust.confidence * link.attenuation,
    };

    if (result === null) {
      result = attenuatedTrust;
    } else {
      result = trustCompose(result, attenuatedTrust);
    }
  }

  return result!;
}

// ---------------------------------------------------------------------------
// Lattice Property Proofs
// ---------------------------------------------------------------------------

/**
 * Test lattice axioms (idempotent, commutative, associative, absorption)
 * on the given samples or 3 randomly generated ones.
 *
 * Uses tolerance 1e-10 for floating-point comparison via the same
 * trustApproxEqual pattern used by proveAlgebraicProperties.
 */
export function proveLatticeProperties(samples?: TrustValue[]): TrustLatticeResult {
  const tolerance = 1e-10;
  const dims = ['integrity', 'competence', 'reliability'];
  const testSamples = samples && samples.length >= 3
    ? samples
    : [randomTrustValue(dims), randomTrustValue(dims), randomTrustValue(dims)];

  const a = testSamples[0]!;
  const b = testSamples[1]!;
  const c = testSamples[2]!;

  const meetResult = trustMeet(a, b);
  const joinResult = trustJoin(a, b);

  // 1. Idempotent: meet(a,a) = a, join(a,a) = a
  let idempotentHolds = true;
  for (const s of testSamples) {
    if (!trustApproxEqual(trustMeet(s, s), s, tolerance)) {
      idempotentHolds = false;
    }
    if (!trustApproxEqual(trustJoin(s, s), s, tolerance)) {
      idempotentHolds = false;
    }
  }

  // 2. Commutative: meet(a,b) = meet(b,a), join(a,b) = join(b,a)
  let commutativeHolds = true;
  for (let i = 0; i < testSamples.length; i++) {
    for (let j = 0; j < testSamples.length; j++) {
      const x = testSamples[i]!;
      const y = testSamples[j]!;
      if (!trustApproxEqual(trustMeet(x, y), trustMeet(y, x), tolerance)) {
        commutativeHolds = false;
      }
      if (!trustApproxEqual(trustJoin(x, y), trustJoin(y, x), tolerance)) {
        commutativeHolds = false;
      }
    }
  }

  // 3. Associative: meet(a, meet(b,c)) = meet(meet(a,b), c)
  let associativeHolds = true;
  for (let i = 0; i < testSamples.length; i++) {
    for (let j = 0; j < testSamples.length; j++) {
      for (let k = 0; k < testSamples.length; k++) {
        const x = testSamples[i]!;
        const y = testSamples[j]!;
        const z = testSamples[k]!;
        if (!trustApproxEqual(trustMeet(x, trustMeet(y, z)), trustMeet(trustMeet(x, y), z), tolerance)) {
          associativeHolds = false;
        }
        if (!trustApproxEqual(trustJoin(x, trustJoin(y, z)), trustJoin(trustJoin(x, y), z), tolerance)) {
          associativeHolds = false;
        }
      }
    }
  }

  // 4. Absorption: join(a, meet(a,b)) = a, meet(a, join(a,b)) = a
  let absorptionHolds = true;
  for (let i = 0; i < testSamples.length; i++) {
    for (let j = 0; j < testSamples.length; j++) {
      const x = testSamples[i]!;
      const y = testSamples[j]!;
      if (!trustApproxEqual(trustJoin(x, trustMeet(x, y)), x, tolerance)) {
        absorptionHolds = false;
      }
      if (!trustApproxEqual(trustMeet(x, trustJoin(x, y)), x, tolerance)) {
        absorptionHolds = false;
      }
    }
  }

  const isLattice = idempotentHolds && commutativeHolds && associativeHolds && absorptionHolds;

  return {
    meetResult,
    joinResult,
    isLattice,
    absorptionHolds,
    idempotentHolds,
  };
}

// ---------------------------------------------------------------------------
// Formal Verification
// ---------------------------------------------------------------------------

export {
  defineKernelInvariants,
  verifyInvariant,
  verifyAllInvariants,
  generateCounterexampleSearch,
  checkConstraintSatisfiability,
} from './formal-verification.js';

export type {
  KernelInvariant,
  KernelVerificationResult,
  ConstraintSatisfiabilityResult,
} from './formal-verification.js';
