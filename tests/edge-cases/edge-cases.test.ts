/**
 * Edge Case & Negative Tests
 *
 * Comprehensive tests targeting boundary conditions, empty inputs,
 * invalid inputs, and other edge cases across the foundation packages.
 * These complement the happy-path tests to strengthen overall coverage.
 */
import { describe, it, expect } from 'vitest';

// ─── @stele/crypto ────────────────────────────────────────────────────────────

describe('Edge Cases: @stele/crypto', () => {
  it('fromHex with empty string returns empty Uint8Array', async () => {
    const { fromHex } = await import('@stele/crypto');
    const result = fromHex('');
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(0);
  });

  it('fromHex with odd-length string throws', async () => {
    const { fromHex } = await import('@stele/crypto');
    expect(() => fromHex('abc')).toThrow(/odd length/i);
  });

  it('fromHex with non-hex characters throws', async () => {
    const { fromHex } = await import('@stele/crypto');
    expect(() => fromHex('zzzz')).toThrow(/non-hex/i);
  });

  it('fromHex with mixed valid and invalid characters throws', async () => {
    const { fromHex } = await import('@stele/crypto');
    expect(() => fromHex('abcxyz')).toThrow(/non-hex/i);
  });

  it('fromHex with whitespace throws', async () => {
    const { fromHex } = await import('@stele/crypto');
    // 'ab cd' is 5 chars (odd length), so odd-length check fires first
    // Use an even-length string with spaces to test the non-hex check
    expect(() => fromHex('ab d')).toThrow(/non-hex/i);
  });

  it('toHex with empty Uint8Array returns empty string', async () => {
    const { toHex } = await import('@stele/crypto');
    const result = toHex(new Uint8Array([]));
    expect(result).toBe('');
  });

  it('toHex round-trips with fromHex for known values', async () => {
    const { toHex, fromHex } = await import('@stele/crypto');
    const original = new Uint8Array([0, 127, 255]);
    const hex = toHex(original);
    expect(hex).toBe('007fff');
    const roundTripped = fromHex(hex);
    expect(roundTripped).toEqual(original);
  });

  it('base64urlEncode with empty Uint8Array returns empty string', async () => {
    const { base64urlEncode } = await import('@stele/crypto');
    const result = base64urlEncode(new Uint8Array([]));
    expect(result).toBe('');
  });

  it('base64urlEncode/base64urlDecode round-trip with empty array', async () => {
    const { base64urlEncode, base64urlDecode } = await import('@stele/crypto');
    const encoded = base64urlEncode(new Uint8Array([]));
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(new Uint8Array([]));
  });

  it('base64urlEncode/base64urlDecode round-trip with single byte', async () => {
    const { base64urlEncode, base64urlDecode } = await import('@stele/crypto');
    const original = new Uint8Array([42]);
    const encoded = base64urlEncode(original);
    const decoded = base64urlDecode(encoded);
    expect(decoded).toEqual(original);
  });

  it('constantTimeEqual with empty arrays returns true', async () => {
    const { constantTimeEqual } = await import('@stele/crypto');
    const result = constantTimeEqual(new Uint8Array([]), new Uint8Array([]));
    expect(result).toBe(true);
  });

  it('constantTimeEqual with different lengths returns false', async () => {
    const { constantTimeEqual } = await import('@stele/crypto');
    const result = constantTimeEqual(
      new Uint8Array([1, 2, 3]),
      new Uint8Array([1, 2]),
    );
    expect(result).toBe(false);
  });

  it('constantTimeEqual with identical arrays returns true', async () => {
    const { constantTimeEqual } = await import('@stele/crypto');
    const a = new Uint8Array([0, 127, 255]);
    const b = new Uint8Array([0, 127, 255]);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it('constantTimeEqual with single-bit difference returns false', async () => {
    const { constantTimeEqual } = await import('@stele/crypto');
    const a = new Uint8Array([0, 127, 255]);
    const b = new Uint8Array([0, 127, 254]);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it('sha256 produces consistent output for same input', async () => {
    const { sha256 } = await import('@stele/crypto');
    const data = new Uint8Array([1, 2, 3]);
    const hash1 = sha256(data);
    const hash2 = sha256(data);
    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64); // 32 bytes = 64 hex chars
  });

  it('sha256String of empty string produces valid hash', async () => {
    const { sha256String } = await import('@stele/crypto');
    const hash = sha256String('');
    expect(hash.length).toBe(64);
    // Known SHA-256 of empty string
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('canonicalizeJson produces same output regardless of key order', async () => {
    const { canonicalizeJson } = await import('@stele/crypto');
    const a = canonicalizeJson({ z: 1, a: 2, m: 3 });
    const b = canonicalizeJson({ a: 2, m: 3, z: 1 });
    expect(a).toBe(b);
  });

  it('canonicalizeJson handles null and undefined values', async () => {
    const { canonicalizeJson } = await import('@stele/crypto');
    const result = canonicalizeJson({ a: null, b: undefined, c: 1 });
    // undefined fields are omitted by JSON.stringify
    expect(result).toBe('{"a":null,"c":1}');
  });

  it('generateNonce returns 32-byte Uint8Array', async () => {
    const { generateNonce } = await import('@stele/crypto');
    const nonce = generateNonce();
    expect(nonce).toBeInstanceOf(Uint8Array);
    expect(nonce.length).toBe(32);
  });

  it('generateId returns hex string of correct length', async () => {
    const { generateId } = await import('@stele/crypto');
    const id16 = generateId();
    expect(id16.length).toBe(32); // 16 bytes = 32 hex chars
    const id32 = generateId(32);
    expect(id32.length).toBe(64); // 32 bytes = 64 hex chars
  });

  it('timestamp returns valid ISO 8601 string', async () => {
    const { timestamp } = await import('@stele/crypto');
    const ts = timestamp();
    expect(new Date(ts).toISOString()).toBe(ts);
  });
});

// ─── @stele/core ──────────────────────────────────────────────────────────────

describe('Edge Cases: @stele/core', () => {
  it('deserializeCovenant with empty string throws', async () => {
    const { deserializeCovenant } = await import('@stele/core');
    expect(() => deserializeCovenant('')).toThrow();
  });

  it('deserializeCovenant with "[]" (array) throws', async () => {
    const { deserializeCovenant } = await import('@stele/core');
    expect(() => deserializeCovenant('[]')).toThrow(/must be a JSON object/i);
  });

  it('deserializeCovenant with "null" throws', async () => {
    const { deserializeCovenant } = await import('@stele/core');
    expect(() => deserializeCovenant('null')).toThrow(/must be a JSON object/i);
  });

  it('deserializeCovenant with empty object throws about missing fields', async () => {
    const { deserializeCovenant } = await import('@stele/core');
    expect(() => deserializeCovenant('{}')).toThrow(/missing or invalid required field/i);
  });

  it('deserializeCovenant with non-JSON string throws', async () => {
    const { deserializeCovenant } = await import('@stele/core');
    expect(() => deserializeCovenant('not json at all')).toThrow(/invalid json/i);
  });

  it('deserializeCovenant with "true" throws', async () => {
    const { deserializeCovenant } = await import('@stele/core');
    expect(() => deserializeCovenant('true')).toThrow(/must be a JSON object/i);
  });

  it('deserializeCovenant with "42" throws', async () => {
    const { deserializeCovenant } = await import('@stele/core');
    expect(() => deserializeCovenant('42')).toThrow(/must be a JSON object/i);
  });

  it('serializeCovenant round-trip with a minimal valid document', async () => {
    const { buildCovenant, serializeCovenant, deserializeCovenant } = await import('@stele/core');
    const { generateKeyPair } = await import('@stele/crypto');

    const kp = await generateKeyPair();
    const doc = await buildCovenant({
      issuer: { id: 'alice', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'bob', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit read on '/data/**'",
      privateKey: kp.privateKey,
    });

    const json = serializeCovenant(doc);
    const restored = deserializeCovenant(json);

    expect(restored.id).toBe(doc.id);
    expect(restored.version).toBe(doc.version);
    expect(restored.issuer.id).toBe(doc.issuer.id);
    expect(restored.beneficiary.id).toBe(doc.beneficiary.id);
    expect(restored.constraints).toBe(doc.constraints);
    expect(restored.signature).toBe(doc.signature);
  });

  it('computeId is deterministic for same document', async () => {
    const { buildCovenant, computeId } = await import('@stele/core');
    const { generateKeyPair } = await import('@stele/crypto');

    const kp = await generateKeyPair();
    const doc = await buildCovenant({
      issuer: { id: 'alice', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'bob', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit read on '/data/**'",
      privateKey: kp.privateKey,
    });

    const id1 = computeId(doc);
    const id2 = computeId(doc);
    expect(id1).toBe(id2);
    expect(id1).toBe(doc.id);
  });

  it('PROTOCOL_VERSION is a non-empty string', async () => {
    const { PROTOCOL_VERSION } = await import('@stele/core');
    expect(typeof PROTOCOL_VERSION).toBe('string');
    expect(PROTOCOL_VERSION.length).toBeGreaterThan(0);
  });

  it('MAX_CHAIN_DEPTH is a positive integer', async () => {
    const { MAX_CHAIN_DEPTH } = await import('@stele/core');
    expect(Number.isInteger(MAX_CHAIN_DEPTH)).toBe(true);
    expect(MAX_CHAIN_DEPTH).toBeGreaterThan(0);
  });

  it('MAX_DOCUMENT_SIZE is a positive integer', async () => {
    const { MAX_DOCUMENT_SIZE } = await import('@stele/core');
    expect(Number.isInteger(MAX_DOCUMENT_SIZE)).toBe(true);
    expect(MAX_DOCUMENT_SIZE).toBeGreaterThan(0);
  });
});

// ─── @stele/ccl ─────────────────────────────────────────────────────────────

describe('Edge Cases: @stele/ccl', () => {
  it('parse with empty string throws CCLSyntaxError', async () => {
    const { parse, CCLSyntaxError } = await import('@stele/ccl');
    expect(() => parse('')).toThrow(CCLSyntaxError);
  });

  it('parse with whitespace-only string throws CCLSyntaxError', async () => {
    const { parse, CCLSyntaxError } = await import('@stele/ccl');
    expect(() => parse('   \n\t  ')).toThrow(CCLSyntaxError);
  });

  it('parse with invalid CCL syntax throws', async () => {
    const { parse } = await import('@stele/ccl');
    expect(() => parse('this is not valid ccl')).toThrow();
  });

  it('evaluate with empty CCL document defaults to deny', async () => {
    const { evaluate } = await import('@stele/ccl');
    // An empty CCLDocument (no permits, denies, etc.) should default deny
    const emptyDoc = {
      statements: [],
      permits: [],
      denies: [],
      obligations: [],
      limits: [],
    };
    const result = evaluate(emptyDoc, 'read', '/data');
    expect(result.permitted).toBe(false);
  });

  it('evaluate with matching deny rule overrides permit', async () => {
    const { parse, evaluate } = await import('@stele/ccl');
    const doc = parse("permit read on '/data/**'\ndeny read on '/data/secret'");
    const result = evaluate(doc, 'read', '/data/secret');
    expect(result.permitted).toBe(false);
  });

  it('matchAction handles wildcard patterns', async () => {
    const { matchAction } = await import('@stele/ccl');
    expect(matchAction('*', 'read')).toBe(true);
    expect(matchAction('*', 'write')).toBe(true);
    expect(matchAction('read', 'read')).toBe(true);
    expect(matchAction('read', 'write')).toBe(false);
  });

  it('matchResource handles wildcard patterns', async () => {
    const { matchResource } = await import('@stele/ccl');
    expect(matchResource('/data/**', '/data/file.txt')).toBe(true);
    expect(matchResource('/data/**', '/other/file.txt')).toBe(false);
    expect(matchResource('/**', '/anything/at/all')).toBe(true);
  });

  it('specificity returns higher value for more specific patterns', async () => {
    const { specificity } = await import('@stele/ccl');
    const general = specificity('*', '/**');
    const specific = specificity('read', '/data/file.txt');
    expect(specific).toBeGreaterThan(general);
  });

  it('serialize round-trips with parse for a simple document', async () => {
    const { parse, serialize } = await import('@stele/ccl');
    const source = "permit read on '/data/**'";
    const doc = parse(source);
    const serialized = serialize(doc);
    const reparsed = parse(serialized);
    expect(reparsed.permits.length).toBe(doc.permits.length);
    expect(reparsed.denies.length).toBe(doc.denies.length);
  });

  it('merge of two documents preserves deny-wins semantics', async () => {
    const { parse, merge, evaluate } = await import('@stele/ccl');
    const docA = parse("permit read on '/data/**'");
    const docB = parse("deny read on '/data/**'");
    const merged = merge(docA, docB);
    const result = evaluate(merged, 'read', '/data/file');
    expect(result.permitted).toBe(false);
  });
});

// ─── @stele/negotiation ──────────────────────────────────────────────────────

describe('Edge Cases: @stele/negotiation', () => {
  it('matchesPattern("*", "anything") matches', async () => {
    const { matchesPattern } = await import('@stele/negotiation');
    expect(matchesPattern('*', 'anything')).toBe(true);
  });

  it('matchesPattern("", "") matches (exact match)', async () => {
    const { matchesPattern } = await import('@stele/negotiation');
    expect(matchesPattern('', '')).toBe(true);
  });

  it('matchesPattern("foo*bar", "foobazbar") matches', async () => {
    const { matchesPattern } = await import('@stele/negotiation');
    expect(matchesPattern('foo*bar', 'foobazbar')).toBe(true);
  });

  it('matchesPattern("foo*bar", "foobaz") does not match', async () => {
    const { matchesPattern } = await import('@stele/negotiation');
    expect(matchesPattern('foo*bar', 'foobaz')).toBe(false);
  });

  it('matchesPattern with no wildcards uses exact match', async () => {
    const { matchesPattern } = await import('@stele/negotiation');
    expect(matchesPattern('deny:exfiltrate-data', 'deny:exfiltrate-data')).toBe(true);
    expect(matchesPattern('deny:exfiltrate-data', 'deny:other')).toBe(false);
  });

  it('matchesPattern with multiple wildcards', async () => {
    const { matchesPattern } = await import('@stele/negotiation');
    expect(matchesPattern('*:*', 'deny:data')).toBe(true);
    expect(matchesPattern('deny:*-*', 'deny:exfiltrate-data')).toBe(true);
  });

  it('matchesPattern with wildcard at start', async () => {
    const { matchesPattern } = await import('@stele/negotiation');
    expect(matchesPattern('*data', 'exfiltrate-data')).toBe(true);
    expect(matchesPattern('*data', 'exfiltrate-other')).toBe(false);
  });

  it('matchesPattern escapes regex special characters', async () => {
    const { matchesPattern } = await import('@stele/negotiation');
    // Dot should be literal, not regex any-char
    expect(matchesPattern('foo.bar', 'foo.bar')).toBe(true);
    expect(matchesPattern('foo.bar', 'fooxbar')).toBe(false);
  });

  it('evaluate rejects proposal containing a dealbreaker', async () => {
    const { evaluate } = await import('@stele/negotiation');
    const proposal = {
      from: 'agent',
      constraints: ['permit:unrestricted-access'],
      requirements: [],
      timestamp: Date.now(),
    };
    const policy = {
      requiredConstraints: [],
      preferredConstraints: [],
      dealbreakers: ['permit:unrestricted-access'],
      maxRounds: 10,
      timeoutMs: 30000,
    };
    expect(evaluate(proposal, policy)).toBe('reject');
  });

  it('evaluate accepts when all required constraints are present', async () => {
    const { evaluate } = await import('@stele/negotiation');
    const proposal = {
      from: 'agent',
      constraints: ['deny:exfiltrate-data', 'require:audit-logging'],
      requirements: ['deny:exfiltrate-data'],
      timestamp: Date.now(),
    };
    const policy = {
      requiredConstraints: ['deny:exfiltrate-data', 'require:audit-logging'],
      preferredConstraints: [],
      dealbreakers: [],
      maxRounds: 10,
      timeoutMs: 30000,
    };
    expect(evaluate(proposal, policy)).toBe('accept');
  });

  it('evaluate returns counter when some required constraints are missing', async () => {
    const { evaluate } = await import('@stele/negotiation');
    const proposal = {
      from: 'agent',
      constraints: ['deny:exfiltrate-data'],
      requirements: ['deny:exfiltrate-data'],
      timestamp: Date.now(),
    };
    const policy = {
      requiredConstraints: ['deny:exfiltrate-data', 'require:audit-logging'],
      preferredConstraints: [],
      dealbreakers: [],
      maxRounds: 10,
      timeoutMs: 30000,
    };
    expect(evaluate(proposal, policy)).toBe('counter');
  });

  it('computeNashBargainingSolution with empty outcomes returns null', async () => {
    const { computeNashBargainingSolution } = await import('@stele/negotiation');
    const utilityA = { partyId: 'a', evaluate: () => 0, disagreementValue: 0 };
    const utilityB = { partyId: 'b', evaluate: () => 0, disagreementValue: 0 };
    expect(computeNashBargainingSolution([], utilityA, utilityB)).toBeNull();
  });

  it('paretoFrontier with empty outcomes returns empty array', async () => {
    const { paretoFrontier } = await import('@stele/negotiation');
    expect(paretoFrontier([], [])).toEqual([]);
  });

  it('roundCount returns number of proposals in session', async () => {
    const { initiate, roundCount } = await import('@stele/negotiation');
    const policy = {
      requiredConstraints: ['deny:exfiltrate-data'],
      preferredConstraints: [],
      dealbreakers: [],
      maxRounds: 10,
      timeoutMs: 30000,
    };
    const session = initiate('alice', 'bob', policy);
    expect(roundCount(session)).toBe(1); // Initial proposal
  });

  it('agree with single proposal uses that proposal as resulting constraints', async () => {
    const { initiate, agree } = await import('@stele/negotiation');
    const policy = {
      requiredConstraints: ['deny:exfiltrate-data'],
      preferredConstraints: ['permit:read-public'],
      dealbreakers: [],
      maxRounds: 10,
      timeoutMs: 30000,
    };
    const session = initiate('alice', 'bob', policy);
    const agreed = agree(session);
    expect(agreed.status).toBe('agreed');
    expect(agreed.resultingConstraints).toBeDefined();
    expect(agreed.resultingConstraints!.length).toBeGreaterThan(0);
  });
});

// ─── @stele/gametheory ────────────────────────────────────────────────────────

describe('Edge Cases: @stele/gametheory', () => {
  it('normalCDF(0) returns approximately 0.5', async () => {
    const { normalCDF } = await import('@stele/gametheory');
    const result = normalCDF(0);
    expect(result).toBeCloseTo(0.5, 5);
  });

  it('normalCDF with very large positive value returns approximately 1', async () => {
    const { normalCDF } = await import('@stele/gametheory');
    const result = normalCDF(10);
    expect(result).toBeCloseTo(1, 5);
  });

  it('normalCDF with very large negative value returns approximately 0', async () => {
    const { normalCDF } = await import('@stele/gametheory');
    const result = normalCDF(-10);
    expect(result).toBeCloseTo(0, 5);
  });

  it('normalCDF is monotonically increasing', async () => {
    const { normalCDF } = await import('@stele/gametheory');
    const values = [-3, -2, -1, 0, 1, 2, 3];
    for (let i = 0; i < values.length - 1; i++) {
      expect(normalCDF(values[i]!)).toBeLessThan(normalCDF(values[i + 1]!));
    }
  });

  it('normalCDF is symmetric around 0: CDF(-x) + CDF(x) = 1', async () => {
    const { normalCDF } = await import('@stele/gametheory');
    for (const x of [0.5, 1, 1.5, 2, 3]) {
      const sum = normalCDF(x) + normalCDF(-x);
      expect(sum).toBeCloseTo(1, 5);
    }
  });

  it('choleskyDecompose with 1x1 identity matrix', async () => {
    const { choleskyDecompose } = await import('@stele/gametheory');
    const result = choleskyDecompose([[1]]);
    expect(result.length).toBe(1);
    expect(result[0]![0]).toBeCloseTo(1, 10);
  });

  it('choleskyDecompose with 2x2 identity matrix', async () => {
    const { choleskyDecompose } = await import('@stele/gametheory');
    const identity = [
      [1, 0],
      [0, 1],
    ];
    const L = choleskyDecompose(identity);
    expect(L.length).toBe(2);
    // L should be the identity matrix for an identity input
    expect(L[0]![0]).toBeCloseTo(1, 10);
    expect(L[0]![1]).toBeCloseTo(0, 10);
    expect(L[1]![0]).toBeCloseTo(0, 10);
    expect(L[1]![1]).toBeCloseTo(1, 10);
  });

  it('choleskyDecompose with 3x3 identity matrix', async () => {
    const { choleskyDecompose } = await import('@stele/gametheory');
    const identity = [
      [1, 0, 0],
      [0, 1, 0],
      [0, 0, 1],
    ];
    const L = choleskyDecompose(identity);
    expect(L.length).toBe(3);
    // L * L^T should equal the identity
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        const expected = i === j ? 1 : 0;
        expect(L[i]![j]).toBeCloseTo(expected, 10);
      }
    }
  });

  it('choleskyDecompose with positive definite matrix reconstructs original', async () => {
    const { choleskyDecompose } = await import('@stele/gametheory');
    const A = [
      [4, 2],
      [2, 3],
    ];
    const L = choleskyDecompose(A);
    // Reconstruct: A = L * L^T
    const n = L.length;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        let sum = 0;
        for (let k = 0; k < n; k++) {
          sum += L[i]![k]! * L[j]![k]!;
        }
        expect(sum).toBeCloseTo(A[i]![j]!, 10);
      }
    }
  });

  it('proveHonesty returns isDominantStrategy=true when conditions hold', async () => {
    const { proveHonesty } = await import('@stele/gametheory');
    const result = proveHonesty({
      stakeAmount: 100,
      detectionProbability: 0.9,
      reputationValue: 50,
      maxViolationGain: 80,
      coburn: 10,
    });
    // 100 * 0.9 + 50 + 10 = 150 > 80
    expect(result.isDominantStrategy).toBe(true);
    expect(result.margin).toBeGreaterThan(0);
  });

  it('proveHonesty returns isDominantStrategy=false when gain exceeds cost', async () => {
    const { proveHonesty } = await import('@stele/gametheory');
    const result = proveHonesty({
      stakeAmount: 10,
      detectionProbability: 0.1,
      reputationValue: 1,
      maxViolationGain: 100,
      coburn: 0,
    });
    // 10 * 0.1 + 1 + 0 = 2 < 100
    expect(result.isDominantStrategy).toBe(false);
    expect(result.margin).toBeLessThan(0);
  });

  it('validateParameters rejects negative stakeAmount', async () => {
    const { validateParameters } = await import('@stele/gametheory');
    expect(() => validateParameters({ stakeAmount: -1 })).toThrow(/stakeAmount/);
  });

  it('validateParameters rejects detectionProbability out of range', async () => {
    const { validateParameters } = await import('@stele/gametheory');
    expect(() => validateParameters({ detectionProbability: 1.5 })).toThrow(/detectionProbability/);
    expect(() => validateParameters({ detectionProbability: -0.1 })).toThrow(/detectionProbability/);
  });
});

// ─── @stele/composition ──────────────────────────────────────────────────────

describe('Edge Cases: @stele/composition', () => {
  it('trustMeet with empty dimensions returns empty dimensions', async () => {
    const { trustMeet } = await import('@stele/composition');
    const a = { dimensions: {}, confidence: 0.5 };
    const b = { dimensions: {}, confidence: 0.7 };
    const result = trustMeet(a, b);
    expect(Object.keys(result.dimensions)).toHaveLength(0);
    expect(result.confidence).toBe(0.5); // min of 0.5, 0.7
  });

  it('trustJoin with empty dimensions returns empty dimensions', async () => {
    const { trustJoin } = await import('@stele/composition');
    const a = { dimensions: {}, confidence: 0.5 };
    const b = { dimensions: {}, confidence: 0.7 };
    const result = trustJoin(a, b);
    expect(Object.keys(result.dimensions)).toHaveLength(0);
    expect(result.confidence).toBe(0.7); // max of 0.5, 0.7
  });

  it('trustMeet takes minimum of each dimension', async () => {
    const { trustMeet } = await import('@stele/composition');
    const a = { dimensions: { integrity: 0.8, competence: 0.6 }, confidence: 0.9 };
    const b = { dimensions: { integrity: 0.5, competence: 0.9 }, confidence: 0.7 };
    const result = trustMeet(a, b);
    expect(result.dimensions.integrity).toBeCloseTo(0.5, 10);
    expect(result.dimensions.competence).toBeCloseTo(0.6, 10);
    expect(result.confidence).toBeCloseTo(0.7, 10);
  });

  it('trustJoin takes maximum of each dimension', async () => {
    const { trustJoin } = await import('@stele/composition');
    const a = { dimensions: { integrity: 0.8, competence: 0.6 }, confidence: 0.9 };
    const b = { dimensions: { integrity: 0.5, competence: 0.9 }, confidence: 0.7 };
    const result = trustJoin(a, b);
    expect(result.dimensions.integrity).toBeCloseTo(0.8, 10);
    expect(result.dimensions.competence).toBeCloseTo(0.9, 10);
    expect(result.confidence).toBeCloseTo(0.9, 10);
  });

  it('trustMeet with disjoint dimensions fills missing with 0', async () => {
    const { trustMeet } = await import('@stele/composition');
    const a = { dimensions: { integrity: 0.8 }, confidence: 0.5 };
    const b = { dimensions: { competence: 0.7 }, confidence: 0.5 };
    const result = trustMeet(a, b);
    // Missing dimensions default to 0, min(0.8, 0) = 0, min(0, 0.7) = 0
    expect(result.dimensions.integrity).toBe(0);
    expect(result.dimensions.competence).toBe(0);
  });

  it('trustJoin with disjoint dimensions fills missing with 0', async () => {
    const { trustJoin } = await import('@stele/composition');
    const a = { dimensions: { integrity: 0.8 }, confidence: 0.5 };
    const b = { dimensions: { competence: 0.7 }, confidence: 0.5 };
    const result = trustJoin(a, b);
    // Missing dimensions default to 0, max(0.8, 0) = 0.8, max(0, 0.7) = 0.7
    expect(result.dimensions.integrity).toBeCloseTo(0.8, 10);
    expect(result.dimensions.competence).toBeCloseTo(0.7, 10);
  });

  it('proveLatticeProperties returns valid lattice result', async () => {
    const { proveLatticeProperties } = await import('@stele/composition');
    const result = proveLatticeProperties();
    expect(result).toHaveProperty('meetResult');
    expect(result).toHaveProperty('joinResult');
    expect(result).toHaveProperty('isLattice');
    expect(result).toHaveProperty('absorptionHolds');
    expect(result).toHaveProperty('idempotentHolds');
    expect(typeof result.isLattice).toBe('boolean');
    expect(typeof result.absorptionHolds).toBe('boolean');
    expect(typeof result.idempotentHolds).toBe('boolean');
  });

  it('proveLatticeProperties with explicit samples validates correctly', async () => {
    const { proveLatticeProperties } = await import('@stele/composition');
    const samples = [
      { dimensions: { integrity: 0.5, competence: 0.5 }, confidence: 0.5 },
      { dimensions: { integrity: 0.7, competence: 0.3 }, confidence: 0.6 },
      { dimensions: { integrity: 0.4, competence: 0.8 }, confidence: 0.7 },
    ];
    const result = proveLatticeProperties(samples);
    expect(result.isLattice).toBe(true);
    expect(result.idempotentHolds).toBe(true);
    expect(result.absorptionHolds).toBe(true);
  });

  it('trustMeet is idempotent: meet(a, a) = a', async () => {
    const { trustMeet } = await import('@stele/composition');
    const a = { dimensions: { integrity: 0.8, competence: 0.6 }, confidence: 0.9 };
    const result = trustMeet(a, a);
    expect(result.dimensions.integrity).toBeCloseTo(a.dimensions.integrity, 10);
    expect(result.dimensions.competence).toBeCloseTo(a.dimensions.competence, 10);
    expect(result.confidence).toBeCloseTo(a.confidence, 10);
  });

  it('trustJoin is idempotent: join(a, a) = a', async () => {
    const { trustJoin } = await import('@stele/composition');
    const a = { dimensions: { integrity: 0.8, competence: 0.6 }, confidence: 0.9 };
    const result = trustJoin(a, a);
    expect(result.dimensions.integrity).toBeCloseTo(a.dimensions.integrity, 10);
    expect(result.dimensions.competence).toBeCloseTo(a.dimensions.competence, 10);
    expect(result.confidence).toBeCloseTo(a.confidence, 10);
  });

  it('trustMeet is commutative: meet(a, b) = meet(b, a)', async () => {
    const { trustMeet } = await import('@stele/composition');
    const a = { dimensions: { integrity: 0.8, competence: 0.6 }, confidence: 0.9 };
    const b = { dimensions: { integrity: 0.5, competence: 0.9 }, confidence: 0.7 };
    const ab = trustMeet(a, b);
    const ba = trustMeet(b, a);
    expect(ab.dimensions.integrity!).toBeCloseTo(ba.dimensions.integrity!, 10);
    expect(ab.dimensions.competence!).toBeCloseTo(ba.dimensions.competence!, 10);
    expect(ab.confidence).toBeCloseTo(ba.confidence, 10);
  });

  it('trustJoin is commutative: join(a, b) = join(b, a)', async () => {
    const { trustJoin } = await import('@stele/composition');
    const a = { dimensions: { integrity: 0.8, competence: 0.6 }, confidence: 0.9 };
    const b = { dimensions: { integrity: 0.5, competence: 0.9 }, confidence: 0.7 };
    const ab = trustJoin(a, b);
    const ba = trustJoin(b, a);
    expect(ab.dimensions.integrity!).toBeCloseTo(ba.dimensions.integrity!, 10);
    expect(ab.dimensions.competence!).toBeCloseTo(ba.dimensions.competence!, 10);
    expect(ab.confidence).toBeCloseTo(ba.confidence, 10);
  });
});
