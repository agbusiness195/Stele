import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  keyPairFromPrivateKey,
  sha256String,
  canonicalizeJson,
  signString,
  verify,
  toHex,
  fromHex,
} from '@kervyx/crypto';
import {
  buildCovenant,
  verifyCovenant,
  countersignCovenant,
  validateChainNarrowing,
  canonicalForm,
  computeId,
  PROTOCOL_VERSION,
} from '@kervyx/core';
import type { CovenantDocument, Issuer, Beneficiary } from '@kervyx/core';
import {
  parse,
  evaluate,
  matchAction,
  matchResource,
  checkRateLimit,
  serialize,
} from '@kervyx/ccl';
import { createIdentity, evolveIdentity } from '@kervyx/identity';

/**
 * Canonical Test Vectors for the Kervyx Protocol.
 *
 * These vectors enable cross-implementation verification.
 * Any conformant implementation in any language MUST produce
 * identical results for these inputs.
 *
 * Vector format:
 * {
 *   category: string,
 *   name: string,
 *   description: string,
 *   input: { ... },
 *   expected: { ... },
 * }
 */

interface TestVector {
  category: string;
  name: string;
  description: string;
  input: Record<string, unknown>;
  expected: Record<string, unknown>;
}

const vectors: TestVector[] = [];

function addVector(vector: TestVector): void {
  vectors.push(vector);
}

// Fixed 32-byte seeds for deterministic test vector generation.
// These MUST NOT change -- all cross-implementation test vectors depend on them.
const ISSUER_SEED = fromHex('0000000000000000000000000000000000000000000000000000000000000001');
const BENEFICIARY_SEED = fromHex('0000000000000000000000000000000000000000000000000000000000000002');
const AUDITOR_SEED = fromHex('0000000000000000000000000000000000000000000000000000000000000003');

describe('Canonical Test Vector Generation', () => {
  // Deterministic key pairs derived from fixed seeds
  let issuerKp: Awaited<ReturnType<typeof generateKeyPair>>;
  let beneficiaryKp: Awaited<ReturnType<typeof generateKeyPair>>;
  let auditorKp: Awaited<ReturnType<typeof generateKeyPair>>;

  it('generates crypto vectors', async () => {
    // ── SHA-256 vectors ──
    const sha256Inputs = [
      '',
      'hello',
      'The quick brown fox jumps over the lazy dog',
      '{"action":"read","resource":"/data"}',
    ];

    for (const input of sha256Inputs) {
      const hash = sha256String(input);
      addVector({
        category: 'crypto',
        name: `sha256-${input.length === 0 ? 'empty' : input.slice(0, 20).replace(/[^a-zA-Z0-9]/g, '-')}`,
        description: `SHA-256 hash of "${input.slice(0, 40)}"`,
        input: { message: input },
        expected: { hash },
      });
    }

    // ── JCS Canonicalization vectors ──
    const jcsInputs = [
      { b: 2, a: 1 },
      { z: 'last', a: 'first', m: 'middle' },
      { nested: { b: 2, a: 1 }, top: 'value' },
      { unicode: '\u00e9', ascii: 'e' },
      { numbers: [3, 1, 2], sorted: false },
    ];

    for (let i = 0; i < jcsInputs.length; i++) {
      const input = jcsInputs[i]!;
      const canonical = canonicalizeJson(input);
      addVector({
        category: 'crypto',
        name: `jcs-canonicalize-${i}`,
        description: `JCS (RFC 8785) canonicalization of test object ${i}`,
        input: { object: input },
        expected: { canonical },
      });
    }

    // ── Ed25519 sign/verify vectors ──
    issuerKp = await keyPairFromPrivateKey(ISSUER_SEED);
    beneficiaryKp = await keyPairFromPrivateKey(BENEFICIARY_SEED);
    auditorKp = await keyPairFromPrivateKey(AUDITOR_SEED);

    const messages = [
      'hello world',
      'The Kervyx Protocol',
      JSON.stringify({ action: 'read', resource: '/data' }),
    ];

    for (const msg of messages) {
      const sig = await signString(msg, issuerKp.privateKey);
      const sigHex = toHex(sig);
      const isValid = await verify(
        new TextEncoder().encode(msg),
        sig,
        issuerKp.publicKey,
      );
      expect(isValid).toBe(true);

      addVector({
        category: 'crypto',
        name: `ed25519-sign-${msg.slice(0, 20).replace(/[^a-zA-Z0-9]/g, '-')}`,
        description: `Ed25519 sign/verify of "${msg.slice(0, 40)}"`,
        input: {
          message: msg,
          publicKey: issuerKp.publicKeyHex,
          privateKey: toHex(issuerKp.privateKey),
        },
        expected: {
          signature: sigHex,
          valid: true,
        },
      });
    }
  });

  it('generates CCL evaluation vectors', () => {
    // ── Parse and evaluate vectors ──
    const cclTestCases = [
      {
        name: 'simple-permit',
        source: "permit read on '/data/**'",
        action: 'read',
        resource: '/data/users',
        expectedPermitted: true,
      },
      {
        name: 'simple-deny',
        source: "deny delete on '/system/**'",
        action: 'delete',
        resource: '/system/config',
        expectedPermitted: false,
      },
      {
        name: 'deny-wins',
        source: "permit read on '/data/**'\ndeny read on '/data/secret'",
        action: 'read',
        resource: '/data/secret',
        expectedPermitted: false,
      },
      {
        name: 'default-deny',
        source: "permit read on '/data/**'",
        action: 'write',
        resource: '/data/users',
        expectedPermitted: false,
      },
      {
        name: 'condition-match',
        source: "permit read on '/data/**' when role = 'admin'",
        action: 'read',
        resource: '/data/users',
        context: { role: 'admin' },
        expectedPermitted: true,
      },
      {
        name: 'condition-no-match',
        source: "permit read on '/data/**' when role = 'admin'",
        action: 'read',
        resource: '/data/users',
        context: { role: 'user' },
        expectedPermitted: false,
      },
      {
        name: 'wildcard-action',
        source: "permit ** on '/public/**'",
        action: 'anything.deep.nested',
        resource: '/public/page',
        expectedPermitted: true,
      },
      {
        name: 'rate-limit-only',
        source: 'limit api.call 100 per 1 hours',
        action: 'api.call',
        resource: '/api/endpoint',
        expectedPermitted: false, // No permit rule, default deny
      },
      {
        name: 'multiple-rules',
        source: "permit read on '/data/**'\npermit write on '/data/public/**'\ndeny write on '/data/private/**'",
        action: 'write',
        resource: '/data/public/file.txt',
        expectedPermitted: true,
      },
      {
        name: 'require-statement',
        source: "require audit on '/sensitive/**'",
        action: 'audit',
        resource: '/sensitive/data',
        expectedPermitted: false, // require doesn't permit, default deny
      },
    ];

    for (const tc of cclTestCases) {
      const cclDoc = parse(tc.source);
      const result = evaluate(cclDoc, tc.action, tc.resource, tc.context);

      expect(result.permitted).toBe(tc.expectedPermitted);

      addVector({
        category: 'ccl',
        name: `evaluate-${tc.name}`,
        description: `CCL evaluation: ${tc.name}`,
        input: {
          source: tc.source,
          action: tc.action,
          resource: tc.resource,
          context: tc.context ?? {},
        },
        expected: {
          permitted: result.permitted,
          reason: result.reason ?? null,
          matchedRule: result.matchedRule
            ? {
                type: result.matchedRule.type,
                action: result.matchedRule.type !== 'limit' ? (result.matchedRule as any).resource : undefined,
              }
            : null,
        },
      });
    }

    // ── Action matching vectors ──
    const actionMatchCases = [
      { pattern: 'read', action: 'read', expected: true },
      { pattern: 'read', action: 'write', expected: false },
      { pattern: '*', action: 'read', expected: true },
      { pattern: '**', action: 'api.call.nested', expected: true },
      { pattern: 'api.*', action: 'api.call', expected: true },
      { pattern: 'api.*', action: 'api.call.nested', expected: false },
      { pattern: 'api.**', action: 'api.call.nested', expected: true },
    ];

    for (const tc of actionMatchCases) {
      const result = matchAction(tc.pattern, tc.action);
      expect(result).toBe(tc.expected);

      addVector({
        category: 'ccl',
        name: `action-match-${tc.pattern}-vs-${tc.action}`,
        description: `Action matching: "${tc.pattern}" vs "${tc.action}"`,
        input: { pattern: tc.pattern, action: tc.action },
        expected: { matches: tc.expected },
      });
    }

    // ── Resource matching vectors ──
    const resourceMatchCases = [
      { pattern: '/data', resource: '/data', expected: true },
      { pattern: '/data', resource: '/data/sub', expected: false },
      { pattern: '/data/**', resource: '/data/sub/deep', expected: true },
      { pattern: '/data/*', resource: '/data/sub', expected: true },
      { pattern: '/data/*', resource: '/data/sub/deep', expected: false },
      { pattern: '**', resource: '/anything/at/all', expected: true },
    ];

    for (const tc of resourceMatchCases) {
      const result = matchResource(tc.pattern, tc.resource);
      expect(result).toBe(tc.expected);

      addVector({
        category: 'ccl',
        name: `resource-match-${tc.pattern.replace(/\//g, '-').replace(/\*/g, 'star')}-vs-${tc.resource.replace(/\//g, '-')}`,
        description: `Resource matching: "${tc.pattern}" vs "${tc.resource}"`,
        input: { pattern: tc.pattern, resource: tc.resource },
        expected: { matches: tc.expected },
      });
    }

    // ── Rate limiting vectors ──
    const rateLimitDoc = parse('limit api.call 100 per 1 hours');
    const now = Date.now();

    const rateLimitCases = [
      {
        name: 'under-limit',
        action: 'api.call',
        currentCount: 50,
        periodStart: now - 1000,
        expectedExceeded: false,
        expectedRemaining: 50,
      },
      {
        name: 'at-limit',
        action: 'api.call',
        currentCount: 100,
        periodStart: now - 1000,
        expectedExceeded: true,
        expectedRemaining: 0,
      },
      {
        name: 'over-limit',
        action: 'api.call',
        currentCount: 150,
        periodStart: now - 1000,
        expectedExceeded: true,
        expectedRemaining: 0,
      },
      {
        name: 'period-expired',
        action: 'api.call',
        currentCount: 150,
        periodStart: now - (3600 * 1000 + 1), // period expired
        expectedExceeded: false,
        expectedRemaining: 100,
      },
    ];

    for (const tc of rateLimitCases) {
      const result = checkRateLimit(rateLimitDoc, tc.action, tc.currentCount, tc.periodStart, now);
      expect(result.exceeded).toBe(tc.expectedExceeded);
      expect(result.remaining).toBe(tc.expectedRemaining);

      addVector({
        category: 'ccl',
        name: `rate-limit-${tc.name}`,
        description: `Rate limiting: ${tc.name}`,
        input: {
          source: 'limit api.call 100 per 1 hours',
          action: tc.action,
          currentCount: tc.currentCount,
          periodStartMs: tc.periodStart,
          nowMs: now,
        },
        expected: {
          exceeded: result.exceeded,
          remaining: result.remaining,
        },
      });
    }

    // ── Serialization round-trip vectors ──
    const roundTripSources = [
      "permit read on '/data/**'",
      "deny delete on '/system/**'",
      "permit read on '/data/**' when role = 'admin'",
      'limit api.call 100 per 1 hours',
      "require audit on '/sensitive/**'",
    ];

    for (const source of roundTripSources) {
      const doc = parse(source);
      const serialized = serialize(doc);

      addVector({
        category: 'ccl',
        name: `serialize-${source.slice(0, 30).replace(/[^a-zA-Z0-9]/g, '-')}`,
        description: `CCL serialize round-trip: "${source.slice(0, 40)}"`,
        input: { source },
        expected: { serialized },
      });
    }
  });

  it('generates covenant lifecycle vectors', async () => {
    // Build a covenant
    const issuer: Issuer = {
      id: 'test-issuer',
      publicKey: issuerKp.publicKeyHex,
      role: 'issuer',
    };

    const beneficiary: Beneficiary = {
      id: 'test-beneficiary',
      publicKey: beneficiaryKp.publicKeyHex,
      role: 'beneficiary',
    };

    const constraints = "permit read on '/data/**'\ndeny delete on '/system/**'";

    const doc = await buildCovenant({
      issuer,
      beneficiary,
      constraints,
      privateKey: issuerKp.privateKey,
    });

    // Capture intermediate values
    const canonical = canonicalForm(doc);
    const computedId = computeId(doc);

    addVector({
      category: 'covenant',
      name: 'build-basic',
      description: 'Build a basic covenant document and capture intermediate values',
      input: {
        issuer: { id: issuer.id, publicKey: issuer.publicKey, role: issuer.role },
        beneficiary: { id: beneficiary.id, publicKey: beneficiary.publicKey, role: beneficiary.role },
        constraints,
        signerPrivateKey: toHex(issuerKp.privateKey),
      },
      expected: {
        version: doc.version,
        id: doc.id,
        canonical_form: canonical,
        canonical_hash_matches_id: computedId === doc.id,
        nonce: doc.nonce,
        nonce_length: doc.nonce.length,
        signature: doc.signature,
        createdAt: doc.createdAt,
      },
    });

    // Verify the covenant
    const verifyResult = await verifyCovenant(doc);
    expect(verifyResult.valid).toBe(true);

    addVector({
      category: 'covenant',
      name: 'verify-valid',
      description: 'Verify a valid covenant document -- all 11 checks should pass',
      input: {
        document: doc,
      },
      expected: {
        valid: true,
        checks: verifyResult.checks.map((c) => ({
          name: c.name,
          passed: c.passed,
        })),
      },
    });

    // Verify with tampered signature (should fail)
    const tamperedSig = doc.signature.startsWith('0')
      ? 'f' + doc.signature.slice(1)
      : '0' + doc.signature.slice(1);
    const tamperedDoc: CovenantDocument = { ...doc, signature: tamperedSig };

    const tamperedResult = await verifyCovenant(tamperedDoc);

    addVector({
      category: 'covenant',
      name: 'verify-tampered-signature',
      description: 'Verify a covenant with tampered signature (should fail)',
      input: {
        document: tamperedDoc,
        tamper: 'first character of signature modified',
      },
      expected: {
        valid: false,
        failed_checks: tamperedResult.checks
          .filter((c) => !c.passed)
          .map((c) => c.name),
      },
    });

    // Verify with tampered constraints (should fail on both id_match and signature)
    const tamperedConstraintsDoc: CovenantDocument = {
      ...doc,
      constraints: "permit write on '/data/**'",
    };
    const tamperedConstraintsResult = await verifyCovenant(tamperedConstraintsDoc);

    addVector({
      category: 'covenant',
      name: 'verify-tampered-constraints',
      description: 'Verify a covenant with tampered constraints (should fail id_match and signature)',
      input: {
        document: tamperedConstraintsDoc,
        tamper: 'constraints modified after signing',
      },
      expected: {
        valid: false,
        failed_checks: tamperedConstraintsResult.checks
          .filter((c) => !c.passed)
          .map((c) => c.name),
      },
    });

    // Countersign
    const countersigned = await countersignCovenant(doc, auditorKp, 'auditor');
    expect(countersigned.countersignatures).toBeDefined();
    expect(countersigned.countersignatures!.length).toBe(1);

    addVector({
      category: 'covenant',
      name: 'countersign',
      description: 'Countersign a covenant document with an auditor',
      input: {
        document_id: doc.id,
        signerPublicKey: auditorKp.publicKeyHex,
        signerPrivateKey: toHex(auditorKp.privateKey),
        signerRole: 'auditor',
      },
      expected: {
        countersignature_count: countersigned.countersignatures!.length,
        countersigner_role: countersigned.countersignatures![0]!.signerRole,
        countersigner_publicKey: countersigned.countersignatures![0]!.signerPublicKey,
        countersignature_signature: countersigned.countersignatures![0]!.signature,
      },
    });

    // Verify the countersigned document
    const countersignedVerify = await verifyCovenant(countersigned);
    expect(countersignedVerify.valid).toBe(true);

    addVector({
      category: 'covenant',
      name: 'verify-countersigned',
      description: 'Verify a countersigned covenant document',
      input: {
        document: countersigned,
      },
      expected: {
        valid: true,
        checks: countersignedVerify.checks.map((c) => ({
          name: c.name,
          passed: c.passed,
        })),
      },
    });
  });

  it('generates identity vectors', async () => {
    const identity = await createIdentity({
      operatorKeyPair: issuerKp,
      operatorIdentifier: 'test-operator',
      model: {
        provider: 'anthropic',
        modelId: 'claude-3',
      },
      capabilities: ['read', 'write', 'api.call'],
      deployment: {
        runtime: 'container',
      },
    });

    addVector({
      category: 'identity',
      name: 'create-basic',
      description: 'Create a basic agent identity',
      input: {
        operatorPublicKey: issuerKp.publicKeyHex,
        operatorPrivateKey: toHex(issuerKp.privateKey),
        operatorIdentifier: 'test-operator',
        model: { provider: 'anthropic', modelId: 'claude-3' },
        capabilities: ['read', 'write', 'api.call'],
        deployment: { runtime: 'container' },
      },
      expected: {
        id: identity.id,
        has_id: identity.id.length > 0,
        model_provider: identity.model.provider,
        model_modelId: identity.model.modelId,
        capabilities_sorted: identity.capabilities,
        capabilities_count: identity.capabilities.length,
        capabilityManifestHash: identity.capabilityManifestHash,
        lineage_length: identity.lineage.length,
        lineage_first_changeType: identity.lineage[0]!.changeType,
        lineage_first_reputationCarryForward: identity.lineage[0]!.reputationCarryForward,
        version: identity.version,
        signature: identity.signature,
      },
    });

    // Evolve the identity
    const evolved = await evolveIdentity(identity, {
      operatorKeyPair: issuerKp,
      changeType: 'model_update',
      description: 'Upgraded to claude-4',
      updates: {
        model: {
          provider: 'anthropic',
          modelId: 'claude-4',
        },
      },
    });

    addVector({
      category: 'identity',
      name: 'evolve-model-update',
      description: 'Evolve an identity with a model update',
      input: {
        originalIdentityId: identity.id,
        operatorPublicKey: issuerKp.publicKeyHex,
        operatorPrivateKey: toHex(issuerKp.privateKey),
        changeType: 'model_update',
        description: 'Upgraded to claude-4',
        updates: { model: { provider: 'anthropic', modelId: 'claude-4' } },
      },
      expected: {
        new_id: evolved.id,
        new_id_differs: evolved.id !== identity.id,
        model_updated: evolved.model.modelId === 'claude-4',
        model_provider: evolved.model.provider,
        lineage_grew: evolved.lineage.length > identity.lineage.length,
        lineage_length: evolved.lineage.length,
        latest_changeType: evolved.lineage[evolved.lineage.length - 1]!.changeType,
        latest_parentHash: evolved.lineage[evolved.lineage.length - 1]!.parentHash,
        version: evolved.version,
        signature: evolved.signature,
      },
    });

    // Evolve with capability change
    const capEvolved = await evolveIdentity(identity, {
      operatorKeyPair: issuerKp,
      changeType: 'capability_change',
      description: 'Added admin capability',
      updates: {
        capabilities: ['read', 'write', 'api.call', 'admin'],
      },
    });

    addVector({
      category: 'identity',
      name: 'evolve-capability-change',
      description: 'Evolve an identity with a capability expansion',
      input: {
        originalIdentityId: identity.id,
        changeType: 'capability_change',
        updates: { capabilities: ['read', 'write', 'api.call', 'admin'] },
      },
      expected: {
        new_id: capEvolved.id,
        capabilities_sorted: capEvolved.capabilities,
        capabilities_count: capEvolved.capabilities.length,
        capabilityManifestHash: capEvolved.capabilityManifestHash,
        lineage_length: capEvolved.lineage.length,
        latest_reputationCarryForward:
          capEvolved.lineage[capEvolved.lineage.length - 1]!.reputationCarryForward,
      },
    });
  });

  it('generates chain narrowing vectors', async () => {
    // Build parent covenant with broad permissions
    const issuer: Issuer = {
      id: 'test-issuer',
      publicKey: issuerKp.publicKeyHex,
      role: 'issuer',
    };

    const beneficiary: Beneficiary = {
      id: 'test-beneficiary',
      publicKey: beneficiaryKp.publicKeyHex,
      role: 'beneficiary',
    };

    const parentDoc = await buildCovenant({
      issuer,
      beneficiary,
      constraints: "permit read on '/data/**'\npermit write on '/data/**'",
      privateKey: issuerKp.privateKey,
    });

    // Build valid narrowing child (subset of parent permissions)
    const validChildDoc = await buildCovenant({
      issuer,
      beneficiary,
      constraints: "permit read on '/data/public/**'",
      privateKey: issuerKp.privateKey,
      chain: {
        parentId: parentDoc.id,
        relation: 'delegates',
        depth: 1,
      },
    });

    const validNarrowing = await validateChainNarrowing(validChildDoc, parentDoc);

    addVector({
      category: 'chain',
      name: 'valid-narrowing',
      description: 'Child narrows parent permissions (valid delegation)',
      input: {
        parentConstraints: parentDoc.constraints,
        childConstraints: validChildDoc.constraints,
        childChain: validChildDoc.chain,
      },
      expected: {
        valid: validNarrowing.valid,
        violations_count: validNarrowing.violations.length,
      },
    });

    // Build invalid broadening child (permits something parent denies)
    const parentWithDeny = await buildCovenant({
      issuer,
      beneficiary,
      constraints: "permit read on '/data/**'\ndeny write on '/data/private/**'",
      privateKey: issuerKp.privateKey,
    });

    const broadeningChildDoc = await buildCovenant({
      issuer,
      beneficiary,
      constraints: "permit write on '/data/private/**'",
      privateKey: issuerKp.privateKey,
      chain: {
        parentId: parentWithDeny.id,
        relation: 'delegates',
        depth: 1,
      },
    });

    const invalidNarrowing = await validateChainNarrowing(broadeningChildDoc, parentWithDeny);

    addVector({
      category: 'chain',
      name: 'invalid-broadening',
      description: 'Child broadens parent permissions (invalid -- permits what parent denies)',
      input: {
        parentConstraints: parentWithDeny.constraints,
        childConstraints: broadeningChildDoc.constraints,
      },
      expected: {
        valid: invalidNarrowing.valid,
        violations_count: invalidNarrowing.violations.length,
        violation_reasons: invalidNarrowing.violations.map((v) => v.reason),
      },
    });

    // Build child that permits outside parent scope
    const outsideScopeChild = await buildCovenant({
      issuer,
      beneficiary,
      constraints: "permit read on '/admin/**'",
      privateKey: issuerKp.privateKey,
      chain: {
        parentId: parentDoc.id,
        relation: 'delegates',
        depth: 1,
      },
    });

    const outsideScope = await validateChainNarrowing(outsideScopeChild, parentDoc);

    addVector({
      category: 'chain',
      name: 'outside-parent-scope',
      description: 'Child permits resources outside parent scope (invalid)',
      input: {
        parentConstraints: parentDoc.constraints,
        childConstraints: outsideScopeChild.constraints,
      },
      expected: {
        valid: outsideScope.valid,
        violations_count: outsideScope.violations.length,
        violation_reasons: outsideScope.violations.map((v) => v.reason),
      },
    });
  });

  it('writes all vectors to JSON', async () => {
    expect(vectors.length).toBeGreaterThan(0);

    // Group by category
    const grouped: Record<string, TestVector[]> = {};
    for (const v of vectors) {
      if (!grouped[v.category]) grouped[v.category] = [];
      grouped[v.category]!.push(v);
    }

    const output = {
      _meta: {
        generated_at: '2026-01-01T00:00:00.000Z',
        protocol_version: PROTOCOL_VERSION,
        generator: '@kervyx/test-vectors',
        description:
          'Canonical test vectors for the Kervyx protocol. Any conformant implementation MUST produce identical results for these inputs.',
        total_vectors: vectors.length,
        categories: Object.keys(grouped),
        category_counts: Object.fromEntries(
          Object.entries(grouped).map(([k, v]) => [k, v.length]),
        ),
      },
      vectors: grouped,
    };

    // Write to file
    const fs = await import('fs');
    const path = await import('path');

    const dir = path.resolve(__dirname);
    fs.mkdirSync(dir, { recursive: true });

    const filePath = path.join(dir, 'canonical-vectors.json');
    fs.writeFileSync(filePath, JSON.stringify(output, null, 2));

    console.log(`\nWrote ${vectors.length} test vectors to ${filePath}`);
    console.log(
      'Categories:',
      Object.entries(grouped)
        .map(([k, v]) => `${k}: ${v.length}`)
        .join(', '),
    );

    // Verify the output is valid JSON by re-reading
    const readBack = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    expect(readBack._meta.total_vectors).toBe(vectors.length);
    expect(readBack._meta.protocol_version).toBe(PROTOCOL_VERSION);
  });
});
