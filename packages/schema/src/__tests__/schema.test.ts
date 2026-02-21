import { describe, it, expect } from 'vitest';
import {
  COVENANT_SCHEMA,
  DISCOVERY_DOCUMENT_SCHEMA,
  AGENT_KEY_SCHEMA,
  CCL_EVALUATION_CONTEXT_SCHEMA,
  validateCovenantSchema,
  validateDiscoverySchema,
  validateAgentKeySchema,
  getAllSchemas,
} from '../index.js';

// ---------------------------------------------------------------------------
// Reusable fixtures
// ---------------------------------------------------------------------------

const HEX64 = 'a'.repeat(64);
const HEX64_ALT = 'b'.repeat(64);
const HEX128 = 'c'.repeat(128); // valid hex string, just longer
const ISO_NOW = '2025-06-01T12:00:00Z';
const ISO_FUTURE = '2026-06-01T12:00:00Z';

function makeValidCovenant(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: HEX64,
    version: '1.0',
    issuer: { id: 'issuer-1', publicKey: HEX64, role: 'issuer' },
    beneficiary: { id: 'beneficiary-1', publicKey: HEX64_ALT, role: 'beneficiary' },
    constraints: 'ALLOW read ON /data WHEN time < "2030-01-01"',
    nonce: HEX64_ALT,
    createdAt: ISO_NOW,
    signature: HEX128,
    ...overrides,
  };
}

function makeValidDiscovery(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    issuer: 'https://platform.example.com',
    keys_endpoint: 'https://platform.example.com/.well-known/grith/keys',
    covenants_endpoint: 'https://platform.example.com/.well-known/grith/covenants',
    protocol_versions_supported: ['1.0'],
    signature_schemes_supported: ['ed25519'],
    hash_algorithms_supported: ['sha256'],
    updated_at: ISO_NOW,
    ...overrides,
  };
}

function makeValidAgentKey(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kid: HEX64,
    kty: 'Ed25519',
    public_key: HEX64_ALT,
    agent_id: 'agent-42',
    status: 'active',
    created_at: ISO_NOW,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. Schema Structure
// ---------------------------------------------------------------------------

describe('Schema Structure', () => {
  it('COVENANT_SCHEMA has correct $id and $schema', () => {
    expect(COVENANT_SCHEMA.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(COVENANT_SCHEMA.$id).toBe('https://grith.dev/schema/covenant-document.json');
  });

  it('COVENANT_SCHEMA has all required fields listed', () => {
    const required = COVENANT_SCHEMA.required;
    expect(required).toContain('id');
    expect(required).toContain('version');
    expect(required).toContain('issuer');
    expect(required).toContain('beneficiary');
    expect(required).toContain('constraints');
    expect(required).toContain('nonce');
    expect(required).toContain('createdAt');
    expect(required).toContain('signature');
    expect(required).toHaveLength(8);
  });

  it('DISCOVERY_DOCUMENT_SCHEMA has correct structure', () => {
    expect(DISCOVERY_DOCUMENT_SCHEMA.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(DISCOVERY_DOCUMENT_SCHEMA.$id).toBe('https://grith.dev/schema/discovery-document.json');
    expect(DISCOVERY_DOCUMENT_SCHEMA.type).toBe('object');
    expect(DISCOVERY_DOCUMENT_SCHEMA.required).toContain('issuer');
    expect(DISCOVERY_DOCUMENT_SCHEMA.required).toContain('keys_endpoint');
    expect(DISCOVERY_DOCUMENT_SCHEMA.required).toContain('covenants_endpoint');
    expect(DISCOVERY_DOCUMENT_SCHEMA.required).toContain('protocol_versions_supported');
    expect(DISCOVERY_DOCUMENT_SCHEMA.required).toContain('signature_schemes_supported');
    expect(DISCOVERY_DOCUMENT_SCHEMA.required).toContain('hash_algorithms_supported');
    expect(DISCOVERY_DOCUMENT_SCHEMA.required).toContain('updated_at');
  });

  it('AGENT_KEY_SCHEMA has correct structure', () => {
    expect(AGENT_KEY_SCHEMA.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(AGENT_KEY_SCHEMA.$id).toBe('https://grith.dev/schema/agent-key.json');
    expect(AGENT_KEY_SCHEMA.type).toBe('object');
    expect(AGENT_KEY_SCHEMA.required).toContain('kid');
    expect(AGENT_KEY_SCHEMA.required).toContain('kty');
    expect(AGENT_KEY_SCHEMA.required).toContain('public_key');
    expect(AGENT_KEY_SCHEMA.required).toContain('agent_id');
    expect(AGENT_KEY_SCHEMA.required).toContain('status');
    expect(AGENT_KEY_SCHEMA.required).toContain('created_at');
  });

  it('CCL_EVALUATION_CONTEXT_SCHEMA exists and has correct structure', () => {
    expect(CCL_EVALUATION_CONTEXT_SCHEMA.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(CCL_EVALUATION_CONTEXT_SCHEMA.$id).toBe('https://grith.dev/schema/ccl-evaluation-context.json');
    expect(CCL_EVALUATION_CONTEXT_SCHEMA.type).toBe('object');
    expect(CCL_EVALUATION_CONTEXT_SCHEMA.additionalProperties).toBe(true);
  });

  it('all schemas have title and description', () => {
    for (const schema of [
      COVENANT_SCHEMA,
      DISCOVERY_DOCUMENT_SCHEMA,
      AGENT_KEY_SCHEMA,
      CCL_EVALUATION_CONTEXT_SCHEMA,
    ]) {
      expect(schema.title).toBeDefined();
      expect(typeof schema.title).toBe('string');
      expect(schema.title.length).toBeGreaterThan(0);
      expect(schema.description).toBeDefined();
      expect(typeof schema.description).toBe('string');
      expect(schema.description.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Covenant Validation
// ---------------------------------------------------------------------------

describe('Covenant Validation', () => {
  it('valid covenant document passes', () => {
    const result = validateCovenantSchema(makeValidCovenant());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  describe('missing required fields', () => {
    const requiredFields = [
      'id', 'version', 'issuer', 'beneficiary',
      'constraints', 'nonce', 'createdAt', 'signature',
    ];

    for (const field of requiredFields) {
      it(`fails when "${field}" is missing`, () => {
        const doc = makeValidCovenant();
        delete doc[field];
        const result = validateCovenantSchema(doc);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.path.includes(field) && e.message.includes('required'))).toBe(true);
      });
    }
  });

  it('invalid id format fails (not hex64)', () => {
    const result = validateCovenantSchema(makeValidCovenant({ id: 'not-a-hex-string' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'id')).toBe(true);
  });

  it('invalid id format fails (too short hex)', () => {
    const result = validateCovenantSchema(makeValidCovenant({ id: 'abcdef' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'id')).toBe(true);
  });

  it('invalid version format fails', () => {
    const result = validateCovenantSchema(makeValidCovenant({ version: 'v1.0.0' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'version')).toBe(true);
  });

  it('invalid issuer structure fails (missing publicKey)', () => {
    const result = validateCovenantSchema(
      makeValidCovenant({ issuer: { id: 'i', role: 'issuer' } }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path.startsWith('issuer'))).toBe(true);
  });

  it('invalid issuer structure fails (wrong role)', () => {
    const result = validateCovenantSchema(
      makeValidCovenant({
        issuer: { id: 'i', publicKey: HEX64, role: 'beneficiary' },
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path.startsWith('issuer'))).toBe(true);
  });

  it('invalid beneficiary structure fails (missing id)', () => {
    const result = validateCovenantSchema(
      makeValidCovenant({ beneficiary: { publicKey: HEX64_ALT, role: 'beneficiary' } }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path.startsWith('beneficiary'))).toBe(true);
  });

  it('invalid beneficiary structure fails (wrong role)', () => {
    const result = validateCovenantSchema(
      makeValidCovenant({
        beneficiary: { id: 'b', publicKey: HEX64_ALT, role: 'issuer' },
      }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path.startsWith('beneficiary'))).toBe(true);
  });

  it('empty constraints fails', () => {
    const result = validateCovenantSchema(makeValidCovenant({ constraints: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'constraints')).toBe(true);
  });

  it('invalid nonce format fails', () => {
    const result = validateCovenantSchema(makeValidCovenant({ nonce: 'xyz-not-hex' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'nonce')).toBe(true);
  });

  it('invalid createdAt format fails', () => {
    const result = validateCovenantSchema(makeValidCovenant({ createdAt: 'June 1st 2025' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'createdAt')).toBe(true);
  });

  it('invalid signature format fails (non-hex)', () => {
    const result = validateCovenantSchema(makeValidCovenant({ signature: 'zzz-not-hex' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'signature')).toBe(true);
  });

  it('invalid signature format fails (empty string)', () => {
    const result = validateCovenantSchema(makeValidCovenant({ signature: '' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'signature')).toBe(true);
  });

  describe('optional fields when valid', () => {
    it('passes with valid chain', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({
          chain: { parentId: 'some-parent', relation: 'delegates', depth: 1 },
        }),
      );
      expect(result.valid).toBe(true);
    });

    it('passes with valid expiresAt', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({ expiresAt: ISO_FUTURE }),
      );
      expect(result.valid).toBe(true);
    });

    it('passes with valid activatesAt', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({ activatesAt: ISO_NOW }),
      );
      expect(result.valid).toBe(true);
    });

    it('passes with valid metadata', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({
          metadata: { name: 'test', description: 'A test covenant', tags: ['test'] },
        }),
      );
      expect(result.valid).toBe(true);
    });

    it('passes with valid obligations', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({
          obligations: [{ id: 'ob-1', description: 'Must log', action: 'log' }],
        }),
      );
      expect(result.valid).toBe(true);
    });

    it('passes with valid enforcement', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({
          enforcement: { type: 'capability', config: {} },
        }),
      );
      expect(result.valid).toBe(true);
    });

    it('passes with valid proof', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({
          proof: { type: 'tee', config: {} },
        }),
      );
      expect(result.valid).toBe(true);
    });

    it('passes with valid revocation', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({
          revocation: { method: 'crl' },
        }),
      );
      expect(result.valid).toBe(true);
    });

    it('passes with valid countersignatures', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({
          countersignatures: [
            {
              signerPublicKey: HEX64,
              signerRole: 'auditor',
              signature: HEX128,
              timestamp: ISO_NOW,
            },
          ],
        }),
      );
      expect(result.valid).toBe(true);
    });
  });

  describe('optional fields when invalid', () => {
    it('invalid expiresAt format fails', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({ expiresAt: 'not-a-date' }),
      );
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'expiresAt')).toBe(true);
    });

    it('invalid chain structure fails (missing relation)', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({ chain: { parentId: 'p', depth: 1 } }),
      );
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path.startsWith('chain'))).toBe(true);
    });

    it('invalid enforcement type fails', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({ enforcement: { type: 'invalid', config: {} } }),
      );
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path.startsWith('enforcement'))).toBe(true);
    });

    it('invalid proof type fails', () => {
      const result = validateCovenantSchema(
        makeValidCovenant({ proof: { type: 'invalid', config: {} } }),
      );
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path.startsWith('proof'))).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// 3. Discovery Document Validation
// ---------------------------------------------------------------------------

describe('Discovery Document Validation', () => {
  it('valid discovery document passes', () => {
    const result = validateDiscoverySchema(makeValidDiscovery());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  describe('missing required fields', () => {
    const requiredFields = [
      'issuer',
      'keys_endpoint',
      'covenants_endpoint',
      'protocol_versions_supported',
      'signature_schemes_supported',
      'hash_algorithms_supported',
      'updated_at',
    ];

    for (const field of requiredFields) {
      it(`fails when "${field}" is missing`, () => {
        const doc = makeValidDiscovery();
        delete doc[field];
        const result = validateDiscoverySchema(doc);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.path.includes(field) && e.message.includes('required'))).toBe(true);
      });
    }
  });

  it('empty protocol_versions_supported array fails', () => {
    const result = validateDiscoverySchema(
      makeValidDiscovery({ protocol_versions_supported: [] }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'protocol_versions_supported')).toBe(true);
  });

  it('empty signature_schemes_supported array fails', () => {
    const result = validateDiscoverySchema(
      makeValidDiscovery({ signature_schemes_supported: [] }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'signature_schemes_supported')).toBe(true);
  });

  it('empty hash_algorithms_supported array fails', () => {
    const result = validateDiscoverySchema(
      makeValidDiscovery({ hash_algorithms_supported: [] }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'hash_algorithms_supported')).toBe(true);
  });

  it('invalid updated_at format fails', () => {
    const result = validateDiscoverySchema(
      makeValidDiscovery({ updated_at: 'yesterday' }),
    );
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'updated_at')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. Agent Key Validation
// ---------------------------------------------------------------------------

describe('Agent Key Validation', () => {
  it('valid key entry passes', () => {
    const result = validateAgentKeySchema(makeValidAgentKey());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  describe('missing required fields', () => {
    const requiredFields = ['kid', 'kty', 'public_key', 'agent_id', 'status', 'created_at'];

    for (const field of requiredFields) {
      it(`fails when "${field}" is missing`, () => {
        const key = makeValidAgentKey();
        delete key[field];
        const result = validateAgentKeySchema(key);
        expect(result.valid).toBe(false);
        expect(result.errors.some((e) => e.path.includes(field) && e.message.includes('required'))).toBe(true);
      });
    }
  });

  it('invalid status value fails', () => {
    const result = validateAgentKeySchema(makeValidAgentKey({ status: 'suspended' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'status')).toBe(true);
  });

  it('invalid kid format fails (not hex64)', () => {
    const result = validateAgentKeySchema(makeValidAgentKey({ kid: 'short' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'kid')).toBe(true);
  });

  it('invalid kty value fails', () => {
    const result = validateAgentKeySchema(makeValidAgentKey({ kty: 'RSA' }));
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === 'kty')).toBe(true);
  });

  it('valid optional fields pass (expires_at, replaced_by)', () => {
    const result = validateAgentKeySchema(
      makeValidAgentKey({
        expires_at: ISO_FUTURE,
        deactivated_at: ISO_NOW,
        replaced_by: HEX64,
        status: 'rotated',
      }),
    );
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 5. getAllSchemas()
// ---------------------------------------------------------------------------

describe('getAllSchemas()', () => {
  it('returns all four schemas', () => {
    const schemas = getAllSchemas();
    expect(Object.keys(schemas)).toHaveLength(4);
  });

  it('keys are correct', () => {
    const schemas = getAllSchemas();
    expect(schemas).toHaveProperty('covenant-document');
    expect(schemas).toHaveProperty('discovery-document');
    expect(schemas).toHaveProperty('agent-key');
    expect(schemas).toHaveProperty('ccl-evaluation-context');
  });

  it('values reference the actual schema objects', () => {
    const schemas = getAllSchemas();
    expect(schemas['covenant-document']).toBe(COVENANT_SCHEMA);
    expect(schemas['discovery-document']).toBe(DISCOVERY_DOCUMENT_SCHEMA);
    expect(schemas['agent-key']).toBe(AGENT_KEY_SCHEMA);
    expect(schemas['ccl-evaluation-context']).toBe(CCL_EVALUATION_CONTEXT_SCHEMA);
  });
});

// ---------------------------------------------------------------------------
// 6. Edge Cases
// ---------------------------------------------------------------------------

describe('Edge Cases', () => {
  it('null input fails covenant validation', () => {
    const result = validateCovenantSchema(null);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('undefined input fails covenant validation', () => {
    const result = validateCovenantSchema(undefined);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('array input fails covenant validation (not an object)', () => {
    const result = validateCovenantSchema([1, 2, 3]);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('number input fails covenant validation', () => {
    const result = validateCovenantSchema(42);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('string input fails covenant validation', () => {
    const result = validateCovenantSchema('not an object');
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('empty object fails covenant validation (all required fields missing)', () => {
    const result = validateCovenantSchema({});
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBe(8); // 8 required fields
  });

  it('null input fails discovery validation', () => {
    const result = validateDiscoverySchema(null);
    expect(result.valid).toBe(false);
  });

  it('null input fails agent key validation', () => {
    const result = validateAgentKeySchema(null);
    expect(result.valid).toBe(false);
  });

  it('empty object fails agent key validation (all required fields missing)', () => {
    const result = validateAgentKeySchema({});
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBe(6); // 6 required fields
  });

  it('empty object fails discovery validation (all required fields missing)', () => {
    const result = validateDiscoverySchema({});
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBe(7); // 7 required fields
  });
});
