/**
 * JSON Schema (Draft 2020-12) for a Kova CovenantDocument.
 *
 * This schema enables any language to validate covenant documents
 * without the TypeScript SDK. It is the machine-readable specification
 * for the covenant format.
 */

/**
 * Reusable schema definitions referenced by the main schema.
 */
const definitions = {
  hex64: {
    type: 'string' as const,
    pattern: '^[0-9a-fA-F]{64}$',
    description: 'A 64-character hexadecimal string (32 bytes)',
  },

  hexString: {
    type: 'string' as const,
    pattern: '^[0-9a-fA-F]+$',
    minLength: 1,
    description: 'A non-empty hexadecimal string',
  },

  iso8601: {
    type: 'string' as const,
    pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})$',
    description: 'An ISO 8601 datetime string',
  },

  semverLike: {
    type: 'string' as const,
    pattern: '^\\d+\\.\\d+$',
    description: 'A version string in "X.Y" format',
  },

  partyRole: {
    type: 'string' as const,
    enum: ['issuer', 'beneficiary', 'auditor', 'operator', 'regulator'],
    description: 'Role a party plays in a covenant',
  },

  party: {
    type: 'object' as const,
    properties: {
      id: { type: 'string' as const, minLength: 1, description: 'Unique identifier for this party' },
      publicKey: { type: 'string' as const, pattern: '^[0-9a-fA-F]{64}$', description: 'Hex-encoded Ed25519 public key (32 bytes)' },
      role: { type: 'string' as const, description: 'The role this party plays' },
      name: { type: 'string' as const, description: 'Optional human-readable name' },
      metadata: { type: 'object' as const, description: 'Arbitrary metadata attached to the party' },
    },
    required: ['id', 'publicKey', 'role'] as const,
    additionalProperties: true,
    description: 'A participant in a covenant',
  },

  chainReference: {
    type: 'object' as const,
    properties: {
      parentId: { type: 'string' as const, minLength: 1, description: 'SHA-256 ID of the parent covenant document' },
      relation: {
        type: 'string' as const,
        enum: ['delegates', 'restricts', 'extends'],
        description: 'How this covenant relates to the parent',
      },
      depth: { type: 'integer' as const, minimum: 1, maximum: 16, description: 'Depth in the chain (1-16)' },
    },
    required: ['parentId', 'relation', 'depth'] as const,
    additionalProperties: false,
    description: 'Reference to a parent covenant in a delegation chain',
  },

  enforcementConfig: {
    type: 'object' as const,
    properties: {
      type: {
        type: 'string' as const,
        enum: ['capability', 'monitor', 'audit', 'bond', 'composite'],
        description: 'The enforcement mechanism type',
      },
      config: { type: 'object' as const, description: 'Type-specific configuration parameters' },
      description: { type: 'string' as const, description: 'Human-readable description' },
    },
    required: ['type', 'config'] as const,
    additionalProperties: false,
    description: 'Runtime enforcement configuration',
  },

  proofConfig: {
    type: 'object' as const,
    properties: {
      type: {
        type: 'string' as const,
        enum: ['tee', 'capability_manifest', 'audit_log', 'bond_reference', 'zkp', 'composite'],
        description: 'The proof mechanism type',
      },
      config: { type: 'object' as const, description: 'Type-specific configuration parameters' },
      description: { type: 'string' as const, description: 'Human-readable description' },
    },
    required: ['type', 'config'] as const,
    additionalProperties: false,
    description: 'Compliance proof configuration',
  },

  revocationConfig: {
    type: 'object' as const,
    properties: {
      method: {
        type: 'string' as const,
        enum: ['crl', 'status_endpoint', 'onchain'],
        description: 'The revocation method',
      },
      endpoint: { type: 'string' as const, description: 'URL endpoint for revocation checking' },
      config: { type: 'object' as const, description: 'Method-specific configuration parameters' },
    },
    required: ['method'] as const,
    additionalProperties: false,
    description: 'Revocation configuration',
  },

  obligation: {
    type: 'object' as const,
    properties: {
      id: { type: 'string' as const, minLength: 1, description: 'Unique identifier for this obligation' },
      description: { type: 'string' as const, minLength: 1, description: 'Human-readable description' },
      action: { type: 'string' as const, minLength: 1, description: 'The action required to fulfill the obligation' },
      deadline: {
        type: 'string' as const,
        pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})$',
        description: 'Optional deadline (ISO 8601)',
      },
    },
    required: ['id', 'description', 'action'] as const,
    additionalProperties: false,
    description: 'An obligation that must be fulfilled as part of the covenant',
  },

  covenantMetadata: {
    type: 'object' as const,
    properties: {
      name: { type: 'string' as const, description: 'Human-readable name' },
      description: { type: 'string' as const, description: 'Human-readable description' },
      tags: {
        type: 'array' as const,
        items: { type: 'string' as const },
        description: 'Searchable tags',
      },
      version: { type: 'string' as const, description: 'Semantic version of the covenant content' },
      custom: { type: 'object' as const, description: 'Arbitrary custom metadata' },
    },
    additionalProperties: false,
    description: 'Optional metadata attached to a covenant document',
  },

  countersignature: {
    type: 'object' as const,
    properties: {
      signerPublicKey: { type: 'string' as const, pattern: '^[0-9a-fA-F]+$', minLength: 1, description: 'Hex-encoded public key of the countersigner' },
      signerRole: { type: 'string' as const, enum: ['issuer', 'beneficiary', 'auditor', 'operator', 'regulator'], description: 'Role of the countersigner' },
      signature: { type: 'string' as const, pattern: '^[0-9a-fA-F]+$', minLength: 1, description: 'Hex-encoded Ed25519 signature' },
      timestamp: {
        type: 'string' as const,
        pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:?\\d{2})$',
        description: 'ISO 8601 timestamp of the countersignature',
      },
    },
    required: ['signerPublicKey', 'signerRole', 'signature', 'timestamp'] as const,
    additionalProperties: false,
    description: 'A countersignature from a third party',
  },
};

/**
 * The complete JSON Schema for a Kova CovenantDocument.
 *
 * Conforms to JSON Schema Draft 2020-12 (https://json-schema.org/draft/2020-12/schema).
 *
 * @example
 * ```typescript
 * import Ajv from 'ajv';
 * import { COVENANT_SCHEMA } from '@usekova/schema';
 *
 * const ajv = new Ajv();
 * const validate = ajv.compile(COVENANT_SCHEMA);
 * const isValid = validate(covenantDocument);
 * ```
 */
export const COVENANT_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://usekova.dev/schema/covenant-document.json',
  title: 'Kova Covenant Document',
  description: 'A complete, signed Kova Covenant document. The covenant is the fundamental unit of the Kova protocol — a cryptographically signed behavioral commitment between an issuer and a beneficiary.',
  type: 'object' as const,

  properties: {
    id: {
      ...definitions.hex64,
      description: 'SHA-256 hash of the canonical form, serving as the document ID',
    },
    version: {
      ...definitions.semverLike,
      description: 'Protocol version (e.g., "1.0")',
    },
    issuer: {
      ...definitions.party,
      description: 'The issuer who created and signed this covenant',
      properties: {
        ...definitions.party.properties,
        role: { type: 'string' as const, const: 'issuer' as const },
      },
    },
    beneficiary: {
      ...definitions.party,
      description: 'The beneficiary bound by this covenant',
      properties: {
        ...definitions.party.properties,
        role: { type: 'string' as const, const: 'beneficiary' as const },
      },
    },
    constraints: {
      type: 'string' as const,
      minLength: 1,
      description: 'CCL (Covenant Constraint Language) source text defining permissions, denials, requirements, and rate limits',
    },
    obligations: {
      type: 'array' as const,
      items: definitions.obligation,
      description: 'Optional list of obligations that must be fulfilled',
    },
    chain: {
      ...definitions.chainReference,
      description: 'Optional reference to a parent covenant in a delegation chain',
    },
    enforcement: definitions.enforcementConfig,
    proof: definitions.proofConfig,
    revocation: definitions.revocationConfig,
    metadata: definitions.covenantMetadata,
    nonce: {
      ...definitions.hex64,
      description: 'Hex-encoded 32-byte nonce for replay protection',
    },
    createdAt: {
      ...definitions.iso8601,
      description: 'ISO 8601 timestamp of document creation',
    },
    expiresAt: {
      ...definitions.iso8601,
      description: 'Optional ISO 8601 expiry timestamp',
    },
    activatesAt: {
      ...definitions.iso8601,
      description: 'Optional ISO 8601 activation timestamp',
    },
    signature: {
      ...definitions.hexString,
      description: 'Hex-encoded Ed25519 signature of the issuer over the canonical form',
    },
    countersignatures: {
      type: 'array' as const,
      items: definitions.countersignature,
      description: 'Optional list of countersignatures from third parties',
    },
  },

  required: [
    'id', 'version', 'issuer', 'beneficiary', 'constraints',
    'nonce', 'createdAt', 'signature',
  ] as const,

  additionalProperties: false,
} as const;

/**
 * JSON Schema for the Discovery Document.
 */
export const DISCOVERY_DOCUMENT_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://usekova.dev/schema/discovery-document.json',
  title: 'Kova Discovery Document',
  description: 'A platform discovery document served at /.well-known/kova/configuration. Enables cross-platform agent verification and protocol negotiation.',
  type: 'object' as const,

  properties: {
    issuer: { type: 'string' as const, minLength: 1, description: 'The platform\'s canonical issuer URL' },
    keys_endpoint: { type: 'string' as const, minLength: 1, description: 'URL of the JWKS-like endpoint listing agent public keys' },
    covenants_endpoint: { type: 'string' as const, minLength: 1, description: 'URL of the covenant registry endpoint' },
    verification_endpoint: { type: 'string' as const, description: 'URL of the verification endpoint' },
    reputation_endpoint: { type: 'string' as const, description: 'URL of the reputation query endpoint' },
    breach_endpoint: { type: 'string' as const, description: 'URL of the breach reporting endpoint' },
    protocol_versions_supported: {
      type: 'array' as const,
      items: { type: 'string' as const },
      minItems: 1,
      description: 'Kova protocol versions supported',
    },
    signature_schemes_supported: {
      type: 'array' as const,
      items: { type: 'string' as const },
      minItems: 1,
      description: 'Signature schemes supported (e.g., ["ed25519"])',
    },
    hash_algorithms_supported: {
      type: 'array' as const,
      items: { type: 'string' as const },
      minItems: 1,
      description: 'Hash algorithms supported (e.g., ["sha256"])',
    },
    enforcement_types_supported: {
      type: 'array' as const,
      items: { type: 'string' as const },
      description: 'Enforcement types supported',
    },
    proof_types_supported: {
      type: 'array' as const,
      items: { type: 'string' as const },
      description: 'Proof types supported',
    },
    platform_name: { type: 'string' as const, description: 'Human-readable platform name' },
    contact: { type: 'string' as const, description: 'Platform operator contact URL' },
    policy_url: { type: 'string' as const, description: 'URL to the platform\'s policy/terms' },
    updated_at: { ...definitions.iso8601, description: 'ISO 8601 timestamp when this document was last updated' },
    signature: { ...definitions.hexString, description: 'Hex-encoded Ed25519 signature of the platform over this document' },
    signing_key: { ...definitions.hex64, description: 'Platform\'s public key used to sign the discovery document' },
  },

  required: [
    'issuer', 'keys_endpoint', 'covenants_endpoint',
    'protocol_versions_supported', 'signature_schemes_supported',
    'hash_algorithms_supported', 'updated_at',
  ] as const,

  additionalProperties: true,
} as const;

/**
 * JSON Schema for the Agent Key Entry (JWKS-like).
 */
export const AGENT_KEY_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://usekova.dev/schema/agent-key.json',
  title: 'Kova Agent Key Entry',
  description: 'A single agent key entry in the key registry (like a JWK but for Ed25519).',
  type: 'object' as const,

  properties: {
    kid: { ...definitions.hex64, description: 'Unique key identifier (SHA-256 of the public key)' },
    kty: { type: 'string' as const, const: 'Ed25519' as const, description: 'Key type (always "Ed25519")' },
    public_key: { ...definitions.hex64, description: 'Hex-encoded Ed25519 public key' },
    agent_id: { type: 'string' as const, minLength: 1, description: 'Agent identifier this key belongs to' },
    status: { type: 'string' as const, enum: ['active', 'rotated', 'revoked'], description: 'Key status' },
    created_at: { ...definitions.iso8601, description: 'ISO 8601 timestamp when this key was registered' },
    expires_at: { ...definitions.iso8601, description: 'ISO 8601 timestamp when this key expires' },
    deactivated_at: { ...definitions.iso8601, description: 'ISO 8601 timestamp when this key was rotated/revoked' },
    replaced_by: { ...definitions.hex64, description: 'Key that replaced this one (for rotation chains)' },
  },

  required: ['kid', 'kty', 'public_key', 'agent_id', 'status', 'created_at'] as const,
  additionalProperties: false,
} as const;

/**
 * JSON Schema for CCL document structure (the parsed form, not the text).
 */
export const CCL_EVALUATION_CONTEXT_SCHEMA = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://usekova.dev/schema/ccl-evaluation-context.json',
  title: 'CCL Evaluation Context',
  description: 'Context object passed to CCL evaluation for condition checking.',
  type: 'object' as const,
  additionalProperties: true,
} as const;
