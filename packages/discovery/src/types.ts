/**
 * @grith/discovery — Types for the Grith cross-platform discovery protocol.
 *
 * Defines the `.well-known/grith/` endpoint format, key discovery (JWKS-like),
 * protocol version negotiation, and cross-platform covenant resolution.
 *
 * @packageDocumentation
 */

// ─── Discovery Document ─────────────────────────────────────────────────────

/**
 * The discovery document served at `/.well-known/grith/configuration`.
 *
 * Modeled after OAuth 2.0 Authorization Server Metadata (RFC 8414)
 * and OpenID Connect Discovery. This is the entry point for any
 * cross-platform verification flow.
 *
 * @example
 * ```
 * GET https://platform.example/.well-known/grith/configuration
 * Content-Type: application/grith+json
 * ```
 */
export interface DiscoveryDocument {
  /** The platform's canonical issuer URL (MUST match the request origin). */
  issuer: string;

  /** URL of the JWKS-like endpoint listing agent public keys. */
  keys_endpoint: string;

  /** URL of the covenant registry endpoint. */
  covenants_endpoint: string;

  /** URL of the verification endpoint (for delegated verification). */
  verification_endpoint?: string;

  /** URL of the reputation query endpoint. */
  reputation_endpoint?: string;

  /** URL of the breach reporting endpoint. */
  breach_endpoint?: string;

  /** Grith protocol versions supported by this platform. */
  protocol_versions_supported: string[];

  /** Signature schemes supported (e.g., ["ed25519"]). */
  signature_schemes_supported: string[];

  /** Hash algorithms supported (e.g., ["sha256"]). */
  hash_algorithms_supported: string[];

  /** Enforcement types supported by this platform. */
  enforcement_types_supported: string[];

  /** Proof types supported by this platform. */
  proof_types_supported: string[];

  /** Human-readable platform name. */
  platform_name?: string;

  /** Platform operator contact URL. */
  contact?: string;

  /** URL to the platform's policy/terms. */
  policy_url?: string;

  /** ISO 8601 timestamp when this document was last updated. */
  updated_at: string;

  /** Hex-encoded Ed25519 signature of the platform over this document. */
  signature?: string;

  /** Platform's public key used to sign the discovery document. */
  signing_key?: string;
}

// ─── Key Set ─────────────────────────────────────────────────────────────────

/**
 * A single agent key entry in the key registry (like a JWK but for Ed25519).
 */
export interface AgentKeyEntry {
  /** Unique key identifier (hex-encoded SHA-256 of the public key). */
  kid: string;

  /** Key type (always "Ed25519" for Grith). */
  kty: 'Ed25519';

  /** Hex-encoded Ed25519 public key. */
  public_key: string;

  /** Agent identifier this key belongs to. */
  agent_id: string;

  /** Key status. */
  status: 'active' | 'rotated' | 'revoked';

  /** ISO 8601 timestamp when this key was registered. */
  created_at: string;

  /** ISO 8601 timestamp when this key expires (if applicable). */
  expires_at?: string;

  /** ISO 8601 timestamp when this key was rotated/revoked (if applicable). */
  deactivated_at?: string;

  /** Key that replaced this one (for rotation chains). */
  replaced_by?: string;
}

/**
 * A key set response from the keys endpoint (like JWKS).
 */
export interface AgentKeySet {
  /** Array of key entries. */
  keys: AgentKeyEntry[];
}

// ─── Covenant Registry ───────────────────────────────────────────────────────

/**
 * A covenant registry entry returned from the covenants endpoint.
 */
export interface CovenantRegistryEntry {
  /** The covenant document ID (SHA-256 hash). */
  id: string;

  /** The issuer's agent ID. */
  issuer_id: string;

  /** The beneficiary's agent ID. */
  beneficiary_id: string;

  /** ISO 8601 creation timestamp. */
  created_at: string;

  /** ISO 8601 expiry timestamp (if applicable). */
  expires_at?: string;

  /** Current status of the covenant. */
  status: 'active' | 'expired' | 'revoked';

  /** Protocol version used for this covenant. */
  protocol_version: string;

  /** URL to fetch the full covenant document. */
  document_url: string;
}

/**
 * Response from the covenants endpoint.
 */
export interface CovenantRegistryResponse {
  /** Array of covenant entries. */
  covenants: CovenantRegistryEntry[];

  /** Total count of covenants matching the query. */
  total: number;

  /** Pagination cursor for the next page (if applicable). */
  next_cursor?: string;
}

// ─── Protocol Negotiation ────────────────────────────────────────────────────

/**
 * A protocol negotiation request sent by one platform to another.
 */
export interface NegotiationRequest {
  /** The requesting platform's issuer URL. */
  from: string;

  /** The target platform's issuer URL. */
  to: string;

  /** Protocol versions the requesting platform supports. */
  protocol_versions: string[];

  /** Signature schemes the requesting platform supports. */
  signature_schemes: string[];

  /** Hash algorithms the requesting platform supports. */
  hash_algorithms: string[];

  /** ISO 8601 timestamp of the request. */
  timestamp: string;

  /** Hex-encoded nonce for replay protection. */
  nonce: string;

  /** Hex-encoded Ed25519 signature over the canonical form. */
  signature?: string;
}

/**
 * A protocol negotiation response.
 */
export interface NegotiationResponse {
  /** Whether negotiation succeeded. */
  accepted: boolean;

  /** The agreed-upon protocol version (if accepted). */
  agreed_version?: string;

  /** The agreed-upon signature scheme (if accepted). */
  agreed_signature_scheme?: string;

  /** The agreed-upon hash algorithm (if accepted). */
  agreed_hash_algorithm?: string;

  /** The responding platform's keys endpoint for key exchange. */
  keys_endpoint?: string;

  /** Reason for rejection (if not accepted). */
  rejection_reason?: string;

  /** ISO 8601 timestamp of the response. */
  timestamp: string;

  /** Hex-encoded nonce matching the request. */
  nonce: string;

  /** Hex-encoded Ed25519 signature over the canonical form. */
  signature?: string;
}

// ─── Cross-Platform Verification ─────────────────────────────────────────────

/**
 * A cross-platform verification request.
 *
 * When Agent A (on Platform X) needs to verify Agent B's covenant
 * (on Platform Y), Platform X sends this request to Platform Y's
 * verification endpoint.
 */
export interface CrossPlatformVerificationRequest {
  /** The covenant document ID to verify. */
  covenant_id: string;

  /** The requesting platform's issuer URL. */
  requesting_platform: string;

  /** Optional: specific verification checks to perform. */
  checks?: string[];

  /** ISO 8601 timestamp. */
  timestamp: string;

  /** Hex-encoded nonce. */
  nonce: string;
}

/**
 * A cross-platform verification response.
 */
export interface CrossPlatformVerificationResponse {
  /** The covenant document ID that was verified. */
  covenant_id: string;

  /** Whether the covenant is valid. */
  valid: boolean;

  /** Detailed check results. */
  checks: Array<{
    name: string;
    passed: boolean;
    message?: string;
  }>;

  /** The full covenant document (if requested and available). */
  document?: Record<string, unknown>;

  /** ISO 8601 timestamp. */
  timestamp: string;

  /** Hex-encoded Ed25519 signature over the response. */
  signature?: string;
}

// ─── Fetch Options ───────────────────────────────────────────────────────────

/**
 * Options for the discovery client's fetch operations.
 */
export interface FetchOptions {
  /** Request timeout in milliseconds (default: 10000). */
  timeout?: number;

  /** Custom headers to include. */
  headers?: Record<string, string>;

  /** Whether to verify the discovery document's signature. */
  verifySignature?: boolean;

  /** Cache TTL in milliseconds (default: 300000 = 5 minutes). */
  cacheTtl?: number;
}
