/**
 * @kervyx/discovery/well-known — Discovery document generation and validation.
 *
 * Implements RFC 5785-compliant `.well-known/kervyx/` endpoint handling
 * for the Kervyx cross-platform discovery protocol.
 */

import { sha256String, signString, verify, canonicalizeJson, timestamp, generateNonce, toHex, fromHex } from '@kervyx/crypto';
import type { KeyPair } from '@kervyx/crypto';
import { PROTOCOL_VERSION } from '@kervyx/core';

import type { DiscoveryDocument, AgentKeyEntry, AgentKeySet } from './types.js';

// ─── Constants ───────────────────────────────────────────────────────────────

/** The well-known path prefix for Kervyx discovery. */
export const WELL_KNOWN_PATH = '/.well-known/kervyx';

/** The well-known configuration path. */
export const CONFIGURATION_PATH = `${WELL_KNOWN_PATH}/configuration`;

/** The MIME type for Kervyx discovery documents. */
export const KERVYX_MEDIA_TYPE = 'application/kervyx+json';

/** Maximum age for a discovery document before it should be refreshed (24 hours). */
export const MAX_DOCUMENT_AGE_MS = 86_400_000;

// ─── Discovery Document Builder ─────────────────────────────────────────────

export interface BuildDiscoveryDocumentOptions {
  /** The platform's canonical issuer URL (e.g., "https://platform.example"). */
  issuer: string;

  /** Optional platform name. */
  platformName?: string;

  /** Optional contact URL. */
  contact?: string;

  /** Optional policy URL. */
  policyUrl?: string;

  /** Additional protocol versions supported (1.0 is always included). */
  additionalVersions?: string[];

  /** Additional enforcement types beyond the defaults. */
  additionalEnforcementTypes?: string[];

  /** Additional proof types beyond the defaults. */
  additionalProofTypes?: string[];

  /** Platform key pair for signing the discovery document. */
  signingKeyPair?: KeyPair;
}

/**
 * Build a complete discovery document for a platform.
 *
 * @param options - Configuration for the discovery document.
 * @returns A signed DiscoveryDocument ready to serve at `/.well-known/kervyx/configuration`.
 */
export async function buildDiscoveryDocument(
  options: BuildDiscoveryDocumentOptions,
): Promise<DiscoveryDocument> {
  const issuer = options.issuer.replace(/\/+$/, ''); // Normalize: strip trailing slash

  const versions = [PROTOCOL_VERSION];
  if (options.additionalVersions) {
    for (const v of options.additionalVersions) {
      if (!versions.includes(v)) versions.push(v);
    }
  }

  const enforcementTypes = ['capability', 'monitor', 'audit'];
  if (options.additionalEnforcementTypes) {
    for (const t of options.additionalEnforcementTypes) {
      if (!enforcementTypes.includes(t)) enforcementTypes.push(t);
    }
  }

  const proofTypes = ['capability_manifest', 'audit_log', 'zkp'];
  if (options.additionalProofTypes) {
    for (const t of options.additionalProofTypes) {
      if (!proofTypes.includes(t)) proofTypes.push(t);
    }
  }

  const doc: DiscoveryDocument = {
    issuer,
    keys_endpoint: `${issuer}${WELL_KNOWN_PATH}/keys`,
    covenants_endpoint: `${issuer}${WELL_KNOWN_PATH}/covenants`,
    verification_endpoint: `${issuer}${WELL_KNOWN_PATH}/verify`,
    reputation_endpoint: `${issuer}${WELL_KNOWN_PATH}/reputation`,
    breach_endpoint: `${issuer}${WELL_KNOWN_PATH}/breach`,
    protocol_versions_supported: versions,
    signature_schemes_supported: ['ed25519'],
    hash_algorithms_supported: ['sha256'],
    enforcement_types_supported: enforcementTypes,
    proof_types_supported: proofTypes,
    updated_at: timestamp(),
  };

  if (options.platformName) doc.platform_name = options.platformName;
  if (options.contact) doc.contact = options.contact;
  if (options.policyUrl) doc.policy_url = options.policyUrl;

  // Sign the document if a key pair is provided
  if (options.signingKeyPair) {
    doc.signing_key = options.signingKeyPair.publicKeyHex;
    const canonical = canonicalizeJson({
      ...doc,
      signature: undefined,
      signing_key: doc.signing_key,
    });
    const sigBytes = await signString(canonical, options.signingKeyPair.privateKey);
    doc.signature = toHex(sigBytes);
  }

  return doc;
}

// ─── Discovery Document Validation ──────────────────────────────────────────

export interface DiscoveryValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validate a discovery document's structure and optionally its signature.
 *
 * @param doc - The discovery document to validate.
 * @param options - Validation options.
 * @returns A validation result with any errors.
 */
export async function validateDiscoveryDocument(
  doc: unknown,
  options?: { verifySignature?: boolean },
): Promise<DiscoveryValidationResult> {
  const errors: string[] = [];

  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return { valid: false, errors: ['Discovery document must be a JSON object'] };
  }

  const d = doc as Record<string, unknown>;

  // Required fields
  if (typeof d.issuer !== 'string' || d.issuer.length === 0) {
    errors.push('issuer must be a non-empty string URL');
  }
  if (typeof d.keys_endpoint !== 'string' || d.keys_endpoint.length === 0) {
    errors.push('keys_endpoint must be a non-empty string URL');
  }
  if (typeof d.covenants_endpoint !== 'string' || d.covenants_endpoint.length === 0) {
    errors.push('covenants_endpoint must be a non-empty string URL');
  }
  if (!Array.isArray(d.protocol_versions_supported) || d.protocol_versions_supported.length === 0) {
    errors.push('protocol_versions_supported must be a non-empty array');
  }
  if (!Array.isArray(d.signature_schemes_supported) || d.signature_schemes_supported.length === 0) {
    errors.push('signature_schemes_supported must be a non-empty array');
  }
  if (!Array.isArray(d.hash_algorithms_supported) || d.hash_algorithms_supported.length === 0) {
    errors.push('hash_algorithms_supported must be a non-empty array');
  }
  if (typeof d.updated_at !== 'string') {
    errors.push('updated_at must be a string');
  }

  // Signature verification
  if (options?.verifySignature && d.signature && d.signing_key) {
    const sig = d.signature as string;
    const pubKey = d.signing_key as string;
    const canonical = canonicalizeJson({
      ...d,
      signature: undefined,
      signing_key: pubKey,
    });
    const messageBytes = new TextEncoder().encode(canonical);
    const sigBytes = fromHex(sig);
    const pubKeyBytes = fromHex(pubKey);
    const isValid = await verify(messageBytes, sigBytes, pubKeyBytes);
    if (!isValid) {
      errors.push('Discovery document signature is invalid');
    }
  }

  return { valid: errors.length === 0, errors };
}

// ─── Key Set Builder ─────────────────────────────────────────────────────────

/**
 * Build an agent key entry for the key registry.
 *
 * @param agentId - The agent's identifier.
 * @param publicKey - Hex-encoded Ed25519 public key.
 * @param options - Optional metadata.
 * @returns An AgentKeyEntry ready for the key set.
 */
export function buildKeyEntry(
  agentId: string,
  publicKey: string,
  options?: { expiresAt?: string; status?: AgentKeyEntry['status'] },
): AgentKeyEntry {
  const kid = sha256String(publicKey);
  return {
    kid,
    kty: 'Ed25519',
    public_key: publicKey,
    agent_id: agentId,
    status: options?.status ?? 'active',
    created_at: timestamp(),
    expires_at: options?.expiresAt,
  };
}

/**
 * Build a key set from multiple key entries.
 *
 * @param entries - The key entries to include.
 * @returns An AgentKeySet response.
 */
export function buildKeySet(entries: AgentKeyEntry[]): AgentKeySet {
  return { keys: entries };
}
