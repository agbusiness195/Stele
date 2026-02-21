/**
 * Certification authority for the Grith protocol.
 *
 * Certifies agents like UL certifies electronics. Agents earn certificates
 * at basic, standard, or enterprise tiers based on trust history, attestation
 * counts, and audit requirements. Certificates can be issued, revoked, and
 * verified.
 *
 * @packageDocumentation
 */

// ─── Types ───────────────────────────────────────────────────────────────────

/** A certificate issued to an agent. */
export interface Certificate {
  /** Unique identifier for the certificate. */
  id: string;
  /** The agent this certificate was issued to. */
  agentId: string;
  /** Timestamp when the certificate was issued. */
  issuedAt: number;
  /** Timestamp when the certificate expires. */
  expiresAt: number;
  /** The certification tier. */
  tier: 'basic' | 'standard' | 'enterprise';
  /** Capabilities the certificate covers. */
  scope: string[];
  /** Digital signature from the issuing authority. */
  issuerSignature: string;
  /** Current status of the certificate. */
  status: 'active' | 'suspended' | 'revoked' | 'expired';
  /** Whether the certificate can be renewed. */
  renewalEligible: boolean;
}

/** A certification authority that issues and manages certificates. */
export interface CertificationAuthority {
  /** Unique identifier for the authority. */
  authorityId: string;
  /** Human-readable name of the authority. */
  name: string;
  /** Public key for verifying the authority's signatures. */
  publicKey: string;
  /** Total number of certificates issued. */
  issuedCertificates: number;
  /** Total number of certificates revoked. */
  revokedCertificates: number;
  /** Trust level of the authority (0-1). */
  trustLevel: number;
}

/** Requirements for earning a certificate at a given tier. */
export interface CertificationRequirements {
  /** The tier these requirements apply to. */
  tier: Certificate['tier'];
  /** Minimum trust score required. */
  minimumTrustScore: number;
  /** Minimum number of days of operational history. */
  minimumHistoryDays: number;
  /** Minimum number of attestations required. */
  requiredAttestations: number;
  /** Whether a formal audit is required. */
  auditRequired: boolean;
  /** Number of days before the certificate must be renewed. */
  renewalPeriodDays: number;
}

// ─── Requirements ────────────────────────────────────────────────────────────

/** Certification requirements for each tier. */
export const CERTIFICATION_REQUIREMENTS: Record<Certificate['tier'], CertificationRequirements> = {
  basic: {
    tier: 'basic',
    minimumTrustScore: 0.5,
    minimumHistoryDays: 30,
    requiredAttestations: 10,
    auditRequired: false,
    renewalPeriodDays: 365,
  },
  standard: {
    tier: 'standard',
    minimumTrustScore: 0.7,
    minimumHistoryDays: 90,
    requiredAttestations: 50,
    auditRequired: true,
    renewalPeriodDays: 180,
  },
  enterprise: {
    tier: 'enterprise',
    minimumTrustScore: 0.9,
    minimumHistoryDays: 180,
    requiredAttestations: 200,
    auditRequired: true,
    renewalPeriodDays: 90,
  },
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Simple deterministic hash for certificate IDs. */
function hashCertificateId(agentId: string, issuedAt: number, tier: string): string {
  // Simple hash: combine agent, time, and tier into a hex-like string
  let hash = 0;
  const input = `${agentId}:${issuedAt}:${tier}`;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return `cert-${Math.abs(hash).toString(16).padStart(8, '0')}`;
}

// ─── Authority Factory ───────────────────────────────────────────────────────

/**
 * Create a new certification authority.
 *
 * @param params - Authority identity parameters.
 * @returns A new CertificationAuthority with zero issued/revoked certificates.
 */
export function createAuthority(params: {
  authorityId: string;
  name: string;
  publicKey: string;
}): CertificationAuthority {
  return {
    authorityId: params.authorityId,
    name: params.name,
    publicKey: params.publicKey,
    issuedCertificates: 0,
    revokedCertificates: 0,
    trustLevel: 1.0,
  };
}

// ─── Certificate Issuance ────────────────────────────────────────────────────

/**
 * Issue a certificate to an agent after validating tier requirements.
 *
 * Checks the agent's trust score, operational history, and attestation count
 * against the requirements for the requested tier. If any requirement is not
 * met, an error is returned instead of a certificate.
 *
 * @param authority - The issuing certification authority.
 * @param params - Agent data and requested tier.
 * @returns A certificate and updated authority, or an error message.
 */
export function issueCertificate(
  authority: CertificationAuthority,
  params: {
    agentId: string;
    tier: Certificate['tier'];
    scope: string[];
    trustScore: number;
    historyDays: number;
    attestationCount: number;
  },
): { certificate: Certificate; authority: CertificationAuthority } | { error: string } {
  const requirements = CERTIFICATION_REQUIREMENTS[params.tier];

  // Validate trust score
  if (params.trustScore < requirements.minimumTrustScore) {
    return {
      error: `Trust score ${params.trustScore} below minimum ${requirements.minimumTrustScore} for ${params.tier} tier`,
    };
  }

  // Validate history
  if (params.historyDays < requirements.minimumHistoryDays) {
    return {
      error: `History ${params.historyDays} days below minimum ${requirements.minimumHistoryDays} for ${params.tier} tier`,
    };
  }

  // Validate attestations
  if (params.attestationCount < requirements.requiredAttestations) {
    return {
      error: `Attestation count ${params.attestationCount} below minimum ${requirements.requiredAttestations} for ${params.tier} tier`,
    };
  }

  const issuedAt = Date.now();
  const expiresAt = issuedAt + requirements.renewalPeriodDays * 86400000;

  const certificate: Certificate = {
    id: hashCertificateId(params.agentId, issuedAt, params.tier),
    agentId: params.agentId,
    issuedAt,
    expiresAt,
    tier: params.tier,
    scope: [...params.scope],
    issuerSignature: `sig-${authority.authorityId}-${issuedAt}`,
    status: 'active',
    renewalEligible: true,
  };

  const updatedAuthority: CertificationAuthority = {
    ...authority,
    issuedCertificates: authority.issuedCertificates + 1,
  };

  return { certificate, authority: updatedAuthority };
}

// ─── Certificate Revocation ──────────────────────────────────────────────────

/**
 * Revoke a certificate, permanently marking it invalid.
 *
 * @param authority - The certification authority revoking the certificate.
 * @param certificate - The certificate to revoke.
 * @param _reason - Reason for revocation (for audit purposes).
 * @returns The revoked certificate and updated authority.
 */
export function revokeCertificate(
  authority: CertificationAuthority,
  certificate: Certificate,
  _reason: string,
): { certificate: Certificate; authority: CertificationAuthority } {
  const revokedCertificate: Certificate = {
    ...certificate,
    status: 'revoked',
    renewalEligible: false,
  };

  const updatedAuthority: CertificationAuthority = {
    ...authority,
    revokedCertificates: authority.revokedCertificates + 1,
  };

  return { certificate: revokedCertificate, authority: updatedAuthority };
}

// ─── Certificate Verification ────────────────────────────────────────────────

/**
 * Verify a certificate's validity based on its status and expiration.
 *
 * @param certificate - The certificate to verify.
 * @returns An object with `valid` and `reason` fields.
 */
export function verifyCertificate(certificate: Certificate): { valid: boolean; reason: string } {
  if (certificate.status === 'revoked') {
    return { valid: false, reason: 'Certificate has been revoked' };
  }

  if (certificate.status === 'suspended') {
    return { valid: false, reason: 'Certificate is suspended' };
  }

  if (certificate.status === 'expired' || certificate.expiresAt < Date.now()) {
    return { valid: false, reason: 'Certificate has expired' };
  }

  if (certificate.status !== 'active') {
    return { valid: false, reason: `Certificate status is ${certificate.status}` };
  }

  return { valid: true, reason: 'Certificate is valid and active' };
}
