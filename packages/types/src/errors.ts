/**
 * Comprehensive error code system for the Kervyx SDK.
 *
 * Every error has a unique, documentable code (KERVYX_Exxx) that maps
 * to a specific, documented failure mode. This enables structured error
 * handling, logging, and user-facing diagnostics.
 *
 * @packageDocumentation
 */

// ─── Error codes ────────────────────────────────────────────────────────────────

/** All Kervyx error codes. Each maps to a specific, documented failure mode. */
export enum KervyxErrorCode {
  // Key management (1xx)
  /** A required private key was not provided or not available. */
  NO_PRIVATE_KEY = 'KERVYX_E100',
  /** A required key pair was not provided or not available. */
  NO_KEY_PAIR = 'KERVYX_E101',
  /** The key size does not meet the required specification. */
  INVALID_KEY_SIZE = 'KERVYX_E102',
  /** The key has exceeded its validity period and must be rotated. */
  KEY_ROTATION_REQUIRED = 'KERVYX_E103',

  // Covenant building (2xx)
  /** The issuer field is required but was not provided. */
  MISSING_ISSUER = 'KERVYX_E200',
  /** The beneficiary field is required but was not provided. */
  MISSING_BENEFICIARY = 'KERVYX_E201',
  /** At least one constraint must be specified. */
  EMPTY_CONSTRAINTS = 'KERVYX_E202',
  /** The expiry date is invalid (e.g., in the past or malformed). */
  INVALID_EXPIRY = 'KERVYX_E203',
  /** The constraints payload exceeds the maximum allowed size. */
  CONSTRAINTS_TOO_LARGE = 'KERVYX_E204',
  /** The document exceeds the maximum allowed size. */
  DOCUMENT_TOO_LARGE = 'KERVYX_E205',

  // Verification (3xx)
  /** The cryptographic signature did not verify. */
  SIGNATURE_INVALID = 'KERVYX_E300',
  /** The document ID does not match the expected value. */
  ID_MISMATCH = 'KERVYX_E301',
  /** The document or token has expired. */
  EXPIRED = 'KERVYX_E302',
  /** The document or token is not yet active (notBefore date in the future). */
  NOT_YET_ACTIVE = 'KERVYX_E303',
  /** The delegation chain exceeds the maximum allowed depth. */
  CHAIN_DEPTH_EXCEEDED = 'KERVYX_E304',
  /** The protocol version is not supported. */
  VERSION_UNSUPPORTED = 'KERVYX_E305',

  // CCL (4xx)
  /** The CCL constraint text contains a syntax error. */
  CCL_SYNTAX_ERROR = 'KERVYX_E400',
  /** The CCL input was empty or missing. */
  CCL_EMPTY_INPUT = 'KERVYX_E401',
  /** The action specified in the CCL rule is not valid. */
  CCL_INVALID_ACTION = 'KERVYX_E402',
  /** The resource specified in the CCL rule is not valid. */
  CCL_INVALID_RESOURCE = 'KERVYX_E403',
  /** A chain narrowing validation detected a broadening violation. */
  CCL_NARROWING_VIOLATION = 'KERVYX_E404',

  // Store (5xx)
  /** The document was expected but not provided to the store operation. */
  STORE_MISSING_DOC = 'KERVYX_E500',
  /** The document ID was expected but not provided. */
  STORE_MISSING_ID = 'KERVYX_E501',
  /** The requested document was not found in the store. */
  STORE_NOT_FOUND = 'KERVYX_E502',
  /** The store write operation failed. */
  STORE_WRITE_FAILED = 'KERVYX_E503',

  // Identity (6xx)
  /** The identity document or format is invalid. */
  IDENTITY_INVALID = 'KERVYX_E600',
  /** An identity evolution operation failed. */
  IDENTITY_EVOLUTION_FAILED = 'KERVYX_E601',

  // Rate limiting / enforcement (7xx)
  /** The rate limit for the operation has been exceeded. */
  RATE_LIMIT_EXCEEDED = 'KERVYX_E700',
  /** The action was denied by enforcement policy. */
  ACTION_DENIED = 'KERVYX_E701',
  /** The audit chain integrity check failed (corrupted or tampered). */
  AUDIT_CHAIN_CORRUPTED = 'KERVYX_E702',

  // Auth (8xx)
  /** Authentication is required but was not provided. */
  AUTH_REQUIRED = 'KERVYX_E800',
  /** The provided authentication key is invalid. */
  AUTH_INVALID_KEY = 'KERVYX_E801',
  /** Authentication attempts have been rate limited. */
  AUTH_RATE_LIMITED = 'KERVYX_E802',

  // Crypto (9xx)
  /** A hex-encoded string was malformed or invalid. */
  CRYPTO_INVALID_HEX = 'KERVYX_E900',
  /** A cryptographic key was invalid or malformed. */
  CRYPTO_INVALID_KEY = 'KERVYX_E901',
  /** A cryptographic signing operation failed. */
  CRYPTO_SIGNATURE_FAILED = 'KERVYX_E902',

  // Reputation (91x)
  /** A reputation receipt was invalid or malformed. */
  REPUTATION_INVALID_RECEIPT = 'KERVYX_E910',
  /** A reputation computation failed. */
  REPUTATION_COMPUTATION_FAILED = 'KERVYX_E911',

  // Breach (92x)
  /** A breach attestation was invalid or malformed. */
  BREACH_INVALID_ATTESTATION = 'KERVYX_E920',
  /** A breach severity value was invalid. */
  BREACH_INVALID_SEVERITY = 'KERVYX_E921',

  // Attestation (93x)
  /** An attestation was invalid or malformed. */
  ATTESTATION_INVALID = 'KERVYX_E930',
  /** An attestation reconciliation operation failed. */
  ATTESTATION_RECONCILIATION_FAILED = 'KERVYX_E931',

  // Protocol general (94x)
  /** A protocol input was invalid or malformed. */
  PROTOCOL_INVALID_INPUT = 'KERVYX_E940',
  /** A protocol computation failed. */
  PROTOCOL_COMPUTATION_FAILED = 'KERVYX_E941',
}

// ─── Error class ────────────────────────────────────────────────────────────────

/** Options for constructing a KervyxError. */
export interface KervyxErrorOptions {
  /** Additional structured context for diagnostics and logging. */
  context?: Record<string, unknown>;
  /** A human-readable hint suggesting how to resolve the error. */
  hint?: string;
  /** The underlying cause of this error, for error chaining. */
  cause?: Error;
}

/**
 * Base error class for all Kervyx errors.
 *
 * Includes a unique error code, optional context for structured logging,
 * and an optional hint for user-facing diagnostics.
 *
 * @example
 * ```typescript
 * throw new KervyxError(
 *   KervyxErrorCode.MISSING_ISSUER,
 *   'Covenant requires an issuer',
 *   { hint: 'Set the issuer field before calling build()' }
 * );
 * ```
 */
export class KervyxError extends Error {
  readonly code: KervyxErrorCode;
  readonly context?: Record<string, unknown>;
  readonly hint?: string;

  constructor(code: KervyxErrorCode, message: string, options?: KervyxErrorOptions) {
    super(message, options?.cause ? { cause: options.cause } : undefined);
    this.name = 'KervyxError';
    this.code = code;
    this.context = options?.context;
    this.hint = options?.hint;
  }

  /**
   * Return a structured JSON representation suitable for logging.
   *
   * Includes the error code, message, and optionally the hint and context.
   */
  toJSON(): { code: string; message: string; hint?: string; context?: Record<string, unknown> } {
    const result: { code: string; message: string; hint?: string; context?: Record<string, unknown> } = {
      code: this.code,
      message: this.message,
    };
    if (this.hint !== undefined) {
      result.hint = this.hint;
    }
    if (this.context !== undefined) {
      result.context = this.context;
    }
    return result;
  }
}

// ─── Utility functions ──────────────────────────────────────────────────────────

/** Base URL for error documentation pages. */
const DOCS_BASE_URL = 'https://kervyx.dev/errors';

/**
 * Look up the documentation URL for an error code.
 *
 * @param code - The Kervyx error code.
 * @returns A URL pointing to the documentation page for this error code.
 *
 * @example
 * ```typescript
 * errorDocsUrl(KervyxErrorCode.MISSING_ISSUER)
 * // => 'https://kervyx.dev/errors/KERVYX_E200'
 * ```
 */
export function errorDocsUrl(code: KervyxErrorCode): string {
  return `${DOCS_BASE_URL}/${code}`;
}

/**
 * Format an error for display.
 *
 * Includes the error code, message, hint (if present), and a link
 * to the documentation page.
 *
 * @param error - The KervyxError to format.
 * @returns A multi-line formatted string for terminal or log output.
 *
 * @example
 * ```typescript
 * const err = new KervyxError(
 *   KervyxErrorCode.MISSING_ISSUER,
 *   'Covenant requires an issuer',
 *   { hint: 'Set the issuer field before calling build()' }
 * );
 * console.log(formatError(err));
 * // [KERVYX_E200] Covenant requires an issuer
 * // Hint: Set the issuer field before calling build()
 * // Docs: https://kervyx.dev/errors/KERVYX_E200
 * ```
 */
export function formatError(error: KervyxError): string {
  const lines: string[] = [];
  lines.push(`[${error.code}] ${error.message}`);
  if (error.hint) {
    lines.push(`Hint: ${error.hint}`);
  }
  lines.push(`Docs: ${errorDocsUrl(error.code)}`);
  return lines.join('\n');
}
