/**
 * Comprehensive error code system for the Grith SDK.
 *
 * Every error has a unique, documentable code (GRITH_Exxx) that maps
 * to a specific, documented failure mode. This enables structured error
 * handling, logging, and user-facing diagnostics.
 *
 * @packageDocumentation
 */

// ─── Error codes ────────────────────────────────────────────────────────────────

/** All Grith error codes. Each maps to a specific, documented failure mode. */
export enum GrithErrorCode {
  // Key management (1xx)
  /** A required private key was not provided or not available. */
  NO_PRIVATE_KEY = 'GRITH_E100',
  /** A required key pair was not provided or not available. */
  NO_KEY_PAIR = 'GRITH_E101',
  /** The key size does not meet the required specification. */
  INVALID_KEY_SIZE = 'GRITH_E102',
  /** The key has exceeded its validity period and must be rotated. */
  KEY_ROTATION_REQUIRED = 'GRITH_E103',

  // Covenant building (2xx)
  /** The issuer field is required but was not provided. */
  MISSING_ISSUER = 'GRITH_E200',
  /** The beneficiary field is required but was not provided. */
  MISSING_BENEFICIARY = 'GRITH_E201',
  /** At least one constraint must be specified. */
  EMPTY_CONSTRAINTS = 'GRITH_E202',
  /** The expiry date is invalid (e.g., in the past or malformed). */
  INVALID_EXPIRY = 'GRITH_E203',
  /** The constraints payload exceeds the maximum allowed size. */
  CONSTRAINTS_TOO_LARGE = 'GRITH_E204',
  /** The document exceeds the maximum allowed size. */
  DOCUMENT_TOO_LARGE = 'GRITH_E205',

  // Verification (3xx)
  /** The cryptographic signature did not verify. */
  SIGNATURE_INVALID = 'GRITH_E300',
  /** The document ID does not match the expected value. */
  ID_MISMATCH = 'GRITH_E301',
  /** The document or token has expired. */
  EXPIRED = 'GRITH_E302',
  /** The document or token is not yet active (notBefore date in the future). */
  NOT_YET_ACTIVE = 'GRITH_E303',
  /** The delegation chain exceeds the maximum allowed depth. */
  CHAIN_DEPTH_EXCEEDED = 'GRITH_E304',
  /** The protocol version is not supported. */
  VERSION_UNSUPPORTED = 'GRITH_E305',

  // CCL (4xx)
  /** The CCL constraint text contains a syntax error. */
  CCL_SYNTAX_ERROR = 'GRITH_E400',
  /** The CCL input was empty or missing. */
  CCL_EMPTY_INPUT = 'GRITH_E401',
  /** The action specified in the CCL rule is not valid. */
  CCL_INVALID_ACTION = 'GRITH_E402',
  /** The resource specified in the CCL rule is not valid. */
  CCL_INVALID_RESOURCE = 'GRITH_E403',
  /** A chain narrowing validation detected a broadening violation. */
  CCL_NARROWING_VIOLATION = 'GRITH_E404',

  // Store (5xx)
  /** The document was expected but not provided to the store operation. */
  STORE_MISSING_DOC = 'GRITH_E500',
  /** The document ID was expected but not provided. */
  STORE_MISSING_ID = 'GRITH_E501',
  /** The requested document was not found in the store. */
  STORE_NOT_FOUND = 'GRITH_E502',
  /** The store write operation failed. */
  STORE_WRITE_FAILED = 'GRITH_E503',

  // Identity (6xx)
  /** The identity document or format is invalid. */
  IDENTITY_INVALID = 'GRITH_E600',
  /** An identity evolution operation failed. */
  IDENTITY_EVOLUTION_FAILED = 'GRITH_E601',

  // Rate limiting / enforcement (7xx)
  /** The rate limit for the operation has been exceeded. */
  RATE_LIMIT_EXCEEDED = 'GRITH_E700',
  /** The action was denied by enforcement policy. */
  ACTION_DENIED = 'GRITH_E701',
  /** The audit chain integrity check failed (corrupted or tampered). */
  AUDIT_CHAIN_CORRUPTED = 'GRITH_E702',

  // Auth (8xx)
  /** Authentication is required but was not provided. */
  AUTH_REQUIRED = 'GRITH_E800',
  /** The provided authentication key is invalid. */
  AUTH_INVALID_KEY = 'GRITH_E801',
  /** Authentication attempts have been rate limited. */
  AUTH_RATE_LIMITED = 'GRITH_E802',

  // Crypto (9xx)
  /** A hex-encoded string was malformed or invalid. */
  CRYPTO_INVALID_HEX = 'GRITH_E900',
  /** A cryptographic key was invalid or malformed. */
  CRYPTO_INVALID_KEY = 'GRITH_E901',
  /** A cryptographic signing operation failed. */
  CRYPTO_SIGNATURE_FAILED = 'GRITH_E902',

  // Reputation (91x)
  /** A reputation receipt was invalid or malformed. */
  REPUTATION_INVALID_RECEIPT = 'GRITH_E910',
  /** A reputation computation failed. */
  REPUTATION_COMPUTATION_FAILED = 'GRITH_E911',

  // Breach (92x)
  /** A breach attestation was invalid or malformed. */
  BREACH_INVALID_ATTESTATION = 'GRITH_E920',
  /** A breach severity value was invalid. */
  BREACH_INVALID_SEVERITY = 'GRITH_E921',

  // Attestation (93x)
  /** An attestation was invalid or malformed. */
  ATTESTATION_INVALID = 'GRITH_E930',
  /** An attestation reconciliation operation failed. */
  ATTESTATION_RECONCILIATION_FAILED = 'GRITH_E931',

  // Protocol general (94x)
  /** A protocol input was invalid or malformed. */
  PROTOCOL_INVALID_INPUT = 'GRITH_E940',
  /** A protocol computation failed. */
  PROTOCOL_COMPUTATION_FAILED = 'GRITH_E941',
}

// ─── Error class ────────────────────────────────────────────────────────────────

/** Options for constructing a GrithError. */
export interface GrithErrorOptions {
  /** Additional structured context for diagnostics and logging. */
  context?: Record<string, unknown>;
  /** A human-readable hint suggesting how to resolve the error. */
  hint?: string;
  /** The underlying cause of this error, for error chaining. */
  cause?: Error;
}

/**
 * Base error class for all Grith errors.
 *
 * Includes a unique error code, optional context for structured logging,
 * and an optional hint for user-facing diagnostics.
 *
 * @example
 * ```typescript
 * throw new GrithError(
 *   GrithErrorCode.MISSING_ISSUER,
 *   'Covenant requires an issuer',
 *   { hint: 'Set the issuer field before calling build()' }
 * );
 * ```
 */
export class GrithError extends Error {
  readonly code: GrithErrorCode;
  readonly context?: Record<string, unknown>;
  readonly hint?: string;

  constructor(code: GrithErrorCode, message: string, options?: GrithErrorOptions) {
    super(message, options?.cause ? { cause: options.cause } : undefined);
    this.name = 'GrithError';
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
const DOCS_BASE_URL = 'https://grith.dev/errors';

/**
 * Look up the documentation URL for an error code.
 *
 * @param code - The Grith error code.
 * @returns A URL pointing to the documentation page for this error code.
 *
 * @example
 * ```typescript
 * errorDocsUrl(GrithErrorCode.MISSING_ISSUER)
 * // => 'https://grith.dev/errors/GRITH_E200'
 * ```
 */
export function errorDocsUrl(code: GrithErrorCode): string {
  return `${DOCS_BASE_URL}/${code}`;
}

/**
 * Format an error for display.
 *
 * Includes the error code, message, hint (if present), and a link
 * to the documentation page.
 *
 * @param error - The GrithError to format.
 * @returns A multi-line formatted string for terminal or log output.
 *
 * @example
 * ```typescript
 * const err = new GrithError(
 *   GrithErrorCode.MISSING_ISSUER,
 *   'Covenant requires an issuer',
 *   { hint: 'Set the issuer field before calling build()' }
 * );
 * console.log(formatError(err));
 * // [GRITH_E200] Covenant requires an issuer
 * // Hint: Set the issuer field before calling build()
 * // Docs: https://grith.dev/errors/GRITH_E200
 * ```
 */
export function formatError(error: GrithError): string {
  const lines: string[] = [];
  lines.push(`[${error.code}] ${error.message}`);
  if (error.hint) {
    lines.push(`Hint: ${error.hint}`);
  }
  lines.push(`Docs: ${errorDocsUrl(error.code)}`);
  return lines.join('\n');
}
