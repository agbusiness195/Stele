import { describe, it, expect } from 'vitest';
import {
  GrithErrorCode,
  GrithError,
  errorDocsUrl,
  formatError,
} from './errors';

// ---------------------------------------------------------------------------
// GrithErrorCode enum
// ---------------------------------------------------------------------------
describe('GrithErrorCode', () => {
  it('has key management codes (1xx)', () => {
    expect(GrithErrorCode.NO_PRIVATE_KEY).toBe('GRITH_E100');
    expect(GrithErrorCode.NO_KEY_PAIR).toBe('GRITH_E101');
    expect(GrithErrorCode.INVALID_KEY_SIZE).toBe('GRITH_E102');
    expect(GrithErrorCode.KEY_ROTATION_REQUIRED).toBe('GRITH_E103');
  });

  it('has covenant building codes (2xx)', () => {
    expect(GrithErrorCode.MISSING_ISSUER).toBe('GRITH_E200');
    expect(GrithErrorCode.MISSING_BENEFICIARY).toBe('GRITH_E201');
    expect(GrithErrorCode.EMPTY_CONSTRAINTS).toBe('GRITH_E202');
    expect(GrithErrorCode.INVALID_EXPIRY).toBe('GRITH_E203');
    expect(GrithErrorCode.CONSTRAINTS_TOO_LARGE).toBe('GRITH_E204');
    expect(GrithErrorCode.DOCUMENT_TOO_LARGE).toBe('GRITH_E205');
  });

  it('has verification codes (3xx)', () => {
    expect(GrithErrorCode.SIGNATURE_INVALID).toBe('GRITH_E300');
    expect(GrithErrorCode.ID_MISMATCH).toBe('GRITH_E301');
    expect(GrithErrorCode.EXPIRED).toBe('GRITH_E302');
    expect(GrithErrorCode.NOT_YET_ACTIVE).toBe('GRITH_E303');
    expect(GrithErrorCode.CHAIN_DEPTH_EXCEEDED).toBe('GRITH_E304');
    expect(GrithErrorCode.VERSION_UNSUPPORTED).toBe('GRITH_E305');
  });

  it('has CCL codes (4xx)', () => {
    expect(GrithErrorCode.CCL_SYNTAX_ERROR).toBe('GRITH_E400');
    expect(GrithErrorCode.CCL_EMPTY_INPUT).toBe('GRITH_E401');
    expect(GrithErrorCode.CCL_INVALID_ACTION).toBe('GRITH_E402');
    expect(GrithErrorCode.CCL_INVALID_RESOURCE).toBe('GRITH_E403');
    expect(GrithErrorCode.CCL_NARROWING_VIOLATION).toBe('GRITH_E404');
  });

  it('has store codes (5xx)', () => {
    expect(GrithErrorCode.STORE_MISSING_DOC).toBe('GRITH_E500');
    expect(GrithErrorCode.STORE_MISSING_ID).toBe('GRITH_E501');
    expect(GrithErrorCode.STORE_NOT_FOUND).toBe('GRITH_E502');
    expect(GrithErrorCode.STORE_WRITE_FAILED).toBe('GRITH_E503');
  });

  it('has identity codes (6xx)', () => {
    expect(GrithErrorCode.IDENTITY_INVALID).toBe('GRITH_E600');
    expect(GrithErrorCode.IDENTITY_EVOLUTION_FAILED).toBe('GRITH_E601');
  });

  it('has enforcement codes (7xx)', () => {
    expect(GrithErrorCode.RATE_LIMIT_EXCEEDED).toBe('GRITH_E700');
    expect(GrithErrorCode.ACTION_DENIED).toBe('GRITH_E701');
    expect(GrithErrorCode.AUDIT_CHAIN_CORRUPTED).toBe('GRITH_E702');
  });

  it('has auth codes (8xx)', () => {
    expect(GrithErrorCode.AUTH_REQUIRED).toBe('GRITH_E800');
    expect(GrithErrorCode.AUTH_INVALID_KEY).toBe('GRITH_E801');
    expect(GrithErrorCode.AUTH_RATE_LIMITED).toBe('GRITH_E802');
  });

  it('every code value starts with GRITH_E', () => {
    const values = Object.values(GrithErrorCode);
    for (const value of values) {
      expect(value).toMatch(/^GRITH_E\d{3}$/);
    }
  });

  it('all code values are unique', () => {
    const values = Object.values(GrithErrorCode);
    const unique = new Set(values);
    expect(unique.size).toBe(values.length);
  });
});

// ---------------------------------------------------------------------------
// GrithError class
// ---------------------------------------------------------------------------
describe('GrithError', () => {
  it('extends Error', () => {
    const err = new GrithError(GrithErrorCode.MISSING_ISSUER, 'no issuer');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(GrithError);
  });

  it('has code, message, and name', () => {
    const err = new GrithError(GrithErrorCode.SIGNATURE_INVALID, 'bad sig');
    expect(err.code).toBe(GrithErrorCode.SIGNATURE_INVALID);
    expect(err.message).toBe('bad sig');
    expect(err.name).toBe('GrithError');
  });

  it('supports hint option', () => {
    const err = new GrithError(
      GrithErrorCode.MISSING_ISSUER,
      'Covenant requires an issuer',
      { hint: 'Set the issuer field before calling build()' },
    );
    expect(err.hint).toBe('Set the issuer field before calling build()');
  });

  it('supports context option', () => {
    const err = new GrithError(
      GrithErrorCode.CONSTRAINTS_TOO_LARGE,
      'constraints exceed limit',
      { context: { maxBytes: 65536, actualBytes: 128000 } },
    );
    expect(err.context).toEqual({ maxBytes: 65536, actualBytes: 128000 });
  });

  it('supports cause option for error chaining', () => {
    const cause = new Error('underlying failure');
    const err = new GrithError(
      GrithErrorCode.STORE_WRITE_FAILED,
      'store write failed',
      { cause },
    );
    expect(err.cause).toBe(cause);
  });

  it('hint and context are undefined when not provided', () => {
    const err = new GrithError(GrithErrorCode.EXPIRED, 'token expired');
    expect(err.hint).toBeUndefined();
    expect(err.context).toBeUndefined();
  });

  it('code is readonly', () => {
    const err = new GrithError(GrithErrorCode.NO_PRIVATE_KEY, 'missing key');
    expect(err.code).toBe(GrithErrorCode.NO_PRIVATE_KEY);
    // Verify value is stable after construction
    expect(err.code).toBe('GRITH_E100');
  });
});

// ---------------------------------------------------------------------------
// GrithError.toJSON
// ---------------------------------------------------------------------------
describe('GrithError.toJSON', () => {
  it('returns code and message for a basic error', () => {
    const err = new GrithError(GrithErrorCode.CCL_SYNTAX_ERROR, 'parse failed');
    const json = err.toJSON();
    expect(json).toEqual({
      code: 'GRITH_E400',
      message: 'parse failed',
    });
  });

  it('includes hint when provided', () => {
    const err = new GrithError(
      GrithErrorCode.MISSING_BENEFICIARY,
      'no beneficiary',
      { hint: 'Add a beneficiary before signing' },
    );
    const json = err.toJSON();
    expect(json.hint).toBe('Add a beneficiary before signing');
  });

  it('includes context when provided', () => {
    const err = new GrithError(
      GrithErrorCode.DOCUMENT_TOO_LARGE,
      'too big',
      { context: { size: 1024000 } },
    );
    const json = err.toJSON();
    expect(json.context).toEqual({ size: 1024000 });
  });

  it('omits hint and context when not provided', () => {
    const err = new GrithError(GrithErrorCode.EXPIRED, 'expired');
    const json = err.toJSON();
    expect('hint' in json).toBe(false);
    expect('context' in json).toBe(false);
  });

  it('returns a plain object suitable for JSON.stringify', () => {
    const err = new GrithError(
      GrithErrorCode.AUTH_REQUIRED,
      'auth needed',
      { hint: 'Provide an API key', context: { endpoint: '/api/v1' } },
    );
    const serialized = JSON.stringify(err.toJSON());
    const parsed = JSON.parse(serialized);
    expect(parsed.code).toBe('GRITH_E800');
    expect(parsed.message).toBe('auth needed');
    expect(parsed.hint).toBe('Provide an API key');
    expect(parsed.context).toEqual({ endpoint: '/api/v1' });
  });
});

// ---------------------------------------------------------------------------
// errorDocsUrl
// ---------------------------------------------------------------------------
describe('errorDocsUrl', () => {
  it('returns a valid URL for a given error code', () => {
    const url = errorDocsUrl(GrithErrorCode.MISSING_ISSUER);
    expect(url).toBe('https://grith.dev/errors/GRITH_E200');
  });

  it('returns different URLs for different codes', () => {
    const url1 = errorDocsUrl(GrithErrorCode.NO_PRIVATE_KEY);
    const url2 = errorDocsUrl(GrithErrorCode.SIGNATURE_INVALID);
    expect(url1).not.toBe(url2);
  });

  it('URL starts with https://', () => {
    const url = errorDocsUrl(GrithErrorCode.CCL_SYNTAX_ERROR);
    expect(url).toMatch(/^https:\/\//);
  });

  it('URL contains the error code', () => {
    const url = errorDocsUrl(GrithErrorCode.STORE_NOT_FOUND);
    expect(url).toContain('GRITH_E502');
  });

  it('returns valid URLs for all error codes', () => {
    const codes = Object.values(GrithErrorCode);
    for (const code of codes) {
      const url = errorDocsUrl(code);
      expect(url).toMatch(/^https:\/\/grith\.dev\/errors\/GRITH_E\d{3}$/);
    }
  });
});

// ---------------------------------------------------------------------------
// formatError
// ---------------------------------------------------------------------------
describe('formatError', () => {
  it('includes the error code in brackets', () => {
    const err = new GrithError(GrithErrorCode.SIGNATURE_INVALID, 'bad signature');
    const formatted = formatError(err);
    expect(formatted).toContain('[GRITH_E300]');
  });

  it('includes the error message', () => {
    const err = new GrithError(GrithErrorCode.EXPIRED, 'document has expired');
    const formatted = formatError(err);
    expect(formatted).toContain('document has expired');
  });

  it('includes the hint when provided', () => {
    const err = new GrithError(
      GrithErrorCode.MISSING_ISSUER,
      'no issuer set',
      { hint: 'Call setIssuer() first' },
    );
    const formatted = formatError(err);
    expect(formatted).toContain('Hint: Call setIssuer() first');
  });

  it('does not include a hint line when hint is absent', () => {
    const err = new GrithError(GrithErrorCode.EXPIRED, 'expired');
    const formatted = formatError(err);
    expect(formatted).not.toContain('Hint:');
  });

  it('includes a docs URL', () => {
    const err = new GrithError(GrithErrorCode.CCL_SYNTAX_ERROR, 'parse error');
    const formatted = formatError(err);
    expect(formatted).toContain('Docs: https://grith.dev/errors/GRITH_E400');
  });

  it('formats a complete error with all fields', () => {
    const err = new GrithError(
      GrithErrorCode.MISSING_ISSUER,
      'Covenant requires an issuer',
      { hint: 'Set the issuer field before calling build()' },
    );
    const formatted = formatError(err);
    const lines = formatted.split('\n');
    expect(lines[0]).toBe('[GRITH_E200] Covenant requires an issuer');
    expect(lines[1]).toBe('Hint: Set the issuer field before calling build()');
    expect(lines[2]).toBe('Docs: https://grith.dev/errors/GRITH_E200');
  });

  it('formats an error without hint as two lines', () => {
    const err = new GrithError(GrithErrorCode.NO_KEY_PAIR, 'no key pair available');
    const formatted = formatError(err);
    const lines = formatted.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe('[GRITH_E101] no key pair available');
    expect(lines[1]).toBe('Docs: https://grith.dev/errors/GRITH_E101');
  });
});
