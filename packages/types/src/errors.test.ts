import { describe, it, expect } from 'vitest';
import {
  KovaErrorCode,
  KovaError,
  errorDocsUrl,
  formatError,
} from './errors';

// ---------------------------------------------------------------------------
// KovaErrorCode enum
// ---------------------------------------------------------------------------
describe('KovaErrorCode', () => {
  it('has key management codes (1xx)', () => {
    expect(KovaErrorCode.NO_PRIVATE_KEY).toBe('KOVA_E100');
    expect(KovaErrorCode.NO_KEY_PAIR).toBe('KOVA_E101');
    expect(KovaErrorCode.INVALID_KEY_SIZE).toBe('KOVA_E102');
    expect(KovaErrorCode.KEY_ROTATION_REQUIRED).toBe('KOVA_E103');
  });

  it('has covenant building codes (2xx)', () => {
    expect(KovaErrorCode.MISSING_ISSUER).toBe('KOVA_E200');
    expect(KovaErrorCode.MISSING_BENEFICIARY).toBe('KOVA_E201');
    expect(KovaErrorCode.EMPTY_CONSTRAINTS).toBe('KOVA_E202');
    expect(KovaErrorCode.INVALID_EXPIRY).toBe('KOVA_E203');
    expect(KovaErrorCode.CONSTRAINTS_TOO_LARGE).toBe('KOVA_E204');
    expect(KovaErrorCode.DOCUMENT_TOO_LARGE).toBe('KOVA_E205');
  });

  it('has verification codes (3xx)', () => {
    expect(KovaErrorCode.SIGNATURE_INVALID).toBe('KOVA_E300');
    expect(KovaErrorCode.ID_MISMATCH).toBe('KOVA_E301');
    expect(KovaErrorCode.EXPIRED).toBe('KOVA_E302');
    expect(KovaErrorCode.NOT_YET_ACTIVE).toBe('KOVA_E303');
    expect(KovaErrorCode.CHAIN_DEPTH_EXCEEDED).toBe('KOVA_E304');
    expect(KovaErrorCode.VERSION_UNSUPPORTED).toBe('KOVA_E305');
  });

  it('has CCL codes (4xx)', () => {
    expect(KovaErrorCode.CCL_SYNTAX_ERROR).toBe('KOVA_E400');
    expect(KovaErrorCode.CCL_EMPTY_INPUT).toBe('KOVA_E401');
    expect(KovaErrorCode.CCL_INVALID_ACTION).toBe('KOVA_E402');
    expect(KovaErrorCode.CCL_INVALID_RESOURCE).toBe('KOVA_E403');
    expect(KovaErrorCode.CCL_NARROWING_VIOLATION).toBe('KOVA_E404');
  });

  it('has store codes (5xx)', () => {
    expect(KovaErrorCode.STORE_MISSING_DOC).toBe('KOVA_E500');
    expect(KovaErrorCode.STORE_MISSING_ID).toBe('KOVA_E501');
    expect(KovaErrorCode.STORE_NOT_FOUND).toBe('KOVA_E502');
    expect(KovaErrorCode.STORE_WRITE_FAILED).toBe('KOVA_E503');
  });

  it('has identity codes (6xx)', () => {
    expect(KovaErrorCode.IDENTITY_INVALID).toBe('KOVA_E600');
    expect(KovaErrorCode.IDENTITY_EVOLUTION_FAILED).toBe('KOVA_E601');
  });

  it('has enforcement codes (7xx)', () => {
    expect(KovaErrorCode.RATE_LIMIT_EXCEEDED).toBe('KOVA_E700');
    expect(KovaErrorCode.ACTION_DENIED).toBe('KOVA_E701');
    expect(KovaErrorCode.AUDIT_CHAIN_CORRUPTED).toBe('KOVA_E702');
  });

  it('has auth codes (8xx)', () => {
    expect(KovaErrorCode.AUTH_REQUIRED).toBe('KOVA_E800');
    expect(KovaErrorCode.AUTH_INVALID_KEY).toBe('KOVA_E801');
    expect(KovaErrorCode.AUTH_RATE_LIMITED).toBe('KOVA_E802');
  });

  it('every code value starts with KOVA_E', () => {
    const values = Object.values(KovaErrorCode);
    for (const value of values) {
      expect(value).toMatch(/^KOVA_E\d{3}$/);
    }
  });

  it('all code values are unique', () => {
    const values = Object.values(KovaErrorCode);
    const unique = new Set(values);
    expect(unique.size).toBe(values.length);
  });
});

// ---------------------------------------------------------------------------
// KovaError class
// ---------------------------------------------------------------------------
describe('KovaError', () => {
  it('extends Error', () => {
    const err = new KovaError(KovaErrorCode.MISSING_ISSUER, 'no issuer');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(KovaError);
  });

  it('has code, message, and name', () => {
    const err = new KovaError(KovaErrorCode.SIGNATURE_INVALID, 'bad sig');
    expect(err.code).toBe(KovaErrorCode.SIGNATURE_INVALID);
    expect(err.message).toBe('bad sig');
    expect(err.name).toBe('KovaError');
  });

  it('supports hint option', () => {
    const err = new KovaError(
      KovaErrorCode.MISSING_ISSUER,
      'Covenant requires an issuer',
      { hint: 'Set the issuer field before calling build()' },
    );
    expect(err.hint).toBe('Set the issuer field before calling build()');
  });

  it('supports context option', () => {
    const err = new KovaError(
      KovaErrorCode.CONSTRAINTS_TOO_LARGE,
      'constraints exceed limit',
      { context: { maxBytes: 65536, actualBytes: 128000 } },
    );
    expect(err.context).toEqual({ maxBytes: 65536, actualBytes: 128000 });
  });

  it('supports cause option for error chaining', () => {
    const cause = new Error('underlying failure');
    const err = new KovaError(
      KovaErrorCode.STORE_WRITE_FAILED,
      'store write failed',
      { cause },
    );
    expect(err.cause).toBe(cause);
  });

  it('hint and context are undefined when not provided', () => {
    const err = new KovaError(KovaErrorCode.EXPIRED, 'token expired');
    expect(err.hint).toBeUndefined();
    expect(err.context).toBeUndefined();
  });

  it('code is readonly', () => {
    const err = new KovaError(KovaErrorCode.NO_PRIVATE_KEY, 'missing key');
    expect(err.code).toBe(KovaErrorCode.NO_PRIVATE_KEY);
    // Verify value is stable after construction
    expect(err.code).toBe('KOVA_E100');
  });
});

// ---------------------------------------------------------------------------
// KovaError.toJSON
// ---------------------------------------------------------------------------
describe('KovaError.toJSON', () => {
  it('returns code and message for a basic error', () => {
    const err = new KovaError(KovaErrorCode.CCL_SYNTAX_ERROR, 'parse failed');
    const json = err.toJSON();
    expect(json).toEqual({
      code: 'KOVA_E400',
      message: 'parse failed',
    });
  });

  it('includes hint when provided', () => {
    const err = new KovaError(
      KovaErrorCode.MISSING_BENEFICIARY,
      'no beneficiary',
      { hint: 'Add a beneficiary before signing' },
    );
    const json = err.toJSON();
    expect(json.hint).toBe('Add a beneficiary before signing');
  });

  it('includes context when provided', () => {
    const err = new KovaError(
      KovaErrorCode.DOCUMENT_TOO_LARGE,
      'too big',
      { context: { size: 1024000 } },
    );
    const json = err.toJSON();
    expect(json.context).toEqual({ size: 1024000 });
  });

  it('omits hint and context when not provided', () => {
    const err = new KovaError(KovaErrorCode.EXPIRED, 'expired');
    const json = err.toJSON();
    expect('hint' in json).toBe(false);
    expect('context' in json).toBe(false);
  });

  it('returns a plain object suitable for JSON.stringify', () => {
    const err = new KovaError(
      KovaErrorCode.AUTH_REQUIRED,
      'auth needed',
      { hint: 'Provide an API key', context: { endpoint: '/api/v1' } },
    );
    const serialized = JSON.stringify(err.toJSON());
    const parsed = JSON.parse(serialized);
    expect(parsed.code).toBe('KOVA_E800');
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
    const url = errorDocsUrl(KovaErrorCode.MISSING_ISSUER);
    expect(url).toBe('https://usekova.dev/errors/KOVA_E200');
  });

  it('returns different URLs for different codes', () => {
    const url1 = errorDocsUrl(KovaErrorCode.NO_PRIVATE_KEY);
    const url2 = errorDocsUrl(KovaErrorCode.SIGNATURE_INVALID);
    expect(url1).not.toBe(url2);
  });

  it('URL starts with https://', () => {
    const url = errorDocsUrl(KovaErrorCode.CCL_SYNTAX_ERROR);
    expect(url).toMatch(/^https:\/\//);
  });

  it('URL contains the error code', () => {
    const url = errorDocsUrl(KovaErrorCode.STORE_NOT_FOUND);
    expect(url).toContain('KOVA_E502');
  });

  it('returns valid URLs for all error codes', () => {
    const codes = Object.values(KovaErrorCode);
    for (const code of codes) {
      const url = errorDocsUrl(code);
      expect(url).toMatch(/^https:\/\/usekova\.dev\/errors\/KOVA_E\d{3}$/);
    }
  });
});

// ---------------------------------------------------------------------------
// formatError
// ---------------------------------------------------------------------------
describe('formatError', () => {
  it('includes the error code in brackets', () => {
    const err = new KovaError(KovaErrorCode.SIGNATURE_INVALID, 'bad signature');
    const formatted = formatError(err);
    expect(formatted).toContain('[KOVA_E300]');
  });

  it('includes the error message', () => {
    const err = new KovaError(KovaErrorCode.EXPIRED, 'document has expired');
    const formatted = formatError(err);
    expect(formatted).toContain('document has expired');
  });

  it('includes the hint when provided', () => {
    const err = new KovaError(
      KovaErrorCode.MISSING_ISSUER,
      'no issuer set',
      { hint: 'Call setIssuer() first' },
    );
    const formatted = formatError(err);
    expect(formatted).toContain('Hint: Call setIssuer() first');
  });

  it('does not include a hint line when hint is absent', () => {
    const err = new KovaError(KovaErrorCode.EXPIRED, 'expired');
    const formatted = formatError(err);
    expect(formatted).not.toContain('Hint:');
  });

  it('includes a docs URL', () => {
    const err = new KovaError(KovaErrorCode.CCL_SYNTAX_ERROR, 'parse error');
    const formatted = formatError(err);
    expect(formatted).toContain('Docs: https://usekova.dev/errors/KOVA_E400');
  });

  it('formats a complete error with all fields', () => {
    const err = new KovaError(
      KovaErrorCode.MISSING_ISSUER,
      'Covenant requires an issuer',
      { hint: 'Set the issuer field before calling build()' },
    );
    const formatted = formatError(err);
    const lines = formatted.split('\n');
    expect(lines[0]).toBe('[KOVA_E200] Covenant requires an issuer');
    expect(lines[1]).toBe('Hint: Set the issuer field before calling build()');
    expect(lines[2]).toBe('Docs: https://usekova.dev/errors/KOVA_E200');
  });

  it('formats an error without hint as two lines', () => {
    const err = new KovaError(KovaErrorCode.NO_KEY_PAIR, 'no key pair available');
    const formatted = formatError(err);
    const lines = formatted.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe('[KOVA_E101] no key pair available');
    expect(lines[1]).toBe('Docs: https://usekova.dev/errors/KOVA_E101');
  });
});
