import { describe, it, expect } from 'vitest';
import {
  KervyxErrorCode,
  KervyxError,
  errorDocsUrl,
  formatError,
} from './errors';

// ---------------------------------------------------------------------------
// KervyxErrorCode enum
// ---------------------------------------------------------------------------
describe('KervyxErrorCode', () => {
  it('has key management codes (1xx)', () => {
    expect(KervyxErrorCode.NO_PRIVATE_KEY).toBe('KERVYX_E100');
    expect(KervyxErrorCode.NO_KEY_PAIR).toBe('KERVYX_E101');
    expect(KervyxErrorCode.INVALID_KEY_SIZE).toBe('KERVYX_E102');
    expect(KervyxErrorCode.KEY_ROTATION_REQUIRED).toBe('KERVYX_E103');
  });

  it('has covenant building codes (2xx)', () => {
    expect(KervyxErrorCode.MISSING_ISSUER).toBe('KERVYX_E200');
    expect(KervyxErrorCode.MISSING_BENEFICIARY).toBe('KERVYX_E201');
    expect(KervyxErrorCode.EMPTY_CONSTRAINTS).toBe('KERVYX_E202');
    expect(KervyxErrorCode.INVALID_EXPIRY).toBe('KERVYX_E203');
    expect(KervyxErrorCode.CONSTRAINTS_TOO_LARGE).toBe('KERVYX_E204');
    expect(KervyxErrorCode.DOCUMENT_TOO_LARGE).toBe('KERVYX_E205');
  });

  it('has verification codes (3xx)', () => {
    expect(KervyxErrorCode.SIGNATURE_INVALID).toBe('KERVYX_E300');
    expect(KervyxErrorCode.ID_MISMATCH).toBe('KERVYX_E301');
    expect(KervyxErrorCode.EXPIRED).toBe('KERVYX_E302');
    expect(KervyxErrorCode.NOT_YET_ACTIVE).toBe('KERVYX_E303');
    expect(KervyxErrorCode.CHAIN_DEPTH_EXCEEDED).toBe('KERVYX_E304');
    expect(KervyxErrorCode.VERSION_UNSUPPORTED).toBe('KERVYX_E305');
  });

  it('has CCL codes (4xx)', () => {
    expect(KervyxErrorCode.CCL_SYNTAX_ERROR).toBe('KERVYX_E400');
    expect(KervyxErrorCode.CCL_EMPTY_INPUT).toBe('KERVYX_E401');
    expect(KervyxErrorCode.CCL_INVALID_ACTION).toBe('KERVYX_E402');
    expect(KervyxErrorCode.CCL_INVALID_RESOURCE).toBe('KERVYX_E403');
    expect(KervyxErrorCode.CCL_NARROWING_VIOLATION).toBe('KERVYX_E404');
  });

  it('has store codes (5xx)', () => {
    expect(KervyxErrorCode.STORE_MISSING_DOC).toBe('KERVYX_E500');
    expect(KervyxErrorCode.STORE_MISSING_ID).toBe('KERVYX_E501');
    expect(KervyxErrorCode.STORE_NOT_FOUND).toBe('KERVYX_E502');
    expect(KervyxErrorCode.STORE_WRITE_FAILED).toBe('KERVYX_E503');
  });

  it('has identity codes (6xx)', () => {
    expect(KervyxErrorCode.IDENTITY_INVALID).toBe('KERVYX_E600');
    expect(KervyxErrorCode.IDENTITY_EVOLUTION_FAILED).toBe('KERVYX_E601');
  });

  it('has enforcement codes (7xx)', () => {
    expect(KervyxErrorCode.RATE_LIMIT_EXCEEDED).toBe('KERVYX_E700');
    expect(KervyxErrorCode.ACTION_DENIED).toBe('KERVYX_E701');
    expect(KervyxErrorCode.AUDIT_CHAIN_CORRUPTED).toBe('KERVYX_E702');
  });

  it('has auth codes (8xx)', () => {
    expect(KervyxErrorCode.AUTH_REQUIRED).toBe('KERVYX_E800');
    expect(KervyxErrorCode.AUTH_INVALID_KEY).toBe('KERVYX_E801');
    expect(KervyxErrorCode.AUTH_RATE_LIMITED).toBe('KERVYX_E802');
  });

  it('every code value starts with KERVYX_E', () => {
    const values = Object.values(KervyxErrorCode);
    for (const value of values) {
      expect(value).toMatch(/^KERVYX_E\d{3}$/);
    }
  });

  it('all code values are unique', () => {
    const values = Object.values(KervyxErrorCode);
    const unique = new Set(values);
    expect(unique.size).toBe(values.length);
  });
});

// ---------------------------------------------------------------------------
// KervyxError class
// ---------------------------------------------------------------------------
describe('KervyxError', () => {
  it('extends Error', () => {
    const err = new KervyxError(KervyxErrorCode.MISSING_ISSUER, 'no issuer');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(KervyxError);
  });

  it('has code, message, and name', () => {
    const err = new KervyxError(KervyxErrorCode.SIGNATURE_INVALID, 'bad sig');
    expect(err.code).toBe(KervyxErrorCode.SIGNATURE_INVALID);
    expect(err.message).toBe('bad sig');
    expect(err.name).toBe('KervyxError');
  });

  it('supports hint option', () => {
    const err = new KervyxError(
      KervyxErrorCode.MISSING_ISSUER,
      'Covenant requires an issuer',
      { hint: 'Set the issuer field before calling build()' },
    );
    expect(err.hint).toBe('Set the issuer field before calling build()');
  });

  it('supports context option', () => {
    const err = new KervyxError(
      KervyxErrorCode.CONSTRAINTS_TOO_LARGE,
      'constraints exceed limit',
      { context: { maxBytes: 65536, actualBytes: 128000 } },
    );
    expect(err.context).toEqual({ maxBytes: 65536, actualBytes: 128000 });
  });

  it('supports cause option for error chaining', () => {
    const cause = new Error('underlying failure');
    const err = new KervyxError(
      KervyxErrorCode.STORE_WRITE_FAILED,
      'store write failed',
      { cause },
    );
    expect(err.cause).toBe(cause);
  });

  it('hint and context are undefined when not provided', () => {
    const err = new KervyxError(KervyxErrorCode.EXPIRED, 'token expired');
    expect(err.hint).toBeUndefined();
    expect(err.context).toBeUndefined();
  });

  it('code is readonly', () => {
    const err = new KervyxError(KervyxErrorCode.NO_PRIVATE_KEY, 'missing key');
    expect(err.code).toBe(KervyxErrorCode.NO_PRIVATE_KEY);
    // Verify value is stable after construction
    expect(err.code).toBe('KERVYX_E100');
  });
});

// ---------------------------------------------------------------------------
// KervyxError.toJSON
// ---------------------------------------------------------------------------
describe('KervyxError.toJSON', () => {
  it('returns code and message for a basic error', () => {
    const err = new KervyxError(KervyxErrorCode.CCL_SYNTAX_ERROR, 'parse failed');
    const json = err.toJSON();
    expect(json).toEqual({
      code: 'KERVYX_E400',
      message: 'parse failed',
    });
  });

  it('includes hint when provided', () => {
    const err = new KervyxError(
      KervyxErrorCode.MISSING_BENEFICIARY,
      'no beneficiary',
      { hint: 'Add a beneficiary before signing' },
    );
    const json = err.toJSON();
    expect(json.hint).toBe('Add a beneficiary before signing');
  });

  it('includes context when provided', () => {
    const err = new KervyxError(
      KervyxErrorCode.DOCUMENT_TOO_LARGE,
      'too big',
      { context: { size: 1024000 } },
    );
    const json = err.toJSON();
    expect(json.context).toEqual({ size: 1024000 });
  });

  it('omits hint and context when not provided', () => {
    const err = new KervyxError(KervyxErrorCode.EXPIRED, 'expired');
    const json = err.toJSON();
    expect('hint' in json).toBe(false);
    expect('context' in json).toBe(false);
  });

  it('returns a plain object suitable for JSON.stringify', () => {
    const err = new KervyxError(
      KervyxErrorCode.AUTH_REQUIRED,
      'auth needed',
      { hint: 'Provide an API key', context: { endpoint: '/api/v1' } },
    );
    const serialized = JSON.stringify(err.toJSON());
    const parsed = JSON.parse(serialized);
    expect(parsed.code).toBe('KERVYX_E800');
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
    const url = errorDocsUrl(KervyxErrorCode.MISSING_ISSUER);
    expect(url).toBe('https://kervyx.dev/errors/KERVYX_E200');
  });

  it('returns different URLs for different codes', () => {
    const url1 = errorDocsUrl(KervyxErrorCode.NO_PRIVATE_KEY);
    const url2 = errorDocsUrl(KervyxErrorCode.SIGNATURE_INVALID);
    expect(url1).not.toBe(url2);
  });

  it('URL starts with https://', () => {
    const url = errorDocsUrl(KervyxErrorCode.CCL_SYNTAX_ERROR);
    expect(url).toMatch(/^https:\/\//);
  });

  it('URL contains the error code', () => {
    const url = errorDocsUrl(KervyxErrorCode.STORE_NOT_FOUND);
    expect(url).toContain('KERVYX_E502');
  });

  it('returns valid URLs for all error codes', () => {
    const codes = Object.values(KervyxErrorCode);
    for (const code of codes) {
      const url = errorDocsUrl(code);
      expect(url).toMatch(/^https:\/\/kervyx\.dev\/errors\/KERVYX_E\d{3}$/);
    }
  });
});

// ---------------------------------------------------------------------------
// formatError
// ---------------------------------------------------------------------------
describe('formatError', () => {
  it('includes the error code in brackets', () => {
    const err = new KervyxError(KervyxErrorCode.SIGNATURE_INVALID, 'bad signature');
    const formatted = formatError(err);
    expect(formatted).toContain('[KERVYX_E300]');
  });

  it('includes the error message', () => {
    const err = new KervyxError(KervyxErrorCode.EXPIRED, 'document has expired');
    const formatted = formatError(err);
    expect(formatted).toContain('document has expired');
  });

  it('includes the hint when provided', () => {
    const err = new KervyxError(
      KervyxErrorCode.MISSING_ISSUER,
      'no issuer set',
      { hint: 'Call setIssuer() first' },
    );
    const formatted = formatError(err);
    expect(formatted).toContain('Hint: Call setIssuer() first');
  });

  it('does not include a hint line when hint is absent', () => {
    const err = new KervyxError(KervyxErrorCode.EXPIRED, 'expired');
    const formatted = formatError(err);
    expect(formatted).not.toContain('Hint:');
  });

  it('includes a docs URL', () => {
    const err = new KervyxError(KervyxErrorCode.CCL_SYNTAX_ERROR, 'parse error');
    const formatted = formatError(err);
    expect(formatted).toContain('Docs: https://kervyx.dev/errors/KERVYX_E400');
  });

  it('formats a complete error with all fields', () => {
    const err = new KervyxError(
      KervyxErrorCode.MISSING_ISSUER,
      'Covenant requires an issuer',
      { hint: 'Set the issuer field before calling build()' },
    );
    const formatted = formatError(err);
    const lines = formatted.split('\n');
    expect(lines[0]).toBe('[KERVYX_E200] Covenant requires an issuer');
    expect(lines[1]).toBe('Hint: Set the issuer field before calling build()');
    expect(lines[2]).toBe('Docs: https://kervyx.dev/errors/KERVYX_E200');
  });

  it('formats an error without hint as two lines', () => {
    const err = new KervyxError(KervyxErrorCode.NO_KEY_PAIR, 'no key pair available');
    const formatted = formatError(err);
    const lines = formatted.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe('[KERVYX_E101] no key pair available');
    expect(lines[1]).toBe('Docs: https://kervyx.dev/errors/KERVYX_E101');
  });
});
