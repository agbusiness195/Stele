/**
 * Runtime type guards and input sanitization utilities for the Stele protocol.
 * Use these at system boundaries (API inputs, deserialization, user-facing functions).
 */

// ─── Type Guards ────────────────────────────────────────────────────────────────

/**
 * Check whether `value` is a non-empty string (after trimming).
 *
 * @param value - The value to check.
 * @returns `true` if `value` is a string with at least one non-whitespace character.
 *
 * @example
 * ```typescript
 * isNonEmptyString('hello'); // true
 * isNonEmptyString('  ');    // false
 * ```
 */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Check whether `value` is a valid hexadecimal string (even length, [0-9a-fA-F]).
 *
 * @param value - The value to check.
 * @returns `true` if `value` is a valid even-length hex string.
 *
 * @example
 * ```typescript
 * isValidHex('a1b2c3'); // true
 * isValidHex('xyz');    // false
 * ```
 */
export function isValidHex(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length % 2 === 0 &&
    /^[0-9a-fA-F]+$/.test(value)
  );
}

/**
 * Check whether `value` is a valid identifier (64-character hex string, i.e. SHA-256 digest).
 *
 * @param value - The value to check.
 * @returns `true` if `value` is a 64-character hex string.
 */
export function isValidId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length === 64 &&
    /^[0-9a-fA-F]{64}$/.test(value)
  );
}

/**
 * Check whether `value` is a valid Ed25519 public key (64-character hex string).
 *
 * @param value - The value to check.
 * @returns `true` if `value` is a 64-character hex string representing a public key.
 */
export function isValidPublicKey(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length === 64 &&
    /^[0-9a-fA-F]{64}$/.test(value)
  );
}

/**
 * Check whether `value` is a valid Ed25519 signature (128-character hex string).
 *
 * @param value - The value to check.
 * @returns `true` if `value` is a 128-character hex string representing a signature.
 */
export function isValidSignature(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length === 128 &&
    /^[0-9a-fA-F]{128}$/.test(value)
  );
}

/**
 * Check whether `value` is a valid ISO 8601 date string.
 *
 * Accepts formats like `2025-01-15`, `2025-01-15T12:00:00Z`,
 * and `2025-01-15T12:00:00.000+05:30`.
 *
 * @param value - The value to check.
 * @returns `true` if `value` is a valid ISO 8601 date string that parses to a real date.
 */
export function isValidISODate(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0) return false;

  // Must match ISO 8601 pattern (fractional seconds limited to 1-9 digits to prevent ReDoS)
  const iso8601 =
    /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})?)?$/;
  if (!iso8601.test(value)) return false;

  // Must parse to a valid date (reject things like 2025-13-45)
  const date = new Date(value);
  return !Number.isNaN(date.getTime());
}

/**
 * Check whether `value` is a valid semantic version string (e.g. `1.2.3` or `0.1.0-beta.1`).
 *
 * @param value - The value to check.
 * @returns `true` if `value` matches a semver-like pattern.
 */
export function isValidVersion(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  return /^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$/.test(value);
}

/**
 * Check whether `value` is a plain object (not an array, null, or an object with
 * a non-Object prototype). This guards against prototype pollution attacks.
 *
 * @param value - The value to check.
 * @returns `true` if `value` is a plain object created by `{}` or `Object.create(null)`.
 */
export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// ─── Sanitization Utilities ─────────────────────────────────────────────────────

/**
 * Sanitize a string value by trimming whitespace, truncating to `maxLength`,
 * and stripping control characters.
 *
 * Stripped character ranges:
 * - ASCII C0 controls (U+0000--U+001F) **except** tab (U+0009), newline (U+000A),
 *   and carriage return (U+000D)
 * - ASCII DEL (U+007F)
 * - ISO 8859 C1 controls (U+0080--U+009F) -- these are invisible formatting
 *   characters that have no valid use in user-facing text and can be abused
 *   for text-direction attacks or invisible content injection
 *
 * @param value     - The string to sanitize.
 * @param maxLength - Maximum allowed length (default: 10_000).
 * @returns The sanitized string.
 */
export function sanitizeString(value: string, maxLength: number = 10_000): string {
  // Trim leading and trailing whitespace
  let result = value.trim();

  // Truncate to maxLength
  if (result.length > maxLength) {
    result = result.slice(0, maxLength);
  }

  // Strip ASCII C0 controls (except tab, newline, CR), DEL, and C1 controls (U+0080–U+009F)
  // eslint-disable-next-line no-control-regex
  result = result.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F]/g, '');

  return result;
}

/**
 * Keys that are dangerous if present in parsed JSON (prototype pollution vectors).
 *
 * - `__proto__`   -- directly sets the prototype chain on assignment
 * - `constructor` -- can be used to access `constructor.prototype` and pollute
 * - `prototype`   -- allows modification of an object's prototype properties
 *
 * @see https://github.com/advisories/GHSA-hrpp-h998-j3pp for background on prototype pollution
 */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Recursively check an object for dangerous keys that could lead to prototype pollution.
 *
 * Walks every nested object and array element, checking each key against the
 * {@link DANGEROUS_KEYS} set. This provides defence-in-depth on top of
 * `JSON.parse`, which itself does not prevent `__proto__` keys from appearing
 * in parsed output.
 *
 * Recursion is bounded by {@link MAX_SANITIZE_DEPTH} to prevent stack overflow
 * attacks via deeply nested payloads.
 *
 * @param obj   - The value to scan (recursively walks objects and arrays).
 * @param depth - Current recursion depth (internal, callers should omit).
 * @throws {Error} If a dangerous key is found or maximum depth is exceeded.
 */
/** Maximum recursion depth for JSON sanitization to prevent stack overflow on deeply nested input. */
const MAX_SANITIZE_DEPTH = 64;

export function assertNoDangerousKeys(obj: unknown, depth: number = 0): void {
  if (depth > MAX_SANITIZE_DEPTH) {
    throw new Error(
      `JSON input exceeds maximum nesting depth of ${MAX_SANITIZE_DEPTH}`,
    );
  }
  if (typeof obj !== 'object' || obj === null) return;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      assertNoDangerousKeys(item, depth + 1);
    }
    return;
  }

  for (const key of Object.keys(obj)) {
    if (DANGEROUS_KEYS.has(key)) {
      throw new Error(
        `Potentially dangerous key "${key}" detected in JSON input`,
      );
    }
    assertNoDangerousKeys((obj as Record<string, unknown>)[key], depth + 1);
  }
}

/**
 * Parse a JSON string with prototype pollution protection.
 *
 * After parsing, the result is recursively checked for keys that could lead to
 * prototype pollution (`__proto__`, `constructor`, `prototype`). If any such key
 * is found, an error is thrown.
 *
 * @param value - The JSON string to parse.
 * @returns The parsed value.
 * @throws {Error} When parsing fails or a dangerous key is detected.
 *
 * @example
 * ```typescript
 * const data = sanitizeJsonInput('{"name": "safe"}'); // OK
 * sanitizeJsonInput('{"__proto__": {}}'); // throws Error
 * ```
 */
export function sanitizeJsonInput(value: string): unknown {
  const parsed: unknown = JSON.parse(value);
  assertNoDangerousKeys(parsed);
  return parsed;
}

// ─── Deep Freeze ────────────────────────────────────────────────────────────────

/**
 * Deeply freeze an object and all of its nested properties to prevent mutation.
 *
 * Arrays and plain objects are frozen recursively. Primitive values and
 * already-frozen objects are returned as-is.
 *
 * @param obj - The value to deep-freeze.
 * @returns The same value, deeply frozen.
 */
export function freezeDeep<T>(obj: T, depth: number = 0): Readonly<T> {
  if (obj === null || obj === undefined || typeof obj !== 'object') {
    return obj as Readonly<T>;
  }

  // Don't re-freeze already-frozen objects
  if (Object.isFrozen(obj)) {
    return obj as Readonly<T>;
  }

  // Prevent stack overflow on deeply nested input
  if (depth > MAX_SANITIZE_DEPTH) {
    return obj as Readonly<T>;
  }

  Object.freeze(obj);

  if (Array.isArray(obj)) {
    for (const item of obj) {
      freezeDeep(item, depth + 1);
    }
  } else {
    for (const value of Object.values(obj as Record<string, unknown>)) {
      freezeDeep(value, depth + 1);
    }
  }

  return obj as Readonly<T>;
}

// ─── Exhaustiveness Check ───────────────────────────────────────────────────────

/**
 * Helper for exhaustiveness checking in `switch` statements.
 *
 * Place this in the `default` branch to get a compile-time error if a case
 * is not handled, and a runtime error if an unexpected value slips through.
 *
 * @param value - The value that should never occur.
 * @throws Error always, indicating an unhandled case.
 *
 * @example
 * ```ts
 * type Direction = 'north' | 'south';
 * function move(dir: Direction) {
 *   switch (dir) {
 *     case 'north': return go(0, 1);
 *     case 'south': return go(0, -1);
 *     default: assertNever(dir);
 *   }
 * }
 * ```
 */
export function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${String(value)}`);
}
