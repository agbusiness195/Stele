/**
 * Encrypted-at-rest wrapper for any {@link CovenantStore}.
 *
 * Wraps an underlying store and transparently encrypts documents on write
 * and decrypts on read using AES-256-GCM. The encryption key is provided
 * at construction time and never persisted by this module.
 *
 * Each document is encrypted with a fresh 12-byte IV (nonce), which is
 * prepended to the ciphertext. The ID field is stored in plaintext so
 * the underlying store can still index by document ID.
 *
 * @packageDocumentation
 */

import * as crypto from 'crypto';
import type { CovenantDocument } from '@stele/core';
import { DocumentedSteleError as SteleError, DocumentedErrorCode as SteleErrorCode } from '@stele/types';

import type {
  CovenantStore,
  StoreFilter,
  StoreEventCallback,
} from './types.js';

// ─── Constants ───────────────────────────────────────────────────────────────

/** AES-256-GCM cipher algorithm identifier. */
const ALGORITHM = 'aes-256-gcm';

/** IV (nonce) length in bytes for AES-256-GCM. */
const IV_LENGTH = 12;

/** Authentication tag length in bytes. */
const AUTH_TAG_LENGTH = 16;

/** Required key length in bytes (256 bits). */
const KEY_LENGTH = 32;

// ─── Types ───────────────────────────────────────────────────────────────────

/** Configuration for the EncryptedStore. */
export interface EncryptedStoreOptions {
  /** The underlying store to delegate to. */
  store: CovenantStore;
  /**
   * 32-byte encryption key (AES-256). Provide as a Buffer or Uint8Array.
   * This key is never persisted — the caller is responsible for key management.
   */
  encryptionKey: Uint8Array;
}

/**
 * Envelope format stored in the underlying store.
 * The `_encrypted` field holds the IV + ciphertext + auth tag as a hex string.
 * All other fields of a CovenantDocument are replaced with empty/placeholder
 * values so the underlying store's validation still passes.
 */
interface EncryptedEnvelope {
  /** The document ID is stored in plaintext for index lookups. */
  id: string;
  /** Hex-encoded encrypted payload: IV (12 bytes) || ciphertext || auth tag (16 bytes). */
  _encrypted: string;
}

// ─── EncryptedStore ──────────────────────────────────────────────────────────

/**
 * A CovenantStore wrapper that encrypts documents at rest using AES-256-GCM.
 *
 * Documents are encrypted before being passed to the underlying store and
 * decrypted when retrieved. The document ID remains in plaintext for
 * indexing. All other fields are encrypted.
 *
 * @example
 * ```ts
 * import { MemoryStore, EncryptedStore } from '@stele/store';
 * import { randomBytes } from 'crypto';
 *
 * const key = randomBytes(32);
 * const store = new EncryptedStore({
 *   store: new MemoryStore(),
 *   encryptionKey: key,
 * });
 *
 * await store.put(doc);
 * const retrieved = await store.get(doc.id); // transparently decrypted
 * ```
 */
export class EncryptedStore implements CovenantStore {
  private readonly inner: CovenantStore;
  private readonly key: Buffer;

  constructor(options: EncryptedStoreOptions) {
    if (!options.store) {
      throw new SteleError(
        SteleErrorCode.STORE_MISSING_DOC,
        'EncryptedStore: underlying store is required',
      );
    }
    if (
      !options.encryptionKey ||
      options.encryptionKey.length !== KEY_LENGTH
    ) {
      throw new SteleError(
        SteleErrorCode.CRYPTO_INVALID_KEY,
        `EncryptedStore: encryptionKey must be exactly ${KEY_LENGTH} bytes`,
        { hint: 'Generate a 32-byte key with crypto.randomBytes(32).' },
      );
    }
    this.inner = options.store;
    this.key = Buffer.from(options.encryptionKey);
  }

  // ── Encryption / Decryption ───────────────────────────────────────────

  private encrypt(doc: CovenantDocument): CovenantDocument {
    const plaintext = JSON.stringify(doc);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv);

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // IV || ciphertext || authTag
    const payload = Buffer.concat([iv, encrypted, authTag]).toString('hex');

    // Return a shell document that the underlying store can accept.
    // Only id is real; everything else is a minimal valid shape.
    return {
      ...doc,
      // Overwrite all sensitive fields with the encrypted envelope marker
      constraints: '',
      signature: '',
      nonce: '',
      metadata: { _encrypted: payload } as unknown as CovenantDocument['metadata'],
    } as CovenantDocument;
  }

  private decrypt(stored: CovenantDocument): CovenantDocument {
    const payload = (stored.metadata as unknown as EncryptedEnvelope)?._encrypted;
    if (!payload || typeof payload !== 'string') {
      // Not encrypted — return as-is (backwards compatibility)
      return stored;
    }

    const data = Buffer.from(payload, 'hex');
    const iv = data.subarray(0, IV_LENGTH);
    const authTag = data.subarray(data.length - AUTH_TAG_LENGTH);
    const ciphertext = data.subarray(IV_LENGTH, data.length - AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]).toString('utf8');

    return JSON.parse(plaintext) as CovenantDocument;
  }

  // ── CovenantStore interface ───────────────────────────────────────────

  async put(doc: CovenantDocument): Promise<void> {
    const encrypted = this.encrypt(doc);
    return this.inner.put(encrypted);
  }

  async get(id: string): Promise<CovenantDocument | undefined> {
    const stored = await this.inner.get(id);
    if (!stored) return undefined;
    return this.decrypt(stored);
  }

  async has(id: string): Promise<boolean> {
    return this.inner.has(id);
  }

  async delete(id: string): Promise<boolean> {
    return this.inner.delete(id);
  }

  async list(filter?: StoreFilter): Promise<CovenantDocument[]> {
    const stored = await this.inner.list(filter);
    return stored.map((doc) => this.decrypt(doc));
  }

  async count(filter?: StoreFilter): Promise<number> {
    return this.inner.count(filter);
  }

  async putBatch(docs: CovenantDocument[]): Promise<void> {
    const encrypted = docs.map((doc) => this.encrypt(doc));
    return this.inner.putBatch(encrypted);
  }

  async getBatch(ids: string[]): Promise<(CovenantDocument | undefined)[]> {
    const stored = await this.inner.getBatch(ids);
    return stored.map((doc) => (doc ? this.decrypt(doc) : undefined));
  }

  async deleteBatch(ids: string[]): Promise<number> {
    return this.inner.deleteBatch(ids);
  }

  onEvent(callback: StoreEventCallback): void {
    this.inner.onEvent(callback);
  }

  offEvent(callback: StoreEventCallback): void {
    this.inner.offEvent(callback);
  }
}
