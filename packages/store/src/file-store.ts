/**
 * File-system-backed implementation of {@link CovenantStore}.
 *
 * Persists each covenant document as a separate JSON file on disk and
 * maintains a lightweight index file for fast listing, filtering, and
 * counting without reading every document.
 *
 * Key design decisions:
 *   - One `{id}.json` file per document.
 *   - A single `_index.json` file stores filterable metadata per document.
 *   - All writes are atomic (write to temp file, then rename).
 *   - Index mutations are serialized through a promise-based mutex.
 *   - The base directory is auto-created on the first write.
 *
 * @packageDocumentation
 */

import * as fs from 'fs/promises';
import * as path from 'path';

import type { CovenantDocument } from '@stele/core';
import { DocumentedSteleError as SteleError, DocumentedErrorCode as SteleErrorCode } from '@stele/types';

import type {
  CovenantStore,
  StoreFilter,
  StoreEvent,
  StoreEventType,
  StoreEventCallback,
} from './types.js';

// ─── Index types ────────────────────────────────────────────────────────────────

/** Metadata stored per document inside the index for fast filtering. */
interface IndexEntry {
  issuerId: string;
  beneficiaryId: string;
  createdAt: string;
  hasChain: boolean;
  tags: string[];
}

/** On-disk shape of the index file. */
interface StoreIndex {
  entries: Record<string, IndexEntry>;
}

// ─── Filter helper ──────────────────────────────────────────────────────────────

/**
 * Test whether an index entry satisfies every criterion in the filter.
 * All fields use AND semantics.
 */
function entryMatchesFilter(entry: IndexEntry, filter: StoreFilter): boolean {
  if (filter.issuerId !== undefined && entry.issuerId !== filter.issuerId) {
    return false;
  }

  if (filter.beneficiaryId !== undefined && entry.beneficiaryId !== filter.beneficiaryId) {
    return false;
  }

  if (filter.createdAfter !== undefined) {
    if (new Date(entry.createdAt) < new Date(filter.createdAfter)) {
      return false;
    }
  }

  if (filter.createdBefore !== undefined) {
    if (new Date(entry.createdAt) > new Date(filter.createdBefore)) {
      return false;
    }
  }

  if (filter.hasChain !== undefined) {
    if (filter.hasChain !== entry.hasChain) {
      return false;
    }
  }

  if (filter.tags !== undefined && filter.tags.length > 0) {
    for (const tag of filter.tags) {
      if (!entry.tags.includes(tag)) {
        return false;
      }
    }
  }

  return true;
}

// ─── FileStore ──────────────────────────────────────────────────────────────────

/**
 * File-system-backed implementation of {@link CovenantStore}.
 *
 * Documents are persisted as individual JSON files inside a configurable
 * base directory.  An `_index.json` sidecar file keeps enough metadata
 * to support fast filtering and counting without reading every document.
 *
 * All writes use an atomic "write-temp-then-rename" strategy so that a
 * crash mid-write never leaves a half-written file in place.  Index
 * mutations are serialized through a lightweight promise-based mutex so
 * concurrent callers cannot corrupt the index.
 */
export class FileStore implements CovenantStore {
  private readonly baseDir: string;
  private readonly indexPath: string;
  private readonly listeners = new Set<StoreEventCallback>();
  private indexLock: Promise<void> = Promise.resolve();
  private dirEnsured = false;

  /**
   * Create a new FileStore.
   *
   * @param baseDir - Directory where document and index files are stored.
   *                  Will be created (including parents) on the first write
   *                  if it does not already exist.
   */
  constructor(baseDir: string) {
    this.baseDir = path.resolve(baseDir);
    this.indexPath = path.join(this.baseDir, '_index.json');
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  /** Ensure the base directory exists (creates it lazily on first call). */
  private async ensureDir(): Promise<void> {
    if (!this.dirEnsured) {
      await fs.mkdir(this.baseDir, { recursive: true });
      this.dirEnsured = true;
    }
  }

  /** Return the absolute path where a document with the given ID is stored. */
  private docPath(id: string): string {
    return path.join(this.baseDir, `${encodeURIComponent(id)}.json`);
  }

  /** Read and parse the index file, returning an empty index on ENOENT. */
  private async readIndex(): Promise<StoreIndex> {
    try {
      const raw = await fs.readFile(this.indexPath, 'utf-8');
      return JSON.parse(raw) as StoreIndex;
    } catch (err: unknown) {
      if (err instanceof Error && (err as NodeJS.ErrnoException).code === 'ENOENT') {
        return { entries: {} };
      }
      throw err;
    }
  }

  /** Atomically write the index to disk. */
  private async writeIndex(index: StoreIndex): Promise<void> {
    await this.atomicWrite(this.indexPath, JSON.stringify(index, null, 2));
  }

  /**
   * Atomically write `data` to `filePath` by writing to a temporary file
   * in the same directory and then renaming.
   *
   * This two-step approach guarantees that readers never see a half-written
   * file: `fs.rename()` on the same filesystem is atomic on POSIX systems.
   * The temporary file name includes the PID, timestamp, and a random suffix
   * to avoid collisions between concurrent writers.
   */
  private async atomicWrite(filePath: string, data: string): Promise<void> {
    // Step 1: Write to a uniquely-named temp file in the same directory.
    const tmpPath = `${filePath}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`;
    await fs.writeFile(tmpPath, data, 'utf-8');
    // Step 2: Atomic rename replaces the target file in one syscall.
    await fs.rename(tmpPath, filePath);
  }

  /**
   * Serialize index mutations.  Only one `fn` runs at a time; subsequent
   * callers queue behind the current one.
   */
  private async withIndexLock<T>(fn: () => Promise<T>): Promise<T> {
    const previous = this.indexLock;
    let release!: () => void;
    this.indexLock = new Promise<void>((r) => {
      release = r;
    });
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  /** Build an {@link IndexEntry} from a full document. */
  private toIndexEntry(doc: CovenantDocument): IndexEntry {
    return {
      issuerId: doc.issuer.id,
      beneficiaryId: doc.beneficiary.id,
      createdAt: doc.createdAt,
      hasChain: doc.chain !== undefined,
      tags: doc.metadata?.tags ?? [],
    };
  }

  /** Broadcast a store event to all registered listeners. */
  private emit(type: StoreEventType, documentId: string, document?: CovenantDocument): void {
    const event: StoreEvent = {
      type,
      documentId,
      document,
      timestamp: new Date().toISOString(),
    };
    for (const cb of this.listeners) {
      cb(event);
    }
  }

  // ── Single-document CRUD ────────────────────────────────────────────────

  /**
   * Store a covenant document, overwriting any existing document with the same ID.
   *
   * Writes the document JSON to disk atomically (temp file + rename), then
   * updates the index under the mutex lock. Emits a `"put"` event on success.
   *
   * @param doc - The covenant document to store. Must have a non-empty `id`.
   * @throws {SteleError} If `doc` is null/undefined or has no valid `id`.
   *
   * @example
   * ```typescript
   * const store = new FileStore('/tmp/covenants');
   * await store.put(myCovenantDoc);
   * ```
   */
  async put(doc: CovenantDocument): Promise<void> {
    if (doc == null) {
      throw new SteleError(
        SteleErrorCode.STORE_MISSING_DOC,
        'put(): document is required',
        { hint: 'Pass a valid CovenantDocument object to store.' }
      );
    }
    if (!doc.id || (typeof doc.id === 'string' && doc.id.trim().length === 0)) {
      throw new SteleError(
        SteleErrorCode.STORE_MISSING_ID,
        'put(): document.id is required and must be a non-empty string',
        { hint: 'Ensure the document has a non-empty id field. Use buildCovenant() to generate properly identified documents.' }
      );
    }
    await this.ensureDir();
    await this.atomicWrite(this.docPath(doc.id), JSON.stringify(doc, null, 2));
    await this.withIndexLock(async () => {
      const index = await this.readIndex();
      index.entries[doc.id] = this.toIndexEntry(doc);
      await this.writeIndex(index);
    });
    this.emit('put', doc.id, doc);
  }

  /**
   * Retrieve a covenant document by its ID.
   *
   * Reads the document JSON file directly from disk. Returns `undefined`
   * if no document with the given ID exists (ENOENT).
   *
   * @param id - The document ID to look up.
   * @returns The document, or `undefined` if not found.
   *
   * @example
   * ```typescript
   * const doc = await store.get('abc123...');
   * if (doc) console.log(doc.constraints);
   * ```
   */
  async get(id: string): Promise<CovenantDocument | undefined> {
    try {
      const raw = await fs.readFile(this.docPath(id), 'utf-8');
      return JSON.parse(raw) as CovenantDocument;
    } catch (err: unknown) {
      if (err instanceof Error && (err as NodeJS.ErrnoException).code === 'ENOENT') {
        return undefined;
      }
      throw err;
    }
  }

  /**
   * Check whether a document with the given ID exists in the store.
   *
   * Uses the in-memory index rather than checking the filesystem,
   * so this is a fast O(1) lookup.
   *
   * @param id - The document ID to check.
   * @returns `true` if the document exists, `false` otherwise.
   */
  async has(id: string): Promise<boolean> {
    const index = await this.readIndex();
    return id in index.entries;
  }

  /**
   * Delete a document by its ID.
   *
   * Removes the document file from disk and its index entry atomically
   * (under the index mutex). Emits a `"delete"` event if the document
   * existed and was successfully removed.
   *
   * @param id - The document ID to delete.
   * @returns `true` if the document was found and deleted, `false` if it did not exist.
   */
  async delete(id: string): Promise<boolean> {
    const deleted = await this.withIndexLock(async () => {
      const index = await this.readIndex();
      if (!(id in index.entries)) {
        return false;
      }
      delete index.entries[id];
      try {
        await fs.unlink(this.docPath(id));
      } catch (err: unknown) {
        if (!(err instanceof Error && (err as NodeJS.ErrnoException).code === 'ENOENT')) throw err;
      }
      await this.writeIndex(index);
      return true;
    });
    if (deleted) {
      this.emit('delete', id);
    }
    return deleted;
  }

  /**
   * List all documents matching an optional filter.
   *
   * Uses the index to find matching document IDs, then reads each
   * document file from disk. If no filter is provided, returns all
   * stored documents.
   *
   * @param filter - Optional filter criteria (issuer, beneficiary, date range, tags, etc.).
   * @returns An array of matching covenant documents.
   *
   * @example
   * ```typescript
   * // All documents by a specific issuer
   * const docs = await store.list({ issuerId: 'alice' });
   *
   * // All documents (no filter)
   * const all = await store.list();
   * ```
   */
  async list(filter?: StoreFilter): Promise<CovenantDocument[]> {
    const index = await this.readIndex();

    let ids: string[];
    if (filter) {
      ids = Object.entries(index.entries)
        .filter(([, entry]) => entryMatchesFilter(entry, filter))
        .map(([id]) => id);
    } else {
      ids = Object.keys(index.entries);
    }

    const docs: CovenantDocument[] = [];
    for (const id of ids) {
      const doc = await this.get(id);
      if (doc) {
        docs.push(doc);
      }
    }
    return docs;
  }

  /**
   * Count documents matching an optional filter.
   *
   * Operates entirely on the in-memory index without reading document
   * files, making it significantly faster than `list().length` for
   * large stores.
   *
   * @param filter - Optional filter criteria. Counts all documents when omitted.
   * @returns The number of matching documents.
   */
  async count(filter?: StoreFilter): Promise<number> {
    const index = await this.readIndex();
    if (!filter) {
      return Object.keys(index.entries).length;
    }
    return Object.values(index.entries).filter((entry) =>
      entryMatchesFilter(entry, filter),
    ).length;
  }

  // ── Batch operations ────────────────────────────────────────────────────

  /**
   * Store multiple documents in a single batch operation.
   *
   * Document files are written in parallel for throughput, then the
   * index is updated in a single atomic step under the mutex. When
   * the same ID appears multiple times, only the last occurrence is kept.
   * Emits a `"put"` event for each document in the original array.
   *
   * @param docs - Array of covenant documents to store.
   *
   * @example
   * ```typescript
   * await store.putBatch([doc1, doc2, doc3]);
   * ```
   */
  async putBatch(docs: CovenantDocument[]): Promise<void> {
    if (docs.length === 0) return;
    await this.ensureDir();

    // Deduplicate: when the same ID appears multiple times, keep the last occurrence.
    const deduped = new Map<string, CovenantDocument>();
    for (const doc of docs) {
      deduped.set(doc.id, doc);
    }
    const uniqueDocs = Array.from(deduped.values());

    // Write all document files in parallel.
    await Promise.all(
      uniqueDocs.map((doc) =>
        this.atomicWrite(this.docPath(doc.id), JSON.stringify(doc, null, 2)),
      ),
    );

    // Update the index in a single atomic step.
    await this.withIndexLock(async () => {
      const index = await this.readIndex();
      for (const doc of uniqueDocs) {
        index.entries[doc.id] = this.toIndexEntry(doc);
      }
      await this.writeIndex(index);
    });

    // Emit events for every doc in the original list (preserving batch semantics).
    for (const doc of docs) {
      this.emit('put', doc.id, doc);
    }
  }

  /**
   * Retrieve multiple documents by their IDs in a single call.
   *
   * Returns results in the same order as the input IDs. Missing
   * documents are represented as `undefined` in the output array.
   *
   * @param ids - Array of document IDs to retrieve.
   * @returns Array of documents (or `undefined`) corresponding to each input ID.
   */
  async getBatch(ids: string[]): Promise<(CovenantDocument | undefined)[]> {
    return Promise.all(ids.map((id) => this.get(id)));
  }

  /**
   * Delete multiple documents by their IDs in a single batch operation.
   *
   * All deletions and the index update happen under a single mutex
   * acquisition. Emits a `"delete"` event for each successfully
   * deleted document (after the lock is released).
   *
   * @param ids - Array of document IDs to delete.
   * @returns The number of documents that were actually deleted.
   */
  async deleteBatch(ids: string[]): Promise<number> {
    if (ids.length === 0) return 0;

    const deletedIds: string[] = [];

    await this.withIndexLock(async () => {
      const index = await this.readIndex();
      for (const id of ids) {
        if (id in index.entries) {
          delete index.entries[id];
          try {
            await fs.unlink(this.docPath(id));
          } catch (err: unknown) {
            if (!(err instanceof Error && (err as NodeJS.ErrnoException).code === 'ENOENT')) throw err;
          }
          deletedIds.push(id);
        }
      }
      await this.writeIndex(index);
    });

    // Emit events outside the lock.
    for (const id of deletedIds) {
      this.emit('delete', id);
    }

    return deletedIds.length;
  }

  // ── Event system ────────────────────────────────────────────────────────

  /**
   * Register a callback to be invoked on store events (put, delete).
   *
   * @param callback - The event handler function.
   *
   * @example
   * ```typescript
   * store.onEvent((event) => {
   *   console.log(`${event.type}: ${event.documentId}`);
   * });
   * ```
   */
  onEvent(callback: StoreEventCallback): void {
    this.listeners.add(callback);
  }

  /**
   * Unregister a previously registered event callback.
   *
   * @param callback - The same function reference that was passed to {@link onEvent}.
   */
  offEvent(callback: StoreEventCallback): void {
    this.listeners.delete(callback);
  }
}
