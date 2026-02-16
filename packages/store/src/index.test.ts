import { describe, it, expect, beforeEach, vi } from 'vitest';
import { MemoryStore } from './index';
import type { CovenantStore, StoreEvent, StoreEventCallback } from './index';
import type { CovenantDocument } from '@stele/core';
import { DocumentedSteleError as SteleError, DocumentedErrorCode as SteleErrorCode } from '@stele/types';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Minimal CovenantDocument factory for testing. */
function makeDoc(overrides: Partial<CovenantDocument> & { id: string }): CovenantDocument {
  return {
    version: '1.0',
    issuer: {
      id: 'issuer-1',
      publicKey: 'aa'.repeat(32),
      role: 'issuer' as const,
    },
    beneficiary: {
      id: 'beneficiary-1',
      publicKey: 'bb'.repeat(32),
      role: 'beneficiary' as const,
    },
    constraints: 'PERMIT read\nDENY write',
    nonce: 'cc'.repeat(32),
    createdAt: '2025-06-01T00:00:00.000Z',
    signature: 'dd'.repeat(64),
    ...overrides,
  } as CovenantDocument;
}

// ---------------------------------------------------------------------------
// MemoryStore — basic instantiation
// ---------------------------------------------------------------------------
describe('MemoryStore - instantiation', () => {
  it('can be constructed with no arguments', () => {
    const store = new MemoryStore();
    expect(store).toBeDefined();
    expect(store.size).toBe(0);
  });

  it('implements CovenantStore interface', () => {
    const store: CovenantStore = new MemoryStore();
    expect(typeof store.put).toBe('function');
    expect(typeof store.get).toBe('function');
    expect(typeof store.has).toBe('function');
    expect(typeof store.delete).toBe('function');
    expect(typeof store.list).toBe('function');
    expect(typeof store.count).toBe('function');
    expect(typeof store.putBatch).toBe('function');
    expect(typeof store.getBatch).toBe('function');
    expect(typeof store.deleteBatch).toBe('function');
    expect(typeof store.onEvent).toBe('function');
    expect(typeof store.offEvent).toBe('function');
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — put / get / has / delete
// ---------------------------------------------------------------------------
describe('MemoryStore - CRUD', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('put stores a document and get retrieves it', async () => {
    const doc = makeDoc({ id: 'doc-1' });
    await store.put(doc);
    const retrieved = await store.get('doc-1');
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe('doc-1');
  });

  it('get returns undefined for a missing ID', async () => {
    const result = await store.get('nonexistent');
    expect(result).toBeUndefined();
  });

  it('has returns true for an existing document', async () => {
    const doc = makeDoc({ id: 'doc-1' });
    await store.put(doc);
    expect(await store.has('doc-1')).toBe(true);
  });

  it('has returns false for a missing document', async () => {
    expect(await store.has('missing')).toBe(false);
  });

  it('delete removes an existing document and returns true', async () => {
    const doc = makeDoc({ id: 'doc-1' });
    await store.put(doc);
    const deleted = await store.delete('doc-1');
    expect(deleted).toBe(true);
    expect(await store.has('doc-1')).toBe(false);
  });

  it('delete returns false for a missing document', async () => {
    const deleted = await store.delete('nonexistent');
    expect(deleted).toBe(false);
  });

  it('put overwrites an existing document with the same ID', async () => {
    const doc1 = makeDoc({ id: 'doc-1', constraints: 'PERMIT read' });
    const doc2 = makeDoc({ id: 'doc-1', constraints: 'DENY write' });
    await store.put(doc1);
    await store.put(doc2);
    const retrieved = await store.get('doc-1');
    expect(retrieved!.constraints).toBe('DENY write');
    expect(store.size).toBe(1);
  });

  it('put and delete update the size property', async () => {
    expect(store.size).toBe(0);
    await store.put(makeDoc({ id: 'a' }));
    expect(store.size).toBe(1);
    await store.put(makeDoc({ id: 'b' }));
    expect(store.size).toBe(2);
    await store.delete('a');
    expect(store.size).toBe(1);
    await store.delete('b');
    expect(store.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — list
// ---------------------------------------------------------------------------
describe('MemoryStore - list', () => {
  let store: MemoryStore;

  beforeEach(async () => {
    store = new MemoryStore();
    await store.put(makeDoc({ id: 'doc-1' }));
    await store.put(makeDoc({ id: 'doc-2' }));
    await store.put(makeDoc({ id: 'doc-3' }));
  });

  it('list without filter returns all documents', async () => {
    const docs = await store.list();
    expect(docs.length).toBe(3);
  });

  it('list with empty filter returns all documents', async () => {
    const docs = await store.list({});
    expect(docs.length).toBe(3);
  });

  it('list filters by issuerId', async () => {
    await store.put(makeDoc({
      id: 'doc-special',
      issuer: { id: 'special-issuer', publicKey: 'aa'.repeat(32), role: 'issuer' },
    }));
    const docs = await store.list({ issuerId: 'special-issuer' });
    expect(docs.length).toBe(1);
    expect(docs[0]!.id).toBe('doc-special');
  });

  it('list filters by beneficiaryId', async () => {
    await store.put(makeDoc({
      id: 'doc-special',
      beneficiary: { id: 'special-ben', publicKey: 'bb'.repeat(32), role: 'beneficiary' },
    }));
    const docs = await store.list({ beneficiaryId: 'special-ben' });
    expect(docs.length).toBe(1);
    expect(docs[0]!.id).toBe('doc-special');
  });

  it('list filters by createdAfter', async () => {
    await store.put(makeDoc({ id: 'old', createdAt: '2020-01-01T00:00:00.000Z' }));
    await store.put(makeDoc({ id: 'new', createdAt: '2026-01-01T00:00:00.000Z' }));
    const docs = await store.list({ createdAfter: '2025-12-01T00:00:00.000Z' });
    expect(docs.length).toBe(1);
    expect(docs[0]!.id).toBe('new');
  });

  it('list filters by createdBefore', async () => {
    await store.put(makeDoc({ id: 'old', createdAt: '2020-01-01T00:00:00.000Z' }));
    await store.put(makeDoc({ id: 'new', createdAt: '2026-01-01T00:00:00.000Z' }));
    const docs = await store.list({ createdBefore: '2021-01-01T00:00:00.000Z' });
    expect(docs.length).toBe(1);
    expect(docs[0]!.id).toBe('old');
  });

  it('list filters by hasChain = true', async () => {
    await store.put(makeDoc({
      id: 'chained',
      chain: { parentId: 'parent-1' as any, relation: 'delegates' as any, depth: 1 },
    }));
    const docs = await store.list({ hasChain: true });
    expect(docs.length).toBe(1);
    expect(docs[0]!.id).toBe('chained');
  });

  it('list filters by hasChain = false', async () => {
    await store.put(makeDoc({
      id: 'chained',
      chain: { parentId: 'parent-1' as any, relation: 'delegates' as any, depth: 1 },
    }));
    // doc-1, doc-2, doc-3 have no chain
    const docs = await store.list({ hasChain: false });
    expect(docs.length).toBe(3);
    expect(docs.every((d) => d.chain === undefined)).toBe(true);
  });

  it('list filters by tags (AND semantics)', async () => {
    await store.put(makeDoc({
      id: 'tagged-1',
      metadata: { tags: ['ai', 'safety', 'governance'] },
    }));
    await store.put(makeDoc({
      id: 'tagged-2',
      metadata: { tags: ['ai', 'compliance'] },
    }));
    const docs = await store.list({ tags: ['ai', 'safety'] });
    expect(docs.length).toBe(1);
    expect(docs[0]!.id).toBe('tagged-1');
  });

  it('list returns empty when no documents match', async () => {
    const docs = await store.list({ issuerId: 'nobody' });
    expect(docs.length).toBe(0);
  });

  it('list with combined filters (AND)', async () => {
    await store.put(makeDoc({
      id: 'match',
      issuer: { id: 'alice', publicKey: 'aa'.repeat(32), role: 'issuer' },
      createdAt: '2026-01-15T00:00:00.000Z',
    }));
    await store.put(makeDoc({
      id: 'no-match-issuer',
      issuer: { id: 'bob', publicKey: 'aa'.repeat(32), role: 'issuer' },
      createdAt: '2026-01-15T00:00:00.000Z',
    }));
    await store.put(makeDoc({
      id: 'no-match-date',
      issuer: { id: 'alice', publicKey: 'aa'.repeat(32), role: 'issuer' },
      createdAt: '2020-01-01T00:00:00.000Z',
    }));
    const docs = await store.list({
      issuerId: 'alice',
      createdAfter: '2026-01-01T00:00:00.000Z',
    });
    expect(docs.length).toBe(1);
    expect(docs[0]!.id).toBe('match');
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — count
// ---------------------------------------------------------------------------
describe('MemoryStore - count', () => {
  let store: MemoryStore;

  beforeEach(async () => {
    store = new MemoryStore();
    await store.put(makeDoc({ id: 'doc-1' }));
    await store.put(makeDoc({ id: 'doc-2' }));
  });

  it('count without filter returns total documents', async () => {
    expect(await store.count()).toBe(2);
  });

  it('count with filter returns matching count', async () => {
    await store.put(makeDoc({
      id: 'special',
      issuer: { id: 'alice', publicKey: 'aa'.repeat(32), role: 'issuer' },
    }));
    expect(await store.count({ issuerId: 'alice' })).toBe(1);
    expect(await store.count({ issuerId: 'issuer-1' })).toBe(2);
  });

  it('count returns 0 for empty store', async () => {
    const emptyStore = new MemoryStore();
    expect(await emptyStore.count()).toBe(0);
  });

  it('count returns 0 when no documents match', async () => {
    expect(await store.count({ issuerId: 'nonexistent' })).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — batch operations
// ---------------------------------------------------------------------------
describe('MemoryStore - batch operations', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('putBatch stores multiple documents', async () => {
    const docs = [makeDoc({ id: 'a' }), makeDoc({ id: 'b' }), makeDoc({ id: 'c' })];
    await store.putBatch(docs);
    expect(store.size).toBe(3);
    expect(await store.has('a')).toBe(true);
    expect(await store.has('b')).toBe(true);
    expect(await store.has('c')).toBe(true);
  });

  it('putBatch with empty array does nothing', async () => {
    await store.putBatch([]);
    expect(store.size).toBe(0);
  });

  it('getBatch retrieves multiple documents in order', async () => {
    await store.putBatch([makeDoc({ id: 'a' }), makeDoc({ id: 'b' }), makeDoc({ id: 'c' })]);
    const results = await store.getBatch(['c', 'a', 'b']);
    expect(results.length).toBe(3);
    expect(results[0]!.id).toBe('c');
    expect(results[1]!.id).toBe('a');
    expect(results[2]!.id).toBe('b');
  });

  it('getBatch returns undefined for missing IDs', async () => {
    await store.put(makeDoc({ id: 'a' }));
    const results = await store.getBatch(['a', 'missing', 'a']);
    expect(results.length).toBe(3);
    expect(results[0]!.id).toBe('a');
    expect(results[1]).toBeUndefined();
    expect(results[2]!.id).toBe('a');
  });

  it('getBatch with empty array returns empty array', async () => {
    const results = await store.getBatch([]);
    expect(results).toEqual([]);
  });

  it('deleteBatch removes multiple documents', async () => {
    await store.putBatch([makeDoc({ id: 'a' }), makeDoc({ id: 'b' }), makeDoc({ id: 'c' })]);
    const deleted = await store.deleteBatch(['a', 'c']);
    expect(deleted).toBe(2);
    expect(store.size).toBe(1);
    expect(await store.has('b')).toBe(true);
  });

  it('deleteBatch returns count of actually deleted documents', async () => {
    await store.put(makeDoc({ id: 'a' }));
    const deleted = await store.deleteBatch(['a', 'nonexistent1', 'nonexistent2']);
    expect(deleted).toBe(1);
  });

  it('deleteBatch with empty array deletes nothing', async () => {
    await store.put(makeDoc({ id: 'a' }));
    const deleted = await store.deleteBatch([]);
    expect(deleted).toBe(0);
    expect(store.size).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — event system
// ---------------------------------------------------------------------------
describe('MemoryStore - events', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('onEvent registers a listener that receives put events', async () => {
    const events: StoreEvent[] = [];
    store.onEvent((e) => events.push(e));

    const doc = makeDoc({ id: 'doc-1' });
    await store.put(doc);

    expect(events.length).toBe(1);
    expect(events[0]!.type).toBe('put');
    expect(events[0]!.documentId).toBe('doc-1');
    expect(events[0]!.document).toBeDefined();
    expect(events[0]!.document!.id).toBe('doc-1');
  });

  it('onEvent registers a listener that receives delete events', async () => {
    const events: StoreEvent[] = [];
    const doc = makeDoc({ id: 'doc-1' });
    await store.put(doc);

    store.onEvent((e) => events.push(e));
    await store.delete('doc-1');

    expect(events.length).toBe(1);
    expect(events[0]!.type).toBe('delete');
    expect(events[0]!.documentId).toBe('doc-1');
    expect(events[0]!.document).toBeUndefined();
  });

  it('delete of non-existent document does not emit event', async () => {
    const events: StoreEvent[] = [];
    store.onEvent((e) => events.push(e));
    await store.delete('nonexistent');
    expect(events.length).toBe(0);
  });

  it('offEvent unregisters a listener', async () => {
    const events: StoreEvent[] = [];
    const listener: StoreEventCallback = (e) => events.push(e);
    store.onEvent(listener);

    await store.put(makeDoc({ id: 'a' }));
    expect(events.length).toBe(1);

    store.offEvent(listener);
    await store.put(makeDoc({ id: 'b' }));
    expect(events.length).toBe(1); // no new events
  });

  it('multiple listeners receive the same event', async () => {
    const events1: StoreEvent[] = [];
    const events2: StoreEvent[] = [];
    store.onEvent((e) => events1.push(e));
    store.onEvent((e) => events2.push(e));

    await store.put(makeDoc({ id: 'doc-1' }));

    expect(events1.length).toBe(1);
    expect(events2.length).toBe(1);
  });

  it('putBatch emits one event per document', async () => {
    const events: StoreEvent[] = [];
    store.onEvent((e) => events.push(e));

    await store.putBatch([makeDoc({ id: 'a' }), makeDoc({ id: 'b' }), makeDoc({ id: 'c' })]);

    expect(events.length).toBe(3);
    expect(events.map((e) => e.documentId)).toEqual(['a', 'b', 'c']);
    expect(events.every((e) => e.type === 'put')).toBe(true);
  });

  it('deleteBatch emits one event per actually deleted document', async () => {
    await store.putBatch([makeDoc({ id: 'a' }), makeDoc({ id: 'b' })]);

    const events: StoreEvent[] = [];
    store.onEvent((e) => events.push(e));

    await store.deleteBatch(['a', 'nonexistent', 'b']);

    expect(events.length).toBe(2);
    expect(events.every((e) => e.type === 'delete')).toBe(true);
  });

  it('event timestamps are valid ISO 8601', async () => {
    const events: StoreEvent[] = [];
    store.onEvent((e) => events.push(e));

    await store.put(makeDoc({ id: 'doc-1' }));

    expect(events.length).toBe(1);
    const ts = events[0]!.timestamp;
    expect(typeof ts).toBe('string');
    const parsed = new Date(ts);
    expect(parsed.getTime()).not.toBeNaN();
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — clear utility
// ---------------------------------------------------------------------------
describe('MemoryStore - clear', () => {
  it('clear removes all documents', async () => {
    const store = new MemoryStore();
    await store.putBatch([makeDoc({ id: 'a' }), makeDoc({ id: 'b' })]);
    expect(store.size).toBe(2);
    store.clear();
    expect(store.size).toBe(0);
    expect(await store.has('a')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — edge cases
// ---------------------------------------------------------------------------
describe('MemoryStore - edge cases', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('handles documents with no metadata', async () => {
    const doc = makeDoc({ id: 'no-meta' });
    delete (doc as any).metadata;
    await store.put(doc);
    const docs = await store.list({ tags: ['anything'] });
    expect(docs.length).toBe(0);
  });

  it('handles documents with empty tags array', async () => {
    const doc = makeDoc({ id: 'empty-tags', metadata: { tags: [] } });
    await store.put(doc);
    const docs = await store.list({ tags: ['anything'] });
    expect(docs.length).toBe(0);
  });

  it('createdAfter is inclusive (equal timestamps match)', async () => {
    const doc = makeDoc({ id: 'exact', createdAt: '2025-06-01T00:00:00.000Z' });
    await store.put(doc);
    const docs = await store.list({ createdAfter: '2025-06-01T00:00:00.000Z' });
    expect(docs.length).toBe(1);
  });

  it('createdBefore is inclusive (equal timestamps match)', async () => {
    const doc = makeDoc({ id: 'exact', createdAt: '2025-06-01T00:00:00.000Z' });
    await store.put(doc);
    const docs = await store.list({ createdBefore: '2025-06-01T00:00:00.000Z' });
    expect(docs.length).toBe(1);
  });

  it('list returns copies (different array references)', async () => {
    await store.put(makeDoc({ id: 'a' }));
    const list1 = await store.list();
    const list2 = await store.list();
    expect(list1).not.toBe(list2);
  });

  it('putBatch with duplicate IDs keeps last version', async () => {
    const doc1 = makeDoc({ id: 'dup', constraints: 'first' });
    const doc2 = makeDoc({ id: 'dup', constraints: 'second' });
    await store.putBatch([doc1, doc2]);
    expect(store.size).toBe(1);
    const retrieved = await store.get('dup');
    expect(retrieved!.constraints).toBe('second');
  });

  it('getBatch handles duplicate IDs', async () => {
    await store.put(makeDoc({ id: 'a' }));
    const results = await store.getBatch(['a', 'a', 'a']);
    expect(results.length).toBe(3);
    expect(results.every((r) => r?.id === 'a')).toBe(true);
  });

  it('deleteBatch with duplicate IDs only deletes once', async () => {
    await store.put(makeDoc({ id: 'a' }));
    const deleted = await store.deleteBatch(['a', 'a', 'a']);
    // Map.delete returns false for subsequent attempts on the same key
    expect(deleted).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — get() error paths
// ---------------------------------------------------------------------------
describe('MemoryStore - get() error paths', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('throws STORE_MISSING_ID when id is null', async () => {
    await expect(store.get(null as unknown as string)).rejects.toThrow(SteleError);
    await expect(store.get(null as unknown as string)).rejects.toThrow(/id must be a non-empty string/);
    try {
      await store.get(null as unknown as string);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('throws STORE_MISSING_ID when id is undefined', async () => {
    await expect(store.get(undefined as unknown as string)).rejects.toThrow(SteleError);
    try {
      await store.get(undefined as unknown as string);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('throws STORE_MISSING_ID when id is empty string', async () => {
    await expect(store.get('')).rejects.toThrow(SteleError);
    try {
      await store.get('');
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('throws STORE_MISSING_ID when id is whitespace-only string', async () => {
    await expect(store.get('   ')).rejects.toThrow(SteleError);
    await expect(store.get('\t')).rejects.toThrow(SteleError);
    await expect(store.get('\n')).rejects.toThrow(SteleError);
    try {
      await store.get('   ');
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('throws STORE_MISSING_ID when id is a number', async () => {
    await expect(store.get(42 as unknown as string)).rejects.toThrow(SteleError);
    try {
      await store.get(42 as unknown as string);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — delete() error paths
// ---------------------------------------------------------------------------
describe('MemoryStore - delete() error paths', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('throws STORE_MISSING_ID when id is null', async () => {
    await expect(store.delete(null as unknown as string)).rejects.toThrow(SteleError);
    await expect(store.delete(null as unknown as string)).rejects.toThrow(/id must be a non-empty string/);
    try {
      await store.delete(null as unknown as string);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('throws STORE_MISSING_ID when id is undefined', async () => {
    await expect(store.delete(undefined as unknown as string)).rejects.toThrow(SteleError);
    try {
      await store.delete(undefined as unknown as string);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('throws STORE_MISSING_ID when id is empty string', async () => {
    await expect(store.delete('')).rejects.toThrow(SteleError);
    try {
      await store.delete('');
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('throws STORE_MISSING_ID when id is whitespace-only string', async () => {
    await expect(store.delete('   ')).rejects.toThrow(SteleError);
    await expect(store.delete('\t')).rejects.toThrow(SteleError);
    await expect(store.delete('\n')).rejects.toThrow(SteleError);
    try {
      await store.delete('   ');
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('throws STORE_MISSING_ID when id is a number', async () => {
    await expect(store.delete(123 as unknown as string)).rejects.toThrow(SteleError);
    try {
      await store.delete(123 as unknown as string);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_ID);
    }
  });

  it('does not delete anything when id is invalid', async () => {
    await store.put(makeDoc({ id: 'keep-me' }));
    expect(store.size).toBe(1);
    await expect(store.delete(null as unknown as string)).rejects.toThrow();
    expect(store.size).toBe(1);
    expect(await store.has('keep-me')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — putBatch() error paths
// ---------------------------------------------------------------------------
describe('MemoryStore - putBatch() error paths', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('throws STORE_MISSING_DOC when docs is null', async () => {
    await expect(store.putBatch(null as unknown as CovenantDocument[])).rejects.toThrow(SteleError);
    try {
      await store.putBatch(null as unknown as CovenantDocument[]);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_DOC);
    }
  });

  it('throws STORE_MISSING_DOC when docs is undefined', async () => {
    await expect(store.putBatch(undefined as unknown as CovenantDocument[])).rejects.toThrow(SteleError);
    try {
      await store.putBatch(undefined as unknown as CovenantDocument[]);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_DOC);
    }
  });

  it('throws STORE_MISSING_DOC when docs is a string (non-array)', async () => {
    await expect(store.putBatch('not-an-array' as unknown as CovenantDocument[])).rejects.toThrow(SteleError);
    try {
      await store.putBatch('not-an-array' as unknown as CovenantDocument[]);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_DOC);
      expect((err as SteleError).message).toMatch(/docs must be an array/);
    }
  });

  it('throws STORE_MISSING_DOC when docs is a number (non-array)', async () => {
    await expect(store.putBatch(42 as unknown as CovenantDocument[])).rejects.toThrow(SteleError);
    try {
      await store.putBatch(42 as unknown as CovenantDocument[]);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_DOC);
    }
  });

  it('throws STORE_MISSING_DOC when docs is a plain object (non-array)', async () => {
    await expect(store.putBatch({} as unknown as CovenantDocument[])).rejects.toThrow(SteleError);
    try {
      await store.putBatch({} as unknown as CovenantDocument[]);
    } catch (err) {
      expect(err).toBeInstanceOf(SteleError);
      expect((err as SteleError).code).toBe(SteleErrorCode.STORE_MISSING_DOC);
    }
  });

  it('does not store any documents when putBatch receives invalid input', async () => {
    try {
      await store.putBatch(null as unknown as CovenantDocument[]);
    } catch {
      // expected
    }
    expect(store.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — event listener errors don't crash
// ---------------------------------------------------------------------------
describe('MemoryStore - event listener error isolation', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('a throwing listener does not prevent other listeners from being called on put', async () => {
    const events: StoreEvent[] = [];

    // First listener throws
    store.onEvent(() => {
      throw new Error('listener kaboom');
    });
    // Second listener should still receive the event
    store.onEvent((e) => events.push(e));

    await store.put(makeDoc({ id: 'doc-1' }));

    expect(events.length).toBe(1);
    expect(events[0]!.type).toBe('put');
    expect(events[0]!.documentId).toBe('doc-1');
  });

  it('a throwing listener does not prevent other listeners from being called on delete', async () => {
    await store.put(makeDoc({ id: 'doc-1' }));

    const events: StoreEvent[] = [];

    // First listener throws
    store.onEvent(() => {
      throw new Error('delete listener error');
    });
    // Second listener should still receive the event
    store.onEvent((e) => events.push(e));

    await store.delete('doc-1');

    expect(events.length).toBe(1);
    expect(events[0]!.type).toBe('delete');
    expect(events[0]!.documentId).toBe('doc-1');
  });

  it('all three listeners are called even when the middle one throws', async () => {
    const calls: number[] = [];

    store.onEvent(() => { calls.push(1); });
    store.onEvent(() => { calls.push(2); throw new Error('middle throws'); });
    store.onEvent(() => { calls.push(3); });

    await store.put(makeDoc({ id: 'doc-1' }));

    expect(calls).toEqual([1, 2, 3]);
  });

  it('put succeeds even when all listeners throw', async () => {
    store.onEvent(() => { throw new Error('boom 1'); });
    store.onEvent(() => { throw new Error('boom 2'); });

    // put should not throw
    await store.put(makeDoc({ id: 'doc-1' }));

    // document should still be stored
    expect(store.size).toBe(1);
    expect(await store.has('doc-1')).toBe(true);
  });

  it('delete succeeds even when all listeners throw', async () => {
    await store.put(makeDoc({ id: 'doc-1' }));

    store.onEvent(() => { throw new Error('boom'); });

    const deleted = await store.delete('doc-1');
    expect(deleted).toBe(true);
    expect(store.size).toBe(0);
  });

  it('putBatch processes all docs even when listeners throw', async () => {
    const events: string[] = [];

    store.onEvent(() => { throw new Error('always throws'); });
    store.onEvent((e) => { events.push(e.documentId); });

    const docs = [makeDoc({ id: 'a' }), makeDoc({ id: 'b' }), makeDoc({ id: 'c' })];
    await store.putBatch(docs);

    expect(store.size).toBe(3);
    expect(events).toEqual(['a', 'b', 'c']);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — count() and has() additional coverage
// ---------------------------------------------------------------------------
describe('MemoryStore - count() and has() additional coverage', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('count reflects insertions and deletions', async () => {
    expect(await store.count()).toBe(0);
    await store.put(makeDoc({ id: 'a' }));
    expect(await store.count()).toBe(1);
    await store.put(makeDoc({ id: 'b' }));
    expect(await store.count()).toBe(2);
    await store.delete('a');
    expect(await store.count()).toBe(1);
    await store.delete('b');
    expect(await store.count()).toBe(0);
  });

  it('count with filter after batch insert', async () => {
    await store.putBatch([
      makeDoc({ id: 'alice-1', issuer: { id: 'alice', publicKey: 'aa'.repeat(32), role: 'issuer' } }),
      makeDoc({ id: 'alice-2', issuer: { id: 'alice', publicKey: 'aa'.repeat(32), role: 'issuer' } }),
      makeDoc({ id: 'bob-1', issuer: { id: 'bob', publicKey: 'aa'.repeat(32), role: 'issuer' } }),
    ]);
    expect(await store.count({ issuerId: 'alice' })).toBe(2);
    expect(await store.count({ issuerId: 'bob' })).toBe(1);
    expect(await store.count({ issuerId: 'charlie' })).toBe(0);
    expect(await store.count()).toBe(3);
  });

  it('has returns false after a document is deleted', async () => {
    await store.put(makeDoc({ id: 'ephemeral' }));
    expect(await store.has('ephemeral')).toBe(true);
    await store.delete('ephemeral');
    expect(await store.has('ephemeral')).toBe(false);
  });

  it('has returns true after put overwrites a document', async () => {
    await store.put(makeDoc({ id: 'overwrite-me', constraints: 'v1' }));
    await store.put(makeDoc({ id: 'overwrite-me', constraints: 'v2' }));
    expect(await store.has('overwrite-me')).toBe(true);
  });

  it('has returns false after clear', async () => {
    await store.put(makeDoc({ id: 'a' }));
    await store.put(makeDoc({ id: 'b' }));
    store.clear();
    expect(await store.has('a')).toBe(false);
    expect(await store.has('b')).toBe(false);
  });

  it('count returns 0 after clear', async () => {
    await store.putBatch([makeDoc({ id: 'a' }), makeDoc({ id: 'b' })]);
    store.clear();
    expect(await store.count()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — deleteBatch() additional coverage
// ---------------------------------------------------------------------------
describe('MemoryStore - deleteBatch() additional coverage', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('returns 0 when deleting non-existent IDs', async () => {
    const deleted = await store.deleteBatch(['ghost-1', 'ghost-2', 'ghost-3']);
    expect(deleted).toBe(0);
  });

  it('returns correct count when mix of existing and non-existent IDs', async () => {
    await store.putBatch([
      makeDoc({ id: 'exists-1' }),
      makeDoc({ id: 'exists-2' }),
      makeDoc({ id: 'exists-3' }),
    ]);
    const deleted = await store.deleteBatch(['exists-1', 'nope', 'exists-3', 'also-nope']);
    expect(deleted).toBe(2);
    expect(store.size).toBe(1);
    expect(await store.has('exists-2')).toBe(true);
  });

  it('does not crash when all IDs are non-existent', async () => {
    await store.put(makeDoc({ id: 'survivor' }));
    const deleted = await store.deleteBatch(['fake-1', 'fake-2']);
    expect(deleted).toBe(0);
    expect(store.size).toBe(1);
    expect(await store.has('survivor')).toBe(true);
  });

  it('emits delete events only for actually deleted documents', async () => {
    await store.putBatch([makeDoc({ id: 'a' }), makeDoc({ id: 'b' })]);
    const events: StoreEvent[] = [];
    store.onEvent((e) => events.push(e));

    await store.deleteBatch(['a', 'nonexistent', 'b']);

    expect(events.length).toBe(2);
    expect(events[0]!.documentId).toBe('a');
    expect(events[1]!.documentId).toBe('b');
    expect(events.every((e) => e.type === 'delete')).toBe(true);
  });

  it('returns 0 for empty ID array', async () => {
    await store.put(makeDoc({ id: 'untouched' }));
    const deleted = await store.deleteBatch([]);
    expect(deleted).toBe(0);
    expect(store.size).toBe(1);
  });

  it('handles large batch of deletions', async () => {
    const ids = Array.from({ length: 100 }, (_, i) => `doc-${i}`);
    const docs = ids.map((id) => makeDoc({ id }));
    await store.putBatch(docs);
    expect(store.size).toBe(100);

    // Delete first 50
    const deleteIds = ids.slice(0, 50);
    const deleted = await store.deleteBatch(deleteIds);
    expect(deleted).toBe(50);
    expect(store.size).toBe(50);

    // Remaining docs should still be accessible
    for (let i = 50; i < 100; i++) {
      expect(await store.has(`doc-${i}`)).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — concurrent put operations for the same document ID
// ---------------------------------------------------------------------------
describe('MemoryStore - concurrent put operations for same document ID', () => {
  let store: MemoryStore;

  beforeEach(() => {
    store = new MemoryStore();
  });

  it('concurrent puts for the same ID all resolve without error', async () => {
    const docs = Array.from({ length: 10 }, (_, i) =>
      makeDoc({ id: 'contested-id', constraints: `version-${i}` }),
    );
    // Fire all puts concurrently
    await Promise.all(docs.map((doc) => store.put(doc)));

    // Only one document should exist
    expect(store.size, 'store should contain exactly 1 document after concurrent puts with same ID').toBe(1);
    const retrieved = await store.get('contested-id');
    expect(retrieved, 'document should be retrievable after concurrent puts').toBeDefined();
  });

  it('concurrent puts for the same ID emit one event per put', async () => {
    const events: StoreEvent[] = [];
    store.onEvent((e) => events.push(e));

    const docs = Array.from({ length: 5 }, (_, i) =>
      makeDoc({ id: 'same-id', constraints: `v${i}` }),
    );
    await Promise.all(docs.map((doc) => store.put(doc)));

    expect(events.length, 'each concurrent put should emit an event').toBe(5);
    expect(events.every((e) => e.type === 'put'), 'all events should be put events').toBe(true);
    expect(events.every((e) => e.documentId === 'same-id'), 'all events should reference same-id').toBe(true);
  });

  it('concurrent puts for different IDs all succeed', async () => {
    const docs = Array.from({ length: 20 }, (_, i) =>
      makeDoc({ id: `concurrent-${i}` }),
    );
    await Promise.all(docs.map((doc) => store.put(doc)));

    expect(store.size, 'all 20 concurrent puts with different IDs should succeed').toBe(20);
    for (let i = 0; i < 20; i++) {
      expect(await store.has(`concurrent-${i}`), `concurrent-${i} should exist in store`).toBe(true);
    }
  });

  it('concurrent put and delete for same ID resolves without error', async () => {
    await store.put(makeDoc({ id: 'race-target' }));

    // Race a put and delete
    await Promise.all([
      store.put(makeDoc({ id: 'race-target', constraints: 'updated' })),
      store.delete('race-target'),
    ]);

    // Final state is implementation-defined but should not throw
    // The document either exists or not, but the store should be in a consistent state
    const exists = await store.has('race-target');
    expect(typeof exists, 'has should return a boolean after concurrent put+delete').toBe('boolean');
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — list with empty store
// ---------------------------------------------------------------------------
describe('MemoryStore - list with empty store', () => {
  it('list() on brand new empty store returns empty array', async () => {
    const store = new MemoryStore();
    const docs = await store.list();
    expect(docs, 'list on empty store should return an array').toBeInstanceOf(Array);
    expect(docs.length, 'list on empty store should return 0 documents').toBe(0);
  });

  it('list() with filter on empty store returns empty array', async () => {
    const store = new MemoryStore();
    const docs = await store.list({ issuerId: 'anyone' });
    expect(docs.length, 'filtered list on empty store should return 0 documents').toBe(0);
  });

  it('list() with tags filter on empty store returns empty array', async () => {
    const store = new MemoryStore();
    const docs = await store.list({ tags: ['ai', 'safety'] });
    expect(docs.length, 'tag-filtered list on empty store should return 0 documents').toBe(0);
  });

  it('list() with date filters on empty store returns empty array', async () => {
    const store = new MemoryStore();
    const docs = await store.list({
      createdAfter: '2020-01-01T00:00:00.000Z',
      createdBefore: '2030-01-01T00:00:00.000Z',
    });
    expect(docs.length, 'date-filtered list on empty store should return 0 documents').toBe(0);
  });

  it('list() on a store after all documents are deleted returns empty array', async () => {
    const store = new MemoryStore();
    await store.put(makeDoc({ id: 'temp-1' }));
    await store.put(makeDoc({ id: 'temp-2' }));
    await store.delete('temp-1');
    await store.delete('temp-2');
    const docs = await store.list();
    expect(docs.length, 'list after deleting all documents should return 0').toBe(0);
  });

  it('list() on a store after clear() returns empty array', async () => {
    const store = new MemoryStore();
    await store.putBatch([makeDoc({ id: 'a' }), makeDoc({ id: 'b' }), makeDoc({ id: 'c' })]);
    store.clear();
    const docs = await store.list();
    expect(docs.length, 'list after clear should return 0').toBe(0);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — pagination with zero/negative limits (via QueryBuilder)
// ---------------------------------------------------------------------------
describe('MemoryStore - pagination edge cases with zero/negative limits', () => {
  let store: MemoryStore;

  beforeEach(async () => {
    store = new MemoryStore();
    await store.putBatch([
      makeDoc({ id: 'p1' }),
      makeDoc({ id: 'p2' }),
      makeDoc({ id: 'p3' }),
    ]);
  });

  it('list returns all documents regardless of pagination (list has no built-in limit)', async () => {
    // MemoryStore.list does not accept limit/offset natively -- that is on QueryBuilder.
    // This tests that list returns everything without pagination.
    const docs = await store.list();
    expect(docs.length, 'list should return all documents when no pagination is applied').toBe(3);
  });

  it('count returns correct value regardless of how many documents exist', async () => {
    expect(await store.count(), 'count should return 3 for 3 documents').toBe(3);
    await store.delete('p1');
    expect(await store.count(), 'count should return 2 after deleting one').toBe(2);
    await store.delete('p2');
    await store.delete('p3');
    expect(await store.count(), 'count should return 0 after deleting all').toBe(0);
  });

  it('list with combined contradictory date filters returns empty', async () => {
    // createdAfter is AFTER createdBefore -- impossible window
    const docs = await store.list({
      createdAfter: '2030-01-01T00:00:00.000Z',
      createdBefore: '2020-01-01T00:00:00.000Z',
    });
    expect(docs.length, 'contradictory date range should return 0 documents').toBe(0);
  });
});

// ---------------------------------------------------------------------------
// MemoryStore — query builder with conflicting filters
// ---------------------------------------------------------------------------
describe('MemoryStore - conflicting filters', () => {
  let store: MemoryStore;

  beforeEach(async () => {
    store = new MemoryStore();
    await store.putBatch([
      makeDoc({
        id: 'alice-doc',
        issuer: { id: 'alice', publicKey: 'aa'.repeat(32), role: 'issuer' },
        beneficiary: { id: 'bob', publicKey: 'bb'.repeat(32), role: 'beneficiary' },
        createdAt: '2025-06-15T00:00:00.000Z',
      }),
      makeDoc({
        id: 'bob-doc',
        issuer: { id: 'bob', publicKey: 'aa'.repeat(32), role: 'issuer' },
        beneficiary: { id: 'alice', publicKey: 'bb'.repeat(32), role: 'beneficiary' },
        createdAt: '2025-03-01T00:00:00.000Z',
      }),
    ]);
  });

  it('filtering by non-existent issuer AND valid beneficiary returns empty', async () => {
    const docs = await store.list({ issuerId: 'nonexistent', beneficiaryId: 'bob' });
    expect(docs.length, 'no documents should match a non-existent issuer').toBe(0);
  });

  it('filtering by valid issuer AND non-existent beneficiary returns empty', async () => {
    const docs = await store.list({ issuerId: 'alice', beneficiaryId: 'nonexistent' });
    expect(docs.length, 'no documents should match a non-existent beneficiary').toBe(0);
  });

  it('filtering by issuer AND beneficiary that never appear together returns empty', async () => {
    // alice is issuer on alice-doc (beneficiary=bob), bob is issuer on bob-doc (beneficiary=alice)
    // There is no doc where issuer=alice AND beneficiary=alice
    const docs = await store.list({ issuerId: 'alice', beneficiaryId: 'alice' });
    expect(docs.length, 'no documents should match issuer=alice and beneficiary=alice').toBe(0);
  });

  it('filtering by date range that excludes all documents returns empty', async () => {
    const docs = await store.list({
      createdAfter: '2099-01-01T00:00:00.000Z',
    });
    expect(docs.length, 'future date filter should match no documents').toBe(0);
  });

  it('filtering by hasChain when no documents have chains returns empty', async () => {
    const docs = await store.list({ hasChain: true });
    expect(docs.length, 'no documents have chains so hasChain=true should return empty').toBe(0);
  });

  it('filtering by hasChain=false returns all documents when none have chains', async () => {
    const docs = await store.list({ hasChain: false });
    expect(docs.length, 'hasChain=false should return all documents when none have chains').toBe(2);
  });

  it('filtering by tags when no documents have metadata returns empty', async () => {
    const docs = await store.list({ tags: ['anything'] });
    expect(docs.length, 'tag filter should match no documents when none have metadata.tags').toBe(0);
  });
});
