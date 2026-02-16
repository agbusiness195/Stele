/**
 * Fluent query builder and pagination utilities for CovenantStore.
 *
 * Provides a chainable API for constructing filtered, sorted, and paginated
 * queries against any {@link CovenantStore} implementation. Works with both
 * MemoryStore and FileStore (or any future backend) because it relies solely
 * on the `list()` and `count()` methods of the store interface.
 *
 * @packageDocumentation
 */

import type { CovenantDocument } from '@stele/core';

import type { CovenantStore, StoreFilter } from './types.js';

// ─── Pagination types ───────────────────────────────────────────────────────────

/** Options for paginated queries. */
export interface PaginationOptions {
  /** Maximum number of items to return per page. */
  limit: number;
  /** Zero-based offset into the result set. Mutually exclusive with `cursor`. */
  offset?: number;
  /** Opaque cursor string returned by a previous paginated result. */
  cursor?: string;
}

/** A page of results returned by a paginated query. */
export interface PaginatedResult<T> {
  /** The items on this page. */
  items: T[];
  /** Total number of items matching the query (across all pages). */
  total: number;
  /** Whether more items exist beyond this page. */
  hasMore: boolean;
  /** Opaque cursor to pass to the next call to fetch the following page. */
  nextCursor?: string;
}

// ─── Sort types ─────────────────────────────────────────────────────────────────

/** Fields that can be used for sorting query results. */
export type SortField = 'createdAt' | 'id';

/** Sort direction. */
export type SortOrder = 'asc' | 'desc';

// ─── QueryBuilder ───────────────────────────────────────────────────────────────

/**
 * Fluent query builder for {@link CovenantStore}.
 *
 * Construct a query step-by-step using chainable methods, then execute it
 * with `execute()`, `paginate()`, `count()`, `first()`, or `exists()`.
 *
 * @example
 * ```ts
 * const results = await createQuery(store)
 *   .issuedBy('alice')
 *   .createdAfter('2025-01-01T00:00:00Z')
 *   .sortBy('createdAt', 'desc')
 *   .limit(10)
 *   .execute();
 * ```
 */
export class QueryBuilder {
  private readonly store: CovenantStore;
  private filter: StoreFilter = {};
  private sortField: SortField | undefined;
  private sortOrder: SortOrder = 'asc';
  private limitValue: number | undefined;
  private offsetValue: number | undefined;

  constructor(store: CovenantStore) {
    this.store = store;
  }

  // ── Filter methods ──────────────────────────────────────────────────────

  /**
   * Add arbitrary filter criteria. Merges with any existing filter.
   *
   * @param f - Filter criteria to merge.
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * createQuery(store)
   *   .where({ issuerId: 'alice', hasChain: true })
   *   .execute();
   * ```
   */
  where(f: StoreFilter): this {
    if (f.issuerId !== undefined) this.filter.issuerId = f.issuerId;
    if (f.beneficiaryId !== undefined) this.filter.beneficiaryId = f.beneficiaryId;
    if (f.createdAfter !== undefined) this.filter.createdAfter = f.createdAfter;
    if (f.createdBefore !== undefined) this.filter.createdBefore = f.createdBefore;
    if (f.hasChain !== undefined) this.filter.hasChain = f.hasChain;
    if (f.tags !== undefined) {
      this.filter.tags = [...(this.filter.tags ?? []), ...f.tags];
    }
    return this;
  }

  /**
   * Filter by issuer ID.
   *
   * @param issuerId - The issuer ID to filter on.
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * const docs = await createQuery(store).issuedBy('alice').execute();
   * ```
   */
  issuedBy(issuerId: string): this {
    this.filter.issuerId = issuerId;
    return this;
  }

  /**
   * Filter by beneficiary ID.
   *
   * @param beneficiaryId - The beneficiary ID to filter on.
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * const docs = await createQuery(store).forBeneficiary('bob').execute();
   * ```
   */
  forBeneficiary(beneficiaryId: string): this {
    this.filter.beneficiaryId = beneficiaryId;
    return this;
  }

  /**
   * Only include documents created on or after `date` (ISO 8601).
   *
   * @param date - ISO 8601 date string (e.g. `"2025-01-01T00:00:00Z"`).
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * const recent = await createQuery(store)
   *   .createdAfter('2025-06-01T00:00:00Z')
   *   .execute();
   * ```
   */
  createdAfter(date: string): this {
    this.filter.createdAfter = date;
    return this;
  }

  /**
   * Only include documents created on or before `date` (ISO 8601).
   *
   * @param date - ISO 8601 date string (e.g. `"2025-12-31T23:59:59Z"`).
   * @returns `this` for chaining.
   */
  createdBefore(date: string): this {
    this.filter.createdBefore = date;
    return this;
  }

  /**
   * Only include documents that have a chain reference (non-root).
   *
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * const delegated = await createQuery(store).withChain().execute();
   * ```
   */
  withChain(): this {
    this.filter.hasChain = true;
    return this;
  }

  /**
   * Only include root documents (no chain reference).
   *
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * const roots = await createQuery(store).withoutChain().execute();
   * ```
   */
  withoutChain(): this {
    this.filter.hasChain = false;
    return this;
  }

  /**
   * Only include documents whose metadata tags contain ALL of the given tags.
   *
   * Multiple calls to `withTags()` are cumulative (AND semantics).
   *
   * @param tags - One or more tag strings to require.
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * const docs = await createQuery(store)
   *   .withTags('production', 'v2')
   *   .execute();
   * ```
   */
  withTags(...tags: string[]): this {
    this.filter.tags = [...(this.filter.tags ?? []), ...tags];
    return this;
  }

  // ── Sort / limit / offset ─────────────────────────────────────────────

  /**
   * Set the sort field and optional direction (default `'asc'`).
   *
   * @param field - The field to sort by (`"createdAt"` or `"id"`).
   * @param order - Sort direction: `"asc"` (default) or `"desc"`.
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * const newest = await createQuery(store)
   *   .sortBy('createdAt', 'desc')
   *   .limit(5)
   *   .execute();
   * ```
   */
  sortBy(field: SortField, order: SortOrder = 'asc'): this {
    this.sortField = field;
    this.sortOrder = order;
    return this;
  }

  /**
   * Limit the number of results returned by `execute()`.
   *
   * @param n - Maximum number of documents to return.
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * const top10 = await createQuery(store).limit(10).execute();
   * ```
   */
  limit(n: number): this {
    this.limitValue = n;
    return this;
  }

  /**
   * Skip the first `n` results (used with `limit()` for basic pagination).
   *
   * @param n - Number of documents to skip.
   * @returns `this` for chaining.
   *
   * @example
   * ```typescript
   * // Page 2 of 10-item pages
   * const page2 = await createQuery(store).offset(10).limit(10).execute();
   * ```
   */
  offset(n: number): this {
    this.offsetValue = n;
    return this;
  }

  // ── Execution methods ─────────────────────────────────────────────────

  /**
   * Execute the query and return all matching documents (subject to any
   * `limit` and `offset` that have been set).
   *
   * @returns An array of matching {@link CovenantDocument} objects.
   *
   * @example
   * ```typescript
   * const docs = await createQuery(store)
   *   .issuedBy('alice')
   *   .sortBy('createdAt', 'desc')
   *   .execute();
   * ```
   */
  async execute(): Promise<CovenantDocument[]> {
    let docs = await this.store.list(this.buildFilter());
    docs = this.applySort(docs);
    docs = this.applySlice(docs);
    return docs;
  }

  /**
   * Execute the query with cursor-based or offset-based pagination.
   *
   * - If `options.cursor` is provided, the result set begins after the
   *   document whose ID matches the cursor value.
   * - Otherwise `options.offset` (default 0) is used.
   *
   * @param options - Pagination options (limit, offset, or cursor).
   * @returns A {@link PaginatedResult} with items, total, hasMore, and nextCursor.
   *
   * @example
   * ```typescript
   * // First page
   * const page1 = await createQuery(store).paginate({ limit: 20 });
   *
   * // Next page using cursor
   * if (page1.hasMore) {
   *   const page2 = await createQuery(store).paginate({
   *     limit: 20,
   *     cursor: page1.nextCursor,
   *   });
   * }
   * ```
   */
  async paginate(options: PaginationOptions): Promise<PaginatedResult<CovenantDocument>> {
    let docs = await this.store.list(this.buildFilter());
    const total = docs.length;

    docs = this.applySort(docs);

    let startIndex: number;
    if (options.cursor) {
      const cursorIndex = docs.findIndex((d) => d.id === options.cursor);
      startIndex = cursorIndex === -1 ? 0 : cursorIndex + 1;
    } else {
      startIndex = options.offset ?? 0;
    }

    const page = docs.slice(startIndex, startIndex + options.limit);
    const hasMore = startIndex + options.limit < total;
    const nextCursor = hasMore && page.length > 0 ? page[page.length - 1]!.id : undefined;

    return { items: page, total, hasMore, nextCursor };
  }

  /**
   * Count documents matching the current filter (ignores sort/limit/offset).
   *
   * @returns The total number of matching documents.
   *
   * @example
   * ```typescript
   * const total = await createQuery(store).issuedBy('alice').count();
   * ```
   */
  async count(): Promise<number> {
    return this.store.count(this.buildFilter());
  }

  /**
   * Return the first document matching the current query, or `undefined`.
   *
   * Respects the current sort order, so this returns the "top" result.
   *
   * @returns The first matching document, or `undefined` if none match.
   *
   * @example
   * ```typescript
   * const latest = await createQuery(store)
   *   .sortBy('createdAt', 'desc')
   *   .first();
   * ```
   */
  async first(): Promise<CovenantDocument | undefined> {
    let docs = await this.store.list(this.buildFilter());
    docs = this.applySort(docs);
    return docs[0];
  }

  /**
   * Return `true` if at least one document matches the current filter.
   *
   * @returns `true` if any matching documents exist, `false` otherwise.
   *
   * @example
   * ```typescript
   * const hasAliceDocs = await createQuery(store).issuedBy('alice').exists();
   * ```
   */
  async exists(): Promise<boolean> {
    return (await this.count()) > 0;
  }

  // ── Internal helpers ──────────────────────────────────────────────────

  /**
   * Build the StoreFilter from the accumulated criteria.
   * Returns `undefined` when no filter criteria have been set so that
   * the store can use its fastest unfiltered path.
   */
  private buildFilter(): StoreFilter | undefined {
    const f = this.filter;
    const hasAnyCriteria =
      f.issuerId !== undefined ||
      f.beneficiaryId !== undefined ||
      f.createdAfter !== undefined ||
      f.createdBefore !== undefined ||
      f.hasChain !== undefined ||
      (f.tags !== undefined && f.tags.length > 0);
    return hasAnyCriteria ? f : undefined;
  }

  /** Sort an array of documents in place and return it. */
  private applySort(docs: CovenantDocument[]): CovenantDocument[] {
    if (!this.sortField) return docs;

    const field = this.sortField;
    const order = this.sortOrder;

    docs.sort((a, b) => {
      let cmp: number;
      if (field === 'createdAt') {
        cmp = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      } else {
        // 'id'
        cmp = a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
      }
      return order === 'desc' ? -cmp : cmp;
    });

    return docs;
  }

  /** Apply offset and limit slicing. */
  private applySlice(docs: CovenantDocument[]): CovenantDocument[] {
    const start = this.offsetValue ?? 0;
    if (this.limitValue !== undefined) {
      return docs.slice(start, start + this.limitValue);
    }
    if (start > 0) {
      return docs.slice(start);
    }
    return docs;
  }
}

// ─── Factory ────────────────────────────────────────────────────────────────────

/**
 * Create a new {@link QueryBuilder} bound to the given store.
 *
 * @example
 * ```ts
 * const page = await createQuery(store)
 *   .issuedBy('alice')
 *   .sortBy('createdAt', 'desc')
 *   .paginate({ limit: 20 });
 * ```
 */
export function createQuery(store: CovenantStore): QueryBuilder {
  return new QueryBuilder(store);
}
