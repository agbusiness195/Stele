# @stele/store

Pluggable storage backends for covenant documents. Ships with `MemoryStore`, `FileStore`, and `SqliteStore`.

## Installation

```bash
npm install @stele/store
```

## Usage

### MemoryStore

```typescript
import { MemoryStore } from '@stele/store';

const store = new MemoryStore();

// Store a document
await store.put(doc);

// Retrieve by ID
const retrieved = await store.get(doc.id);

// List with filters
const aliceDocs = await store.list({ issuerId: 'alice' });

// Check existence and count
const exists = await store.has(doc.id);
const total = await store.count();

// Batch operations
await store.putBatch([doc1, doc2, doc3]);
const docs = await store.getBatch([id1, id2]);
```

### FileStore

```typescript
import { FileStore } from '@stele/store';

const store = new FileStore('/path/to/covenants');
await store.put(doc);
const retrieved = await store.get(doc.id);
```

### SqliteStore (bring-your-own-driver)

```typescript
import { SqliteStore } from '@stele/store';
import type { SQLiteDriver } from '@stele/store';

const driver: SQLiteDriver = { /* your sqlite driver implementation */ };
const store = new SqliteStore(driver);
await store.put(doc);
```

### Events and Queries

```typescript
store.onEvent((event) => console.log(`${event.type}: ${event.documentId}`));

import { createQuery } from '@stele/store';
const query = createQuery().where({ issuerId: 'alice' }).sortBy('createdAt', 'desc');
```

## Key APIs

- **Stores**: `MemoryStore`, `FileStore`, `SqliteStore`
- **Interface**: `CovenantStore` (put, get, has, delete, list, count, putBatch, getBatch, deleteBatch)
- **Querying**: `QueryBuilder`, `createQuery()`, `StoreIndex`, `IndexedStore`
- **Events**: `onEvent()`, `offEvent()`
- **Transactions**: `createTransaction()`
- **Types**: `StoreFilter`, `StoreEvent`, `PaginatedResult`, `SortField`

## Docs

See the [Stele SDK root documentation](../../README.md) for the full API reference and architecture guide.
