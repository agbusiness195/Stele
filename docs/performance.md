# Performance Tuning Guide

This document provides guidance for optimizing Stele performance in
production deployments.

## Baseline Performance

Benchmarks run on a single core (Node.js 22, Apple M-series):

| Operation | Throughput | P99 Latency |
|-----------|-----------|-------------|
| Ed25519 sign (100B) | ~1,000/s | < 1ms |
| Ed25519 verify | ~500/s | < 2ms |
| SHA-256 hash (10KB) | ~16,000/s | < 0.1ms |
| CCL parse (5 rules) | ~50,000/s | < 0.1ms |
| CCL evaluate | ~100,000/s | < 0.05ms |
| MemoryStore.get | ~1,000,000/s | < 0.01ms |
| MemoryStore.list (1K docs, filtered) | ~3,000/s | < 0.5ms |
| Full covenant build+sign | ~800/s | < 1.5ms |
| Full covenant verify (11 checks) | ~400/s | < 3ms |

## Bottleneck Analysis

### Signing and Verification

Ed25519 operations are the primary bottleneck for high-throughput
scenarios. These are CPU-bound and cannot be parallelized within a
single operation.

**Optimizations:**
- **Batch verification**: Use `verifier.verifyBatch()` to verify
  multiple covenants in sequence, amortizing startup overhead.
- **Caching**: Cache verification results keyed by document ID + signature.
  Covenant documents are immutable once signed, so a verified document
  remains valid until its expiry.
- **Worker threads**: Offload signing/verification to worker threads
  for concurrent throughput.

```ts
// Cache verification results
const verificationCache = new Map<string, boolean>();

async function cachedVerify(doc: CovenantDocument): Promise<boolean> {
  const cacheKey = `${doc.id}:${doc.signature}`;
  if (verificationCache.has(cacheKey)) {
    return verificationCache.get(cacheKey)!;
  }
  const result = await client.verifyCovenant(doc);
  verificationCache.set(cacheKey, result.valid);
  return result.valid;
}
```

### Store Operations

**MemoryStore** is fastest but limited to process memory:
- Sub-microsecond reads
- Linear scan for filtered lists

**FileStore** is I/O bound:
- Use SSDs for the backing directory
- The index file (`_index.json`) is read/written atomically on every
  mutation; keep document counts under 100K per directory
- Shard into multiple directories for large datasets

**SqliteStore** is a good middle ground:
- Transactional writes
- Indexed lookups by ID
- For high write throughput, use WAL mode:

```ts
const store = new SqliteStore(driver, { walMode: true });
```

**EncryptedStore** adds overhead per operation:
- AES-256-GCM encryption: ~1-5 microseconds per document
- Total overhead is negligible compared to I/O and Ed25519 operations

### CCL Evaluation

CCL evaluation is extremely fast (100K+ evaluations per second).
It is rarely a bottleneck. If you have complex rule sets (50+ rules),
consider:

- Ordering rules so the most common matches appear first
- Using specific resource paths instead of broad wildcards
- Splitting large constraint documents into focused covenants

## Memory Management

### Document Size

Covenant documents are typically 1-5 KB. The protocol enforces
`MAX_DOCUMENT_SIZE` (default 1 MB) to prevent abuse. For stores
holding many documents:

| Document Count | Approximate Memory (MemoryStore) |
|---------------|----------------------------------|
| 1,000 | ~5 MB |
| 10,000 | ~50 MB |
| 100,000 | ~500 MB |

For datasets exceeding available memory, use `FileStore` or
`SqliteStore` instead of `MemoryStore`.

### Audit Trail

The enforcement `Monitor` maintains an in-memory audit trail.
For long-running processes, periodically export and trim the trail:

```ts
const entries = monitor.getAuditTrail();
await persistToStorage(entries);
monitor.clearAuditTrail();
```

## Concurrency

Stele operations are safe to call concurrently. The main considerations:

- **MemoryStore**: Thread-safe within a single event loop. No locking
  needed for concurrent async operations.
- **FileStore**: Uses an internal mutex for index writes. Concurrent
  reads are safe; writes are serialized.
- **SqliteStore**: Uses database-level locking. WAL mode improves
  concurrent read performance.

For multi-process deployments, use a shared database backend
(SqliteStore with a shared file, or a custom PostgreSQL/Redis store).

## Node.js Configuration

### Recommended Flags

```bash
# Production
node --max-old-space-size=4096 --enable-source-maps server.js

# High-throughput signing
node --max-old-space-size=4096 server.js
```

### Cluster Mode

For multi-core utilization, use Node.js cluster module or a process
manager like PM2:

```bash
pm2 start server.js -i max
```

Each worker process should have its own store connection. Use
`EncryptedStore` independently per worker (the encryption key
can be shared).

## Profiling

### Built-in Benchmarks

Run the benchmark suite to establish baselines:

```bash
npx vitest run benchmarks/bench.test.ts
```

### Custom Profiling

```ts
import { createLogger } from '@stele/types';

const logger = createLogger({ level: 'debug', prefix: 'perf' });

const start = performance.now();
const result = await client.verifyCovenant(doc);
logger.debug(`verify: ${(performance.now() - start).toFixed(2)}ms`);
```

## SLA Targets

Recommended SLA targets for production:

| Metric | Target |
|--------|--------|
| Covenant verification | P99 < 10ms |
| CCL evaluation | P99 < 1ms |
| Store read (single doc) | P99 < 5ms |
| Store list (filtered) | P99 < 50ms |
| Health check response | P99 < 100ms |
| Availability | 99.9% |
