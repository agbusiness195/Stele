# @nobulex/mcp

Model Context Protocol (MCP) integration -- wraps any MCP server with Nobulex covenant enforcement, audit logging, and compliance proofs.

## Installation

```bash
npm install @nobulex/mcp
```

## Key APIs

- **NobulexGuard.wrap(server, options)**: Wrap an MCP server with constraint enforcement using CCL text or a preset name. Returns a `WrappedMCPServer`.
- **NobulexGuard.fromCovenant(server, covenant, keyPair)**: Wrap an MCP server using a pre-built `CovenantDocument` (for externally managed covenants).
- **PRESETS**: Built-in CCL constraint presets (`standard:data-isolation`, `standard:read-write`, `standard:network`, `standard:minimal`).
- **WrappedMCPServer**: Extended server with `getMonitor()`, `getAuditLog()`, `generateProof()`, `getReceipt()`, and `getCovenant()` accessors.

## Usage

```typescript
import { NobulexGuard } from '@nobulex/mcp';

// Your existing MCP server
const mcpServer = {
  tools: [{ name: 'readFile' }, { name: 'writeFile' }],
  handleToolCall: async (name: string, args: Record<string, unknown>) => {
    // ... tool implementation
  },
};

// Wrap with a built-in preset (2 lines)
const guarded = await NobulexGuard.wrap(mcpServer, {
  constraints: 'standard:data-isolation',
  mode: 'enforce', // or 'log_only'
  onViolation: (v) => console.warn(`Blocked: ${v.toolName} - ${v.constraint}`),
});

// Tool calls are now intercepted and enforced
await guarded.handleToolCall!('readFile', { path: '/data/report.csv' });

// Retrieve audit trail and compliance proof
const auditLog = guarded.getAuditLog();
const proof = await guarded.generateProof();
const receipt = guarded.getReceipt();
```

### Using a pre-built covenant

```typescript
import { NobulexGuard } from '@nobulex/mcp';
import { buildCovenant } from '@nobulex/core';
import { generateKeyPair } from '@nobulex/crypto';

const keyPair = await generateKeyPair();
const covenant = await buildCovenant({ /* ... */ });

const guarded = await NobulexGuard.fromCovenant(mcpServer, covenant, keyPair);
```

## Presets

| Preset | Description |
|---|---|
| `standard:data-isolation` | Read-only data access, no writes or network |
| `standard:read-write` | Read + scoped writes, no network |
| `standard:network` | Full I/O with PII guards and rate limits |
| `standard:minimal` | Deny everything, audit only |

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
