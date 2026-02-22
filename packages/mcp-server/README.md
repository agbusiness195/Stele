# @nobulex/mcp-server

Model Context Protocol (MCP) server that exposes Nobulex covenant operations as tools to any AI agent via JSON-RPC 2.0.

## Installation

```bash
npm install @nobulex/mcp-server
```

## Key APIs

- **NobulexServer**: MCP server class that handles JSON-RPC 2.0 messages and exposes Nobulex tools. Supports `initialize`, `tools/list`, `tools/call`, and `ping` methods.
- **createAuthMiddleware()**: Authentication middleware for securing MCP endpoints.
- **JSON_RPC_ERRORS**: Standard JSON-RPC 2.0 error code constants.

### Exposed Tools

| Tool | Description |
|------|-------------|
| `create_covenant` | Create a signed covenant document with CCL constraints |
| `verify_covenant` | Verify a covenant document (signature, expiry, CCL syntax) |
| `evaluate_action` | Check if an action on a resource is permitted by a covenant |
| `create_identity` | Create an agent identity with model attestation and capabilities |
| `parse_ccl` | Parse CCL source text into a structured document |
| `list_covenants` | List stored covenants with optional issuer/beneficiary filters |

## Usage

```typescript
import { NobulexServer } from '@nobulex/mcp-server';
import { MemoryStore } from '@nobulex/store';

const server = new NobulexServer(new MemoryStore(), {
  name: 'my-nobulex-server',
  version: '1.0.0',
});

// Handle a JSON-RPC message
const response = await server.handleMessage({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/list',
  params: {},
});

// Call a tool directly
const result = await server.callTool('evaluate_action', {
  covenantId: 'abc123',
  action: 'read',
  resource: '/data',
});
```

## Docs

See the [Nobulex SDK root documentation](../../README.md) for the full API reference.
