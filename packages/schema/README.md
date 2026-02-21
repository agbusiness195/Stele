# @grith/schema

JSON Schema definitions (Draft 2020-12) for Grith protocol documents, enabling cross-language validation without the TypeScript SDK.

## Installation

```bash
npm install @grith/schema
```

## Key APIs

### Schema Constants
- **COVENANT_SCHEMA**: JSON Schema for `CovenantDocument` objects
- **DISCOVERY_DOCUMENT_SCHEMA**: JSON Schema for `.well-known/grith/` discovery documents
- **AGENT_KEY_SCHEMA**: JSON Schema for `AgentKeyEntry` objects
- **CCL_EVALUATION_CONTEXT_SCHEMA**: JSON Schema for CCL evaluation contexts

### Validation Functions
- **validateCovenantSchema(data)**: Validate an object against the covenant schema
- **validateDiscoverySchema(data)**: Validate an object against the discovery document schema
- **validateAgentKeySchema(data)**: Validate an object against the agent key entry schema
- **getAllSchemas()**: Retrieve all schemas as a record keyed by name

### Types
- **SchemaValidationResult**: Result of a validation call (`valid`, `errors`)
- **SchemaValidationError**: Individual validation error (`path`, `message`, `keyword`)

## Usage

```typescript
import {
  COVENANT_SCHEMA,
  validateCovenantSchema,
  validateDiscoverySchema,
  getAllSchemas,
} from '@grith/schema';

// Validate a covenant document
const result = validateCovenantSchema({
  id: 'abc123',
  version: '1.0',
  rules: '...',
  signature: '...',
});

if (!result.valid) {
  for (const err of result.errors) {
    console.error(`${err.path}: ${err.message}`);
  }
}

// Access the raw JSON Schema for use in other languages
const schema = COVENANT_SCHEMA;
console.log(schema.$schema); // "https://json-schema.org/draft/2020-12/schema"

// Get all schemas at once
const all = getAllSchemas();
console.log(Object.keys(all)); // ['covenant', 'discovery', 'agentKey', 'cclContext']
```

## Docs

See the [Grith SDK root documentation](../../README.md) for the full API reference.
