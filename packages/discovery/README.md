# @stele/discovery

Cross-platform discovery protocol for `.well-known/stele/` endpoints. Enables agent key discovery, covenant registry lookup, cross-platform verification, and protocol negotiation.

## Installation

```bash
npm install @stele/discovery
```

## Key APIs

- **buildDiscoveryDocument(options)**: Generate a `.well-known/stele/configuration` document
- **validateDiscoveryDocument(doc)**: Validate a discovery document's structure and fields
- **buildKeyEntry(...)**: Create an `AgentKeyEntry` for the key registry
- **buildKeySet(...)**: Create an `AgentKeySet` grouping multiple keys for an agent
- **DiscoveryClient**: Fetch and validate discovery documents, key sets, and covenant registries from remote hosts
- **DiscoveryServer**: Serve discovery endpoints with configurable route handlers
- **WELL_KNOWN_PATH** / **CONFIGURATION_PATH** / **STELE_MEDIA_TYPE** / **MAX_DOCUMENT_AGE_MS**: Protocol constants

## Usage

```typescript
import {
  buildDiscoveryDocument,
  validateDiscoveryDocument,
  buildKeyEntry,
  DiscoveryClient,
  DiscoveryServer,
  WELL_KNOWN_PATH,
} from '@stele/discovery';

// Build a discovery document
const doc = buildDiscoveryDocument({
  platformId: 'my-platform',
  platformName: 'My Platform',
  covenantEndpoint: 'https://example.com/.well-known/stele/covenants',
  keyEndpoint: 'https://example.com/.well-known/stele/keys',
  negotiationEndpoint: 'https://example.com/.well-known/stele/negotiate',
});

// Validate a discovery document
const result = validateDiscoveryDocument(doc);
console.log(result.valid);

// Fetch a remote platform's discovery document
const client = new DiscoveryClient({ baseUrl: 'https://example.com' });
const remoteDoc = await client.fetchConfiguration();

// Serve discovery endpoints
const server = new DiscoveryServer({
  platformId: 'my-platform',
  platformName: 'My Platform',
});
```

## Types

- `DiscoveryDocument` -- Platform identity, endpoints, supported versions, and capabilities
- `AgentKeyEntry` / `AgentKeySet` -- Public key registry for agent verification
- `CovenantRegistryEntry` / `CovenantRegistryResponse` -- Covenant lookup by ID or agent
- `NegotiationRequest` / `NegotiationResponse` -- Cross-platform protocol negotiation
- `CrossPlatformVerificationRequest` / `CrossPlatformVerificationResponse` -- Remote covenant verification
- `DiscoveryClientOptions` / `DiscoveryServerOptions` -- Client and server configuration

## Docs

See the [Stele SDK root documentation](../../README.md) for the full API reference.
