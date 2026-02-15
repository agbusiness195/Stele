/**
 * @stele/discovery — Cross-platform discovery protocol for Stele.
 *
 * Implements the `.well-known/stele/` endpoint specification,
 * enabling cross-platform agent verification, key discovery,
 * and protocol negotiation.
 *
 * @packageDocumentation
 */

// Types
export type {
  DiscoveryDocument,
  AgentKeyEntry,
  AgentKeySet,
  CovenantRegistryEntry,
  CovenantRegistryResponse,
  NegotiationRequest,
  NegotiationResponse,
  CrossPlatformVerificationRequest,
  CrossPlatformVerificationResponse,
  FetchOptions,
} from './types.js';

// Well-known document generation & validation
export {
  buildDiscoveryDocument,
  validateDiscoveryDocument,
  buildKeyEntry,
  buildKeySet,
  WELL_KNOWN_PATH,
  CONFIGURATION_PATH,
  STELE_MEDIA_TYPE,
  MAX_DOCUMENT_AGE_MS,
} from './well-known.js';
export type { BuildDiscoveryDocumentOptions, DiscoveryValidationResult } from './well-known.js';

// Discovery client
export { DiscoveryClient } from './client.js';
export type { DiscoveryClientOptions } from './client.js';

// Discovery server
export { DiscoveryServer } from './server.js';
export type { DiscoveryServerOptions, RouteHandler } from './server.js';

// Federated discovery protocol
export {
  createFederationConfig,
  addResolver,
  removeResolver,
  resolveAgent,
  selectOptimalResolvers,
} from './federation.js';
export type {
  FederatedResolver,
  FederationConfig,
  ResolutionResult,
} from './federation.js';

// Trust-gated marketplace
export {
  createMarketplace,
  listAgent,
  searchMarketplace,
  createTransaction,
  completeTransaction,
  disputeTransaction,
} from './marketplace.js';
export type {
  MarketplaceListing,
  MarketplaceConfig,
  MarketplaceQuery,
  MarketplaceTransaction,
} from './marketplace.js';
