/**
 * @stele/schema — Formal JSON Schema definitions for Stele protocol documents.
 *
 * Provides machine-readable schemas (JSON Schema Draft 2020-12) for:
 * - Covenant documents
 * - Discovery documents
 * - Agent key entries
 * - CCL evaluation contexts
 *
 * These schemas enable any language implementation to validate
 * Stele protocol documents without the TypeScript SDK.
 *
 * @packageDocumentation
 */

// Schema definitions
export {
  COVENANT_SCHEMA,
  DISCOVERY_DOCUMENT_SCHEMA,
  AGENT_KEY_SCHEMA,
  CCL_EVALUATION_CONTEXT_SCHEMA,
} from './covenant.js';

// Validation functions
export {
  validateCovenantSchema,
  validateDiscoverySchema,
  validateAgentKeySchema,
  getAllSchemas,
} from './validate.js';
export type {
  SchemaValidationError,
  SchemaValidationResult,
} from './validate.js';
