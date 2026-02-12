/**
 * Lightweight schema validation for Stele documents.
 *
 * Provides validation against the formal JSON Schema definitions
 * without requiring external dependencies (no Ajv).
 * For full JSON Schema validation, use an external validator
 * with the exported schema objects.
 */

import { COVENANT_SCHEMA, DISCOVERY_DOCUMENT_SCHEMA, AGENT_KEY_SCHEMA, CCL_EVALUATION_CONTEXT_SCHEMA } from './covenant.js';

export interface SchemaValidationError {
  path: string;
  message: string;
  value?: unknown;
}

export interface SchemaValidationResult {
  valid: boolean;
  errors: SchemaValidationError[];
}

/**
 * Validate a value against a simple schema definition.
 * This handles the subset of JSON Schema used in our definitions.
 */
function validateField(
  value: unknown,
  schema: Record<string, unknown>,
  path: string,
  errors: SchemaValidationError[],
): void {
  // Type check
  const schemaType = schema.type as string | undefined;
  if (schemaType === 'string') {
    if (typeof value !== 'string') {
      errors.push({ path, message: `must be a string`, value });
      return;
    }
    const minLength = schema.minLength as number | undefined;
    if (minLength !== undefined && value.length < minLength) {
      errors.push({ path, message: `must have minimum length ${minLength}`, value });
    }
    const pattern = schema.pattern as string | undefined;
    if (pattern && !new RegExp(pattern).test(value)) {
      errors.push({ path, message: `must match pattern ${pattern}`, value });
    }
    const constVal = schema.const as string | undefined;
    if (constVal !== undefined && value !== constVal) {
      errors.push({ path, message: `must be "${constVal}"`, value });
    }
    const enumVals = schema.enum as string[] | undefined;
    if (enumVals && !enumVals.includes(value)) {
      errors.push({ path, message: `must be one of: ${enumVals.join(', ')}`, value });
    }
  } else if (schemaType === 'integer' || schemaType === 'number') {
    if (typeof value !== 'number') {
      errors.push({ path, message: `must be a number`, value });
      return;
    }
    if (schemaType === 'integer' && !Number.isInteger(value)) {
      errors.push({ path, message: `must be an integer`, value });
    }
    const minimum = schema.minimum as number | undefined;
    if (minimum !== undefined && value < minimum) {
      errors.push({ path, message: `must be >= ${minimum}`, value });
    }
    const maximum = schema.maximum as number | undefined;
    if (maximum !== undefined && value > maximum) {
      errors.push({ path, message: `must be <= ${maximum}`, value });
    }
  } else if (schemaType === 'array') {
    if (!Array.isArray(value)) {
      errors.push({ path, message: `must be an array`, value });
      return;
    }
    const minItems = schema.minItems as number | undefined;
    if (minItems !== undefined && value.length < minItems) {
      errors.push({ path, message: `must have at least ${minItems} items`, value });
    }
    const items = schema.items as Record<string, unknown> | undefined;
    if (items) {
      for (let i = 0; i < value.length; i++) {
        validateField(value[i], items, `${path}[${i}]`, errors);
      }
    }
  } else if (schemaType === 'object') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      errors.push({ path, message: `must be an object`, value });
      return;
    }
    const obj = value as Record<string, unknown>;
    const properties = schema.properties as Record<string, Record<string, unknown>> | undefined;
    const required = schema.required as readonly string[] | undefined;

    if (required) {
      for (const key of required) {
        if (obj[key] === undefined) {
          errors.push({ path: path ? `${path}.${key}` : key, message: `is required`, value: undefined });
        }
      }
    }

    if (properties) {
      for (const [key, propSchema] of Object.entries(properties)) {
        if (obj[key] !== undefined) {
          validateField(obj[key], propSchema, path ? `${path}.${key}` : key, errors);
        }
      }
    }
  }
}

/**
 * Validate a covenant document against the formal JSON Schema.
 *
 * @param doc - The document to validate.
 * @returns Validation result with errors (if any).
 *
 * @example
 * ```typescript
 * const result = validateCovenantSchema(doc);
 * if (!result.valid) {
 *   console.error(result.errors);
 * }
 * ```
 */
export function validateCovenantSchema(doc: unknown): SchemaValidationResult {
  const errors: SchemaValidationError[] = [];
  validateField(doc, COVENANT_SCHEMA as unknown as Record<string, unknown>, '', errors);
  return { valid: errors.length === 0, errors };
}

/**
 * Validate a discovery document against the formal JSON Schema.
 *
 * @param doc - The document to validate.
 * @returns Validation result with errors (if any).
 */
export function validateDiscoverySchema(doc: unknown): SchemaValidationResult {
  const errors: SchemaValidationError[] = [];
  validateField(doc, DISCOVERY_DOCUMENT_SCHEMA as unknown as Record<string, unknown>, '', errors);
  return { valid: errors.length === 0, errors };
}

/**
 * Validate an agent key entry against the formal JSON Schema.
 *
 * @param key - The key entry to validate.
 * @returns Validation result with errors (if any).
 */
export function validateAgentKeySchema(key: unknown): SchemaValidationResult {
  const errors: SchemaValidationError[] = [];
  validateField(key, AGENT_KEY_SCHEMA as unknown as Record<string, unknown>, '', errors);
  return { valid: errors.length === 0, errors };
}

/**
 * Get all schemas as a map for external validators (like Ajv).
 *
 * @returns A map of schema ID -> schema object.
 *
 * @example
 * ```typescript
 * import Ajv from 'ajv';
 * import { getAllSchemas } from '@stele/schema';
 *
 * const ajv = new Ajv();
 * for (const [id, schema] of Object.entries(getAllSchemas())) {
 *   ajv.addSchema(schema, id);
 * }
 * ```
 */
export function getAllSchemas(): Record<string, unknown> {
  return {
    'covenant-document': COVENANT_SCHEMA,
    'discovery-document': DISCOVERY_DOCUMENT_SCHEMA,
    'agent-key': AGENT_KEY_SCHEMA,
    'ccl-evaluation-context': CCL_EVALUATION_CONTEXT_SCHEMA,
  };
}
