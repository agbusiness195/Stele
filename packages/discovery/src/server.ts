/**
 * @usekova/discovery/server — Discovery server for serving .well-known/kova endpoints.
 *
 * Provides a framework-agnostic discovery server that manages discovery documents,
 * key sets, and covenant registries. Can be mounted in Express, Fastify, or
 * any HTTP framework.
 */

import type { CovenantDocument } from '@usekova/core';
import { verifyCovenant } from '@usekova/core';

import type {
  DiscoveryDocument,
  AgentKeyEntry,
  AgentKeySet,
  CovenantRegistryEntry,
  CovenantRegistryResponse,
  CrossPlatformVerificationRequest,
  CrossPlatformVerificationResponse,
} from './types.js';
import { buildDiscoveryDocument, buildKeyEntry, KOVA_MEDIA_TYPE, type BuildDiscoveryDocumentOptions } from './well-known.js';

// ─── Discovery Server ────────────────────────────────────────────────────────

export interface DiscoveryServerOptions extends BuildDiscoveryDocumentOptions {
  /** Maximum number of covenants to return per page. */
  pageSize?: number;
}

/**
 * A framework-agnostic discovery server for the Kova protocol.
 *
 * Manages discovery documents, agent key registries, and covenant registries.
 * Provides handler functions that can be mounted in any HTTP framework.
 *
 * @example
 * ```typescript
 * const server = new DiscoveryServer({
 *   issuer: 'https://my-platform.com',
 *   platformName: 'My AI Platform',
 *   signingKeyPair: platformKeyPair,
 * });
 *
 * // Register an agent's key
 * server.registerAgentKey('agent-1', publicKeyHex);
 *
 * // Register a covenant
 * server.registerCovenant(covenantDoc);
 *
 * // Mount handlers (framework-specific, e.g. Express):
 * app.get('/.well-known/kova/configuration', (req, res) => {
 *   const doc = server.getDiscoveryDocument();
 *   res.type('application/kova+json').json(doc);
 * });
 * ```
 */
export class DiscoveryServer {
  private _discoveryDoc: DiscoveryDocument | undefined;
  private readonly _options: DiscoveryServerOptions;
  private readonly _keys: Map<string, AgentKeyEntry> = new Map();
  private readonly _agentKeys: Map<string, Set<string>> = new Map(); // agentId -> Set<kid>
  private readonly _covenants: Map<string, CovenantRegistryEntry> = new Map();
  private readonly _covenantDocs: Map<string, CovenantDocument> = new Map();
  private readonly _pageSize: number;

  constructor(options: DiscoveryServerOptions) {
    this._options = options;
    this._pageSize = options.pageSize ?? 100;
  }

  /**
   * Get (or lazily build) the discovery document.
   */
  async getDiscoveryDocument(): Promise<DiscoveryDocument> {
    if (!this._discoveryDoc) {
      this._discoveryDoc = await buildDiscoveryDocument(this._options);
    }
    return this._discoveryDoc;
  }

  /**
   * Invalidate the cached discovery document (e.g., after configuration change).
   */
  invalidateDiscoveryDocument(): void {
    this._discoveryDoc = undefined;
  }

  /**
   * Register an agent's public key in the key registry.
   *
   * @param agentId - The agent's identifier.
   * @param publicKey - Hex-encoded Ed25519 public key.
   * @param options - Optional metadata.
   * @returns The created key entry.
   */
  registerAgentKey(
    agentId: string,
    publicKey: string,
    options?: { expiresAt?: string },
  ): AgentKeyEntry {
    const entry = buildKeyEntry(agentId, publicKey, options);

    this._keys.set(entry.kid, entry);

    if (!this._agentKeys.has(agentId)) {
      this._agentKeys.set(agentId, new Set());
    }
    this._agentKeys.get(agentId)!.add(entry.kid);

    return entry;
  }

  /**
   * Rotate an agent's key. Marks the old key as rotated and registers the new one.
   *
   * @param agentId - The agent's identifier.
   * @param oldKid - The key ID of the key being rotated.
   * @param newPublicKey - Hex-encoded new Ed25519 public key.
   * @returns The new key entry.
   */
  rotateAgentKey(
    agentId: string,
    oldKid: string,
    newPublicKey: string,
  ): AgentKeyEntry {
    const oldEntry = this._keys.get(oldKid);
    if (oldEntry) {
      const newEntry = this.registerAgentKey(agentId, newPublicKey);
      oldEntry.status = 'rotated';
      oldEntry.deactivated_at = new Date().toISOString();
      oldEntry.replaced_by = newEntry.kid;
      return newEntry;
    }
    return this.registerAgentKey(agentId, newPublicKey);
  }

  /**
   * Revoke an agent's key.
   *
   * @param kid - The key ID to revoke.
   */
  revokeKey(kid: string): void {
    const entry = this._keys.get(kid);
    if (entry) {
      entry.status = 'revoked';
      entry.deactivated_at = new Date().toISOString();
    }
  }

  /**
   * Get the key set, optionally filtered by agent ID or key ID.
   *
   * @param query - Optional filter parameters.
   * @returns The matching key set.
   */
  getKeySet(query?: { agentId?: string; kid?: string }): AgentKeySet {
    let keys = Array.from(this._keys.values());

    if (query?.agentId) {
      const kids = this._agentKeys.get(query.agentId);
      if (kids) {
        keys = keys.filter((k) => kids.has(k.kid));
      } else {
        keys = [];
      }
    }

    if (query?.kid) {
      keys = keys.filter((k) => k.kid === query.kid);
    }

    return { keys };
  }

  /**
   * Register a covenant document in the registry.
   *
   * @param doc - The covenant document to register.
   */
  registerCovenant(doc: CovenantDocument): void {
    const entry: CovenantRegistryEntry = {
      id: doc.id,
      issuer_id: doc.issuer.id,
      beneficiary_id: doc.beneficiary.id,
      created_at: doc.createdAt,
      expires_at: doc.expiresAt,
      status: this._computeCovenantStatus(doc),
      protocol_version: doc.version,
      document_url: `${this._options.issuer.replace(/\/+$/, '')}/.well-known/kova/covenants/${doc.id}`,
    };

    this._covenants.set(doc.id, entry);
    this._covenantDocs.set(doc.id, doc);
  }

  /**
   * Query the covenant registry.
   *
   * @param query - Filter parameters.
   * @returns A paginated covenant registry response.
   */
  queryCovenants(query?: {
    issuerId?: string;
    beneficiaryId?: string;
    status?: 'active' | 'expired' | 'revoked';
    cursor?: string;
    limit?: number;
  }): CovenantRegistryResponse {
    let entries = Array.from(this._covenants.values());

    if (query?.issuerId) {
      entries = entries.filter((e) => e.issuer_id === query.issuerId);
    }
    if (query?.beneficiaryId) {
      entries = entries.filter((e) => e.beneficiary_id === query.beneficiaryId);
    }
    if (query?.status) {
      entries = entries.filter((e) => e.status === query.status);
    }

    const total = entries.length;
    const limit = query?.limit ?? this._pageSize;

    // Simple cursor-based pagination
    let startIdx = 0;
    if (query?.cursor) {
      const cursorIdx = entries.findIndex((e) => e.id === query.cursor);
      if (cursorIdx >= 0) startIdx = cursorIdx + 1;
    }

    const page = entries.slice(startIdx, startIdx + limit);
    const nextCursor = startIdx + limit < total ? entries[startIdx + limit]?.id : undefined;

    return {
      covenants: page,
      total,
      next_cursor: nextCursor,
    };
  }

  /**
   * Get a specific covenant document by ID.
   *
   * @param covenantId - The covenant document ID.
   * @returns The covenant document, or undefined if not found.
   */
  getCovenantDocument(covenantId: string): CovenantDocument | undefined {
    return this._covenantDocs.get(covenantId);
  }

  /**
   * Handle a cross-platform verification request.
   *
   * @param request - The verification request.
   * @returns The verification response.
   */
  async handleVerificationRequest(
    request: CrossPlatformVerificationRequest,
  ): Promise<CrossPlatformVerificationResponse> {
    const doc = this._covenantDocs.get(request.covenant_id);

    if (!doc) {
      return {
        covenant_id: request.covenant_id,
        valid: false,
        checks: [{ name: 'exists', passed: false, message: 'Covenant not found' }],
        timestamp: new Date().toISOString(),
      };
    }

    const result = await verifyCovenant(doc);

    return {
      covenant_id: request.covenant_id,
      valid: result.valid,
      checks: result.checks.map((c) => ({
        name: c.name,
        passed: c.passed,
        message: c.message,
      })),
      timestamp: new Date().toISOString(),
    };
  }

  // ── Route handlers (framework-agnostic) ────────────────────────────────

  /**
   * Get all route handlers as a map of path -> handler function.
   * Each handler takes (query params) and returns { status, headers, body }.
   *
   * @returns A map of route handlers for mounting in any HTTP framework.
   */
  getRouteHandlers(): Map<string, RouteHandler> {
    const handlers = new Map<string, RouteHandler>();

    handlers.set('GET /.well-known/kova/configuration', async () => ({
      status: 200,
      headers: { 'Content-Type': KOVA_MEDIA_TYPE, 'Cache-Control': 'public, max-age=3600' },
      body: await this.getDiscoveryDocument(),
    }));

    handlers.set('GET /.well-known/kova/keys', async (query) => ({
      status: 200,
      headers: { 'Content-Type': KOVA_MEDIA_TYPE },
      body: this.getKeySet({
        agentId: query?.agent_id as string | undefined,
        kid: query?.kid as string | undefined,
      }),
    }));

    handlers.set('GET /.well-known/kova/covenants', async (query) => ({
      status: 200,
      headers: { 'Content-Type': KOVA_MEDIA_TYPE },
      body: this.queryCovenants({
        issuerId: query?.issuer_id as string | undefined,
        beneficiaryId: query?.beneficiary_id as string | undefined,
        status: query?.status as 'active' | 'expired' | 'revoked' | undefined,
        cursor: query?.cursor as string | undefined,
        limit: query?.limit ? Number(query.limit) : undefined,
      }),
    }));

    handlers.set('POST /.well-known/kova/verify', async (_query, body) => {
      const request = body as CrossPlatformVerificationRequest;
      const result = await this.handleVerificationRequest(request);
      return {
        status: 200,
        headers: { 'Content-Type': KOVA_MEDIA_TYPE },
        body: result,
      };
    });

    return handlers;
  }

  // ── Private helpers ────────────────────────────────────────────────────

  private _computeCovenantStatus(doc: CovenantDocument): 'active' | 'expired' | 'revoked' {
    if (doc.expiresAt && new Date(doc.expiresAt) < new Date()) {
      return 'expired';
    }
    return 'active';
  }
}

/**
 * A framework-agnostic route handler function.
 */
export type RouteHandler = (
  query?: Record<string, unknown>,
  body?: unknown,
) => Promise<{
  status: number;
  headers: Record<string, string>;
  body: unknown;
}>;
