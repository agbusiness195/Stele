/**
 * @kervyx/discovery/client — Cross-platform discovery client.
 *
 * Fetches, validates, and caches discovery documents from remote platforms.
 * This is what Agent A uses when it needs to verify Agent B's covenant
 * on a different platform.
 */

import { generateNonce, timestamp, toHex } from '@kervyx/crypto';
import type { KeyPair } from '@kervyx/crypto';

import type {
  DiscoveryDocument,
  AgentKeySet,
  AgentKeyEntry,
  CovenantRegistryResponse,
  NegotiationResponse,
  CrossPlatformVerificationRequest,
  CrossPlatformVerificationResponse,
  FetchOptions,
} from './types.js';
import { CONFIGURATION_PATH, validateDiscoveryDocument } from './well-known.js';

// ─── Cache Entry ─────────────────────────────────────────────────────────────

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

// ─── Discovery Client ────────────────────────────────────────────────────────

export interface DiscoveryClientOptions {
  /** Default fetch options. */
  fetchOptions?: FetchOptions;

  /** Custom fetch function (for testing or non-browser environments). */
  fetchFn?: (url: string, init?: RequestInit) => Promise<Response>;
}

/**
 * Client for the Kervyx cross-platform discovery protocol.
 *
 * Discovers, caches, and interacts with remote Kervyx platform endpoints.
 * This is the primary interface for cross-platform agent verification.
 *
 * @example
 * ```typescript
 * const client = new DiscoveryClient();
 *
 * // Discover a remote platform
 * const discovery = await client.discover('https://platform.example');
 *
 * // Look up an agent's keys
 * const keys = await client.getAgentKeys('https://platform.example', 'agent-123');
 *
 * // Verify a covenant cross-platform
 * const result = await client.verifyCovenant('https://platform.example', 'covenant-id-hex');
 * ```
 */
export class DiscoveryClient {
  private readonly _cache: Map<string, CacheEntry<unknown>> = new Map();
  private readonly _defaultOptions: FetchOptions;
  private readonly _fetchFn: (url: string, init?: RequestInit) => Promise<Response>;

  constructor(options?: DiscoveryClientOptions) {
    this._defaultOptions = {
      timeout: 10_000,
      cacheTtl: 300_000, // 5 minutes
      verifySignature: true,
      ...options?.fetchOptions,
    };

    // Use provided fetch function or fall back to global fetch
    this._fetchFn = options?.fetchFn ?? (
      typeof globalThis.fetch === 'function'
        ? globalThis.fetch.bind(globalThis)
        : async () => { throw new Error('No fetch implementation available. Provide a fetchFn in options.'); }
    );
  }

  /**
   * Discover a remote platform's Kervyx configuration.
   *
   * Fetches the discovery document from `{platformUrl}/.well-known/kervyx/configuration`,
   * validates its structure, and optionally verifies its signature.
   *
   * @param platformUrl - The platform's base URL (e.g., "https://platform.example").
   * @param options - Optional fetch configuration.
   * @returns The validated DiscoveryDocument.
   * @throws {Error} When the document is invalid or unreachable.
   */
  async discover(
    platformUrl: string,
    options?: FetchOptions,
  ): Promise<DiscoveryDocument> {
    const opts = { ...this._defaultOptions, ...options };
    const url = `${platformUrl.replace(/\/+$/, '')}${CONFIGURATION_PATH}`;

    // Check cache
    const cached = this._getCache<DiscoveryDocument>(url);
    if (cached) return cached;

    const response = await this._fetch(url, opts);
    const doc = await response.json() as DiscoveryDocument;

    // Validate
    const validation = await validateDiscoveryDocument(doc, {
      verifySignature: opts.verifySignature,
    });

    if (!validation.valid) {
      throw new Error(
        `Invalid discovery document from ${platformUrl}: ${validation.errors.join('; ')}`,
      );
    }

    // Cache
    this._setCache(url, doc, opts.cacheTtl ?? 300_000);

    return doc;
  }

  /**
   * Get the key set for a specific agent on a remote platform.
   *
   * @param platformUrl - The platform's base URL.
   * @param agentId - The agent's identifier.
   * @param options - Optional fetch configuration.
   * @returns The agent's key set.
   */
  async getAgentKeys(
    platformUrl: string,
    agentId: string,
    options?: FetchOptions,
  ): Promise<AgentKeyEntry[]> {
    const discovery = await this.discover(platformUrl, options);
    const url = `${discovery.keys_endpoint}?agent_id=${encodeURIComponent(agentId)}`;
    const opts = { ...this._defaultOptions, ...options };

    const response = await this._fetch(url, opts);
    const keySet = await response.json() as AgentKeySet;

    return keySet.keys.filter((k) => k.agent_id === agentId);
  }

  /**
   * Look up a specific key by its key ID (kid).
   *
   * @param platformUrl - The platform's base URL.
   * @param kid - The key identifier (SHA-256 of the public key).
   * @param options - Optional fetch configuration.
   * @returns The matching key entry, or undefined if not found.
   */
  async getKeyById(
    platformUrl: string,
    kid: string,
    options?: FetchOptions,
  ): Promise<AgentKeyEntry | undefined> {
    const discovery = await this.discover(platformUrl, options);
    const url = `${discovery.keys_endpoint}?kid=${encodeURIComponent(kid)}`;
    const opts = { ...this._defaultOptions, ...options };

    const response = await this._fetch(url, opts);
    const keySet = await response.json() as AgentKeySet;

    return keySet.keys.find((k) => k.kid === kid);
  }

  /**
   * Query the covenant registry on a remote platform.
   *
   * @param platformUrl - The platform's base URL.
   * @param query - Optional query parameters.
   * @param options - Optional fetch configuration.
   * @returns The covenant registry response.
   */
  async queryCovenants(
    platformUrl: string,
    query?: {
      issuer_id?: string;
      beneficiary_id?: string;
      status?: 'active' | 'expired' | 'revoked';
      cursor?: string;
      limit?: number;
    },
    options?: FetchOptions,
  ): Promise<CovenantRegistryResponse> {
    const discovery = await this.discover(platformUrl, options);

    const params = new URLSearchParams();
    if (query?.issuer_id) params.set('issuer_id', query.issuer_id);
    if (query?.beneficiary_id) params.set('beneficiary_id', query.beneficiary_id);
    if (query?.status) params.set('status', query.status);
    if (query?.cursor) params.set('cursor', query.cursor);
    if (query?.limit) params.set('limit', String(query.limit));

    const url = `${discovery.covenants_endpoint}${params.toString() ? '?' + params.toString() : ''}`;
    const opts = { ...this._defaultOptions, ...options };

    const response = await this._fetch(url, opts);
    return response.json() as Promise<CovenantRegistryResponse>;
  }

  /**
   * Verify a covenant cross-platform.
   *
   * Sends a verification request to the remote platform's verification endpoint.
   *
   * @param platformUrl - The platform's base URL.
   * @param covenantId - The covenant document ID to verify.
   * @param options - Optional fetch configuration.
   * @returns The cross-platform verification response.
   */
  async verifyCovenant(
    platformUrl: string,
    covenantId: string,
    options?: FetchOptions,
  ): Promise<CrossPlatformVerificationResponse> {
    const discovery = await this.discover(platformUrl, options);

    if (!discovery.verification_endpoint) {
      throw new Error(`Platform ${platformUrl} does not support cross-platform verification`);
    }

    const nonce = toHex(generateNonce());
    const request: CrossPlatformVerificationRequest = {
      covenant_id: covenantId,
      requesting_platform: 'local', // Will be overridden by actual platform URL
      timestamp: timestamp(),
      nonce,
    };

    const opts = { ...this._defaultOptions, ...options };
    const response = await this._fetchFn(discovery.verification_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/kervyx+json',
        ...opts.headers,
      },
      body: JSON.stringify(request),
      signal: opts.timeout ? AbortSignal.timeout(opts.timeout) : undefined,
    });

    if (!response.ok) {
      throw new Error(`Cross-platform verification failed: ${response.status} ${response.statusText}`);
    }

    return response.json() as Promise<CrossPlatformVerificationResponse>;
  }

  /**
   * Negotiate protocol capabilities with a remote platform.
   *
   * @param platformUrl - The remote platform's base URL.
   * @param localCapabilities - This platform's capabilities.
   * @param _signingKeyPair - Optional key pair for signing the request (reserved for future use).
   * @returns The negotiation response.
   */
  async negotiate(
    platformUrl: string,
    localCapabilities: {
      protocolVersions: string[];
      signatureSchemes: string[];
      hashAlgorithms: string[];
    },
    _signingKeyPair?: KeyPair,
  ): Promise<NegotiationResponse> {
    const discovery = await this.discover(platformUrl);

    // Find common capabilities
    const commonVersions = localCapabilities.protocolVersions.filter(
      (v) => discovery.protocol_versions_supported.includes(v),
    );
    const commonSchemes = localCapabilities.signatureSchemes.filter(
      (s) => discovery.signature_schemes_supported.includes(s),
    );
    const commonAlgorithms = localCapabilities.hashAlgorithms.filter(
      (a) => discovery.hash_algorithms_supported.includes(a),
    );

    if (commonVersions.length === 0 || commonSchemes.length === 0 || commonAlgorithms.length === 0) {
      return {
        accepted: false,
        rejection_reason: 'No common protocol capabilities found',
        timestamp: timestamp(),
        nonce: toHex(generateNonce()),
      };
    }

    return {
      accepted: true,
      agreed_version: commonVersions[0],
      agreed_signature_scheme: commonSchemes[0],
      agreed_hash_algorithm: commonAlgorithms[0],
      keys_endpoint: discovery.keys_endpoint,
      timestamp: timestamp(),
      nonce: toHex(generateNonce()),
    };
  }

  /**
   * Clear the discovery cache entirely or for a specific platform.
   *
   * @param platformUrl - Optional platform URL to clear (clears all if omitted).
   */
  clearCache(platformUrl?: string): void {
    if (platformUrl) {
      const prefix = platformUrl.replace(/\/+$/, '');
      for (const key of this._cache.keys()) {
        if (key.startsWith(prefix)) {
          this._cache.delete(key);
        }
      }
    } else {
      this._cache.clear();
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────

  private async _fetch(url: string, opts: FetchOptions): Promise<Response> {
    const response = await this._fetchFn(url, {
      headers: {
        Accept: 'application/kervyx+json, application/json',
        ...opts.headers,
      },
      signal: opts.timeout ? AbortSignal.timeout(opts.timeout) : undefined,
    });

    if (!response.ok) {
      throw new Error(`Discovery fetch failed: ${response.status} ${response.statusText} (${url})`);
    }

    return response;
  }

  private _getCache<T>(key: string): T | undefined {
    const entry = this._cache.get(key) as CacheEntry<T> | undefined;
    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this._cache.delete(key);
      return undefined;
    }

    return entry.value;
  }

  private _setCache<T>(key: string, value: T, ttl: number): void {
    this._cache.set(key, {
      value,
      expiresAt: Date.now() + ttl,
    });
  }
}
