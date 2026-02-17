/**
 * @stele/sdk -- High-level TypeScript SDK that unifies the entire Stele protocol.
 *
 * Provides a single entry point (SteleClient) for key management, covenant
 * lifecycle, identity management, chain operations, and CCL utilities.
 *
 * @packageDocumentation
 */

// ─── Imports from underlying packages ───────────────────────────────────────

import {
  generateKeyPair as cryptoGenerateKeyPair,
  timestamp,
  KeyManager,
} from '@stele/crypto';
import type { KeyPair, KeyRotationPolicy, ManagedKeyPair } from '@stele/crypto';

import {
  buildCovenant,
  verifyCovenant as coreVerifyCovenant,
  countersignCovenant,
  resolveChain as coreResolveChain,
  computeEffectiveConstraints,
  validateChainNarrowing,
  MemoryChainResolver,
  CovenantBuildError,
  CovenantVerificationError,
  PROTOCOL_VERSION,
  MAX_CONSTRAINTS,
  MAX_CHAIN_DEPTH,
  MAX_DOCUMENT_SIZE,
  canonicalForm,
  computeId,
  resignCovenant,
  serializeCovenant,
  deserializeCovenant,
} from '@stele/core';
import type {
  CovenantDocument,
  VerificationResult,
  CovenantBuilderOptions,
  Issuer,
  Beneficiary,
  PartyRole,
} from '@stele/core';

import {
  parse as cclParse,
  evaluate as cclEvaluate,
  matchAction as cclMatchAction,
  matchResource as cclMatchResource,
  merge as cclMerge,
  serialize as cclSerialize,
  checkRateLimit as cclCheckRateLimit,
  validateNarrowing as cclValidateNarrowing,
} from '@stele/ccl';
import type { CCLDocument, EvaluationContext } from '@stele/ccl';

import {
  createIdentity as identityCreate,
  evolveIdentity as identityEvolve,
  verifyIdentity as identityVerify,
} from '@stele/identity';
import type { AgentIdentity } from '@stele/identity';

import type {
  SteleClientOptions,
  CreateCovenantOptions,
  EvaluationResult,
  CreateIdentityOptions,
  EvolveOptions,
  ChainValidationResult,
  NarrowingViolationEntry,
  SteleEventType,
  SteleEventMap,
  SteleEventHandler,
} from './types.js';

// ─── Re-exports ─────────────────────────────────────────────────────────────

// Re-export conformance suite
export {
  runConformanceSuite,
  cryptoConformance,
  cclConformance,
  covenantConformance,
  interopConformance,
  securityConformance,
} from './conformance.js';
export type {
  ConformanceResult,
  ConformanceFailure,
  ConformanceTarget,
} from './conformance.js';

// Re-export middleware system
export { MiddlewarePipeline, loggingMiddleware, validationMiddleware, timingMiddleware, rateLimitMiddleware } from './middleware.js';
export type { MiddlewareContext, MiddlewareResult, MiddlewareFn, SteleMiddleware } from './middleware.js';

// Re-export plugins
export * from './plugins/index.js';

// Re-export telemetry
export {
  telemetryMiddleware,
  SteleMetrics,
  NoopTracer,
  NoopMeter,
  NoopSpan,
  NoopCounter,
  NoopHistogram,
  createTelemetry,
  SpanStatusCode,
} from './telemetry.js';
export type {
  Span,
  Tracer,
  Meter,
  Counter,
  Histogram,
  TelemetryMiddlewareOptions,
  CreateTelemetryOptions,
  EventSource,
} from './telemetry.js';

// Re-export all SDK types
export type {
  SteleClientOptions,
  CreateCovenantOptions,
  EvaluationResult,
  CreateIdentityOptions,
  EvolveOptions,
  ChainValidationResult,
  NarrowingViolationEntry,
  SteleEventType,
  SteleEventMap,
  SteleEventHandler,
  CovenantCreatedEvent,
  CovenantVerifiedEvent,
  CovenantCountersignedEvent,
  IdentityCreatedEvent,
  IdentityEvolvedEvent,
  ChainResolvedEvent,
  ChainValidatedEvent,
  EvaluationCompletedEvent,
  KeyRotatedEvent,
  SteleEvent,
} from './types.js';

// Re-export core types
export type {
  CovenantDocument,
  CovenantBuilderOptions,
  VerificationResult,
  VerificationCheck,
  Issuer,
  Beneficiary,
  Party,
  ChainReference,
  EnforcementConfig,
  ProofConfig,
  RevocationConfig,
  CovenantMetadata,
  Obligation,
  PartyRole,
  Countersignature,
  ChainRelation,
  EnforcementType,
  ProofType,
  RevocationMethod,
  Severity,
} from '@stele/core';

export {
  PROTOCOL_VERSION,
  MAX_CONSTRAINTS,
  MAX_CHAIN_DEPTH,
  MAX_DOCUMENT_SIZE,
  CovenantBuildError,
  CovenantVerificationError,
  MemoryChainResolver,
  canonicalForm,
  computeId,
  buildCovenant,
  verifyCovenant as verifyCovenant_core,
  countersignCovenant,
  resignCovenant,
  serializeCovenant,
  deserializeCovenant,
  resolveChain as resolveChain_core,
  computeEffectiveConstraints,
  validateChainNarrowing,
} from '@stele/core';

export type { ChainResolver } from '@stele/core';

// Re-export crypto types and functions
export type {
  KeyPair,
  HashHex,
  Base64Url,
  PrivateKey,
  PublicKey,
  Signature,
  DetachedSignature,
  Nonce,
  KeyRotationPolicy,
  ManagedKeyPair,
} from '@stele/crypto';

export {
  generateKeyPair,
  sign,
  signString,
  verify,
  sha256,
  sha256String,
  sha256Object,
  canonicalizeJson,
  toHex,
  fromHex,
  base64urlEncode,
  base64urlDecode,
  generateNonce,
  generateId,
  constantTimeEqual,
  timestamp,
  keyPairFromPrivateKey,
  keyPairFromPrivateKeyHex,
  KeyManager,
} from '@stele/crypto';

// Re-export CCL types and functions
export type {
  CCLDocument,
  EvaluationContext,
  EvaluationResult as CCLEvaluationResult,
  Statement,
  PermitDenyStatement,
  RequireStatement,
  LimitStatement,
  Condition,
  CompoundCondition,
  NarrowingViolation,
} from '@stele/ccl';

export {
  parse as parseCCL,
  evaluate as evaluateCCL,
  matchAction,
  matchResource,
  specificity,
  evaluateCondition,
  checkRateLimit,
  merge as mergeCCL,
  validateNarrowing,
  serialize as serializeCCL,
  tokenize,
  parseTokens,
  CCLSyntaxError,
  CCLValidationError,
} from '@stele/ccl';

// Re-export identity types and functions
export type {
  AgentIdentity,
  ModelAttestation,
  DeploymentContext,
  LineageEntry,
  EvolutionPolicy,
  CreateIdentityOptions as CoreCreateIdentityOptions,
  EvolveIdentityOptions as CoreEvolveIdentityOptions,
  RuntimeType,
} from '@stele/identity';

export {
  createIdentity as createIdentity_core,
  evolveIdentity as evolveIdentity_core,
  verifyIdentity,
  computeCapabilityManifestHash,
  computeIdentityHash,
  computeCarryForward,
  getLineage,
  shareAncestor,
  serializeIdentity,
  deserializeIdentity,
  DEFAULT_EVOLUTION_POLICY,
  triggerReverification,
  computeDecayedTrust,
  completeReverification,
} from '@stele/identity';

// ─── SteleClient ────────────────────────────────────────────────────────────

/**
 * The main entry point for the Stele SDK.
 *
 * Provides a unified, high-level API for the entire Stele protocol:
 * key management, covenant lifecycle, identity management, chain
 * operations, and CCL utilities.
 *
 * @example
 * ```typescript
 * const client = new SteleClient();
 * await client.generateKeyPair();
 *
 * const doc = await client.createCovenant({
 *   issuer: { id: 'alice', publicKey: client.keyPair!.publicKeyHex, role: 'issuer' },
 *   beneficiary: { id: 'bob', publicKey: bobPubHex, role: 'beneficiary' },
 *   constraints: "permit read on '/data/**'",
 * });
 *
 * const result = await client.verifyCovenant(doc);
 * console.log(result.valid); // true
 * ```
 */
export class SteleClient {
  private _keyPair: KeyPair | undefined;
  private readonly _agentId: string | undefined;
  private readonly _strictMode: boolean;
  private readonly _listeners: Map<SteleEventType, Set<SteleEventHandler<SteleEventType>>>;
  private _keyManager: KeyManager | undefined;

  constructor(options: SteleClientOptions = {}) {
    this._keyPair = options.keyPair;
    this._agentId = options.agentId;
    this._strictMode = options.strictMode ?? false;
    this._listeners = new Map();

    if (options.keyRotation) {
      this._keyManager = new KeyManager({
        maxAgeMs: options.keyRotation.maxAgeMs,
        overlapPeriodMs: options.keyRotation.overlapPeriodMs,
        onRotation: options.keyRotation.onRotation,
      });
    }
  }

  // ── Accessors ───────────────────────────────────────────────────────────

  /** The currently configured key pair, if any. */
  get keyPair(): KeyPair | undefined {
    return this._keyPair;
  }

  /** The currently configured agent ID, if any. */
  get agentId(): string | undefined {
    return this._agentId;
  }

  /** Whether strict mode is enabled. */
  get strictMode(): boolean {
    return this._strictMode;
  }

  /** Get the key manager instance, if key rotation is configured. */
  get keyManager(): KeyManager | undefined {
    return this._keyManager;
  }

  // ── Key management ──────────────────────────────────────────────────────

  /**
   * Generate a new Ed25519 key pair and set it as the client's active key pair.
   *
   * Subsequent operations (createCovenant, countersign, etc.) will use this
   * key pair automatically unless overridden per-call.
   *
   * If key rotation is configured and initialized, returns the current
   * managed key pair instead of generating a new one.
   *
   * @returns The generated key pair.
   *
   * @example
   * ```typescript
   * const kp = await client.generateKeyPair();
   * console.log(kp.publicKeyHex); // 64-char hex
   * ```
   */
  async generateKeyPair(): Promise<KeyPair> {
    if (this._keyManager) {
      try {
        const managed = this._keyManager.current();
        this._keyPair = managed.keyPair;
        return managed.keyPair;
      } catch {
        // KeyManager not initialized yet, fall through to normal generation
      }
    }
    const kp = await cryptoGenerateKeyPair();
    this._keyPair = kp;
    return kp;
  }

  /**
   * Initialize key rotation. Generates the first key and starts lifecycle management.
   *
   * Requires that the client was constructed with a `keyRotation` policy.
   * After initialization, the managed key becomes the client's active key pair.
   *
   * @throws {Error} When key rotation is not configured.
   */
  async initializeKeyRotation(): Promise<void> {
    if (!this._keyManager) {
      throw new Error(
        'Key rotation is not configured. Pass { keyRotation } in the client options.',
      );
    }
    const managed = await this._keyManager.initialize();
    this._keyPair = managed.keyPair;
  }

  /**
   * Check if the current key needs rotation and rotate if necessary.
   *
   * If the key manager determines that the current key has exceeded its
   * maximum age, a new key is generated and the old key enters the overlap
   * period. Emits a `key:rotated` event on rotation.
   *
   * @returns `true` if rotation occurred, `false` otherwise.
   * @throws {Error} When key rotation is not configured.
   */
  async rotateKeyIfNeeded(): Promise<boolean> {
    if (!this._keyManager) {
      throw new Error(
        'Key rotation is not configured. Pass { keyRotation } in the client options.',
      );
    }

    if (!this._keyManager.needsRotation()) {
      return false;
    }

    const { previous, current } = await this._keyManager.rotate();
    this._keyPair = current.keyPair;

    this._emit('key:rotated', {
      type: 'key:rotated',
      timestamp: timestamp(),
      previousPublicKey: previous.keyPair.publicKeyHex,
      currentPublicKey: current.keyPair.publicKeyHex,
    });

    return true;
  }

  // ── Covenant lifecycle ──────────────────────────────────────────────────

  /**
   * Create a new, signed covenant document.
   *
   * If `options.privateKey` is not provided, the client's key pair is used.
   * Emits a `covenant:created` event on success.
   *
   * @param options - Covenant creation options including parties and constraints.
   * @returns A complete, signed CovenantDocument.
   * @throws {CovenantBuildError} When validation of inputs or CCL parsing fails.
   * @throws {Error} When no private key is available.
   *
   * @example
   * ```typescript
   * const doc = await client.createCovenant({
   *   issuer: { id: 'alice', publicKey: pubHex, role: 'issuer' },
   *   beneficiary: { id: 'bob', publicKey: bobHex, role: 'beneficiary' },
   *   constraints: "permit read on '/data/**'",
   * });
   * ```
   */
  async createCovenant(options: CreateCovenantOptions): Promise<CovenantDocument> {
    // ── Input validation (Stripe-quality errors at the public API boundary) ──
    if (!options.issuer || !options.issuer.id) {
      throw new Error(
        "SteleClient.createCovenant(): issuer.id is required. Provide a non-empty string identifying the issuing party.",
      );
    }
    if (!options.beneficiary || !options.beneficiary.id) {
      throw new Error(
        "SteleClient.createCovenant(): beneficiary.id is required. Provide a non-empty string identifying the beneficiary party.",
      );
    }
    if (!options.constraints || options.constraints.trim().length === 0) {
      throw new Error(
        "SteleClient.createCovenant(): constraints must be a non-empty CCL string. Example: permit read on '/data/**'",
      );
    }

    // Auto-rotate key if key rotation is configured and initialized
    if (this._keyManager && !options.privateKey) {
      try {
        await this.rotateKeyIfNeeded();
      } catch {
        // KeyManager may not be initialized; fall through to normal key resolution
      }
    }

    const privateKey = options.privateKey ?? this._keyPair?.privateKey;
    if (!privateKey) {
      throw new Error(
        "SteleClient.createCovenant(): No private key available. Either call client.generateKeyPair() first, or pass { privateKey } in the options.",
      );
    }

    const builderOpts: CovenantBuilderOptions = {
      issuer: options.issuer,
      beneficiary: options.beneficiary,
      constraints: options.constraints,
      privateKey,
      obligations: options.obligations,
      chain: options.chain,
      enforcement: options.enforcement,
      proof: options.proof,
      revocation: options.revocation,
      metadata: options.metadata,
      expiresAt: options.expiresAt,
      activatesAt: options.activatesAt,
    };

    const doc = await buildCovenant(builderOpts);

    this._emit('covenant:created', {
      type: 'covenant:created',
      timestamp: timestamp(),
      document: doc,
    });

    return doc;
  }

  /**
   * Verify a covenant document by running all specification checks.
   *
   * Checks include signature validity, ID integrity, protocol version,
   * party roles, expiry, and constraint syntax. In strict mode, throws
   * `CovenantVerificationError` on failure. Emits a `covenant:verified` event.
   *
   * @param doc - The covenant document to verify.
   * @returns A VerificationResult with `valid` and detailed `checks` array.
   * @throws {CovenantVerificationError} In strict mode when verification fails.
   *
   * @example
   * ```typescript
   * const result = await client.verifyCovenant(doc);
   * if (!result.valid) {
   *   console.log(result.checks.filter(c => !c.passed));
   * }
   * ```
   */
  async verifyCovenant(doc: CovenantDocument): Promise<VerificationResult> {
    const result = await coreVerifyCovenant(doc);

    this._emit('covenant:verified', {
      type: 'covenant:verified',
      timestamp: timestamp(),
      result,
    });

    if (this._strictMode && !result.valid) {
      throw new CovenantVerificationError(
        `Covenant verification failed: ${result.checks.filter((c) => !c.passed).map((c) => c.name).join(', ')}`,
        result.checks,
      );
    }

    return result;
  }

  /**
   * Add a countersignature to a covenant document.
   *
   * If no key pair is provided, the client's key pair is used.
   * Emits a `covenant:countersigned` event on success. Returns a
   * new document; the original is not mutated.
   *
   * @param doc - The covenant document to countersign.
   * @param signerRole - Role of the countersigner (default: `'auditor'`).
   * @param signerKeyPair - Optional key pair override.
   * @returns A new CovenantDocument with the countersignature appended.
   * @throws {Error} When no key pair is available.
   *
   * @example
   * ```typescript
   * const audited = await client.countersign(doc, 'auditor');
   * ```
   */
  async countersign(
    doc: CovenantDocument,
    signerRole: PartyRole = 'auditor',
    signerKeyPair?: KeyPair,
  ): Promise<CovenantDocument> {
    // Auto-rotate key if key rotation is configured and initialized
    if (this._keyManager && !signerKeyPair) {
      try {
        await this.rotateKeyIfNeeded();
      } catch {
        // KeyManager may not be initialized; fall through to normal key resolution
      }
    }

    const kp = signerKeyPair ?? this._keyPair;
    if (!kp) {
      throw new Error(
        "SteleClient.countersign(): No key pair available. Either call client.generateKeyPair() first, or pass a KeyPair as the third argument.",
      );
    }

    const result = await countersignCovenant(doc, kp, signerRole);

    this._emit('covenant:countersigned', {
      type: 'covenant:countersigned',
      timestamp: timestamp(),
      document: result,
      signerRole,
    });

    return result;
  }

  /**
   * Evaluate an action/resource pair against a covenant's CCL constraints.
   *
   * Parses the covenant's constraints and runs the CCL evaluator.
   * Uses default-deny semantics: if no rules match, the result is
   * `permitted: false`. Emits an `evaluation:completed` event.
   *
   * @param doc - The covenant document containing CCL constraints.
   * @param action - The action to evaluate (e.g. `"read"`, `"api.call"`).
   * @param resource - The target resource (e.g. `"/data/users"`).
   * @param context - Optional evaluation context for condition checking.
   * @returns An EvaluationResult with the access decision.
   *
   * @example
   * ```typescript
   * const result = await client.evaluateAction(doc, 'read', '/data/users');
   * console.log(result.permitted); // true or false
   * ```
   */
  async evaluateAction(
    doc: CovenantDocument,
    action: string,
    resource: string,
    context?: EvaluationContext,
  ): Promise<EvaluationResult> {
    if (!action || action.trim().length === 0) {
      throw new Error(
        "SteleClient.evaluateAction(): action must be a non-empty string (e.g., 'read', 'write', 'api.call').",
      );
    }
    if (!resource || resource.trim().length === 0) {
      throw new Error(
        "SteleClient.evaluateAction(): resource must be a non-empty string (e.g., '/data/**', '/api/endpoint').",
      );
    }

    const cclDoc = cclParse(doc.constraints);
    const cclResult = cclEvaluate(cclDoc, action, resource, context);

    const result: EvaluationResult = {
      permitted: cclResult.permitted,
      matchedRule: cclResult.matchedRule,
      allMatches: cclResult.allMatches,
      reason: cclResult.reason,
      severity: cclResult.severity,
    };

    this._emit('evaluation:completed', {
      type: 'evaluation:completed',
      timestamp: timestamp(),
      result,
      action,
      resource,
    });

    return result;
  }

  // ── Identity ────────────────────────────────────────────────────────────

  /**
   * Create a new agent identity.
   *
   * If `options.operatorKeyPair` is not provided, the client's key pair is used.
   * Emits an `identity:created` event on success.
   *
   * @param options - Identity creation options including model and capabilities.
   * @returns A signed AgentIdentity object.
   * @throws {Error} When no key pair is available.
   *
   * @example
   * ```typescript
   * const identity = await client.createIdentity({
   *   model: { provider: 'anthropic', modelId: 'claude-3' },
   *   capabilities: ['read', 'write'],
   *   deployment: { runtime: 'container' },
   * });
   * ```
   */
  async createIdentity(options: CreateIdentityOptions): Promise<AgentIdentity> {
    const operatorKeyPair = options.operatorKeyPair ?? this._keyPair;
    if (!operatorKeyPair) {
      throw new Error(
        "SteleClient.createIdentity(): No key pair available. Either call client.generateKeyPair() first, or pass { operatorKeyPair } in the options.",
      );
    }

    const identity = await identityCreate({
      operatorKeyPair,
      operatorIdentifier: options.operatorIdentifier,
      model: options.model,
      capabilities: options.capabilities,
      deployment: options.deployment,
    });

    this._emit('identity:created', {
      type: 'identity:created',
      timestamp: timestamp(),
      identity,
    });

    return identity;
  }

  /**
   * Evolve an existing agent identity with updates.
   *
   * Creates a new lineage entry recording the change. If
   * `options.operatorKeyPair` is not provided, the client's key pair
   * is used. Emits an `identity:evolved` event on success.
   *
   * @param identity - The current agent identity to evolve.
   * @param options - Evolution options describing the change.
   * @returns The updated AgentIdentity with a new lineage entry.
   * @throws {Error} When no key pair is available.
   *
   * @example
   * ```typescript
   * const evolved = await client.evolveIdentity(identity, {
   *   changeType: 'model_update',
   *   description: 'Upgraded to v2',
   *   updates: { model: { provider: 'anthropic', modelId: 'claude-4' } },
   * });
   * ```
   */
  async evolveIdentity(
    identity: AgentIdentity,
    options: EvolveOptions,
  ): Promise<AgentIdentity> {
    const operatorKeyPair = options.operatorKeyPair ?? this._keyPair;
    if (!operatorKeyPair) {
      throw new Error(
        "SteleClient.evolveIdentity(): No key pair available. Either call client.generateKeyPair() first, or pass { operatorKeyPair } in the options.",
      );
    }

    const evolved = await identityEvolve(identity, {
      operatorKeyPair,
      changeType: options.changeType,
      description: options.description,
      updates: options.updates,
      reputationCarryForward: options.reputationCarryForward,
    });

    this._emit('identity:evolved', {
      type: 'identity:evolved',
      timestamp: timestamp(),
      identity: evolved,
      changeType: options.changeType,
    });

    return evolved;
  }

  // ── Chain ───────────────────────────────────────────────────────────────

  /**
   * Resolve the ancestor chain of a covenant document.
   *
   * Uses a MemoryChainResolver seeded with the provided documents.
   * If no additional documents are provided, only the document's
   * immediate chain reference is followed.
   * Emits a `chain:resolved` event.
   *
   * @param doc - The covenant document whose chain to resolve.
   * @param knownDocuments - Optional array of documents that may be ancestors.
   * @returns An array of ancestor documents, parent-first.
   *
   * @example
   * ```typescript
   * const ancestors = await client.resolveChain(childDoc, [parentDoc]);
   * ```
   */
  async resolveChain(
    doc: CovenantDocument,
    knownDocuments?: CovenantDocument[],
  ): Promise<CovenantDocument[]> {
    const resolver = new MemoryChainResolver();

    if (knownDocuments) {
      for (const d of knownDocuments) {
        resolver.add(d);
      }
    }
    resolver.add(doc);

    const ancestors = await coreResolveChain(doc, resolver);

    this._emit('chain:resolved', {
      type: 'chain:resolved',
      timestamp: timestamp(),
      documents: ancestors,
    });

    return ancestors;
  }

  /**
   * Validate a chain of covenant documents.
   *
   * Verifies each document individually and checks that each child
   * only narrows (restricts) its parent's constraints. Documents
   * should be ordered from root (index 0) to leaf (last index).
   * Emits a `chain:validated` event.
   *
   * @param docs - The chain of documents, ordered root-first.
   * @returns A ChainValidationResult with per-document and narrowing results.
   *
   * @example
   * ```typescript
   * const result = await client.validateChain([rootDoc, childDoc]);
   * console.log(result.valid); // true if all docs valid and narrowing holds
   * ```
   */
  async validateChain(docs: CovenantDocument[]): Promise<ChainValidationResult> {
    const results: VerificationResult[] = [];
    const narrowingViolations: NarrowingViolationEntry[] = [];

    // Verify each document individually
    for (const doc of docs) {
      const result = await coreVerifyCovenant(doc);
      results.push(result);
    }

    // Check narrowing between consecutive parent-child pairs
    for (let i = 1; i < docs.length; i++) {
      const parent = docs[i - 1]!;
      const child = docs[i]!;

      const narrowing = await validateChainNarrowing(child, parent);
      if (!narrowing.valid) {
        narrowingViolations.push({
          childIndex: i,
          parentIndex: i - 1,
          violations: narrowing.violations,
        });
      }
    }

    const allVerificationsValid = results.every((r) => r.valid);
    const noNarrowingViolations = narrowingViolations.length === 0;

    const chainResult: ChainValidationResult = {
      valid: allVerificationsValid && noNarrowingViolations,
      results,
      narrowingViolations,
    };

    this._emit('chain:validated', {
      type: 'chain:validated',
      timestamp: timestamp(),
      result: chainResult,
    });

    return chainResult;
  }

  // ── CCL utilities ─────────────────────────────────────────────────────

  /**
   * Parse CCL source text into a CCLDocument.
   *
   * @param source - CCL source text.
   * @returns A parsed CCLDocument.
   * @throws {CCLSyntaxError} When the source has syntax errors.
   *
   * @example
   * ```typescript
   * const cclDoc = client.parseCCL("permit read on '/data/**'");
   * ```
   */
  parseCCL(source: string): CCLDocument {
    return cclParse(source);
  }

  /**
   * Merge two CCL documents using deny-wins semantics.
   *
   * @param a - The first (parent) CCL document.
   * @param b - The second (child) CCL document.
   * @returns A new merged CCLDocument.
   */
  mergeCCL(a: CCLDocument, b: CCLDocument): CCLDocument {
    return cclMerge(a, b);
  }

  /**
   * Serialize a CCLDocument back to human-readable CCL source text.
   *
   * @param doc - The CCL document to serialize.
   * @returns Multi-line CCL source string.
   */
  serializeCCL(doc: CCLDocument): string {
    return cclSerialize(doc);
  }

  // ── Event system ──────────────────────────────────────────────────────

  /**
   * Register an event handler for a specific event type.
   *
   * @param event - The event type to listen for.
   * @param handler - The callback function.
   * @returns A disposal function that removes the handler when called.
   *
   * @example
   * ```typescript
   * const off = client.on('covenant:created', (e) => {
   *   console.log('Created:', e.document.id);
   * });
   * // later: off() to unsubscribe
   * ```
   */
  on<T extends SteleEventType>(
    event: T,
    handler: SteleEventHandler<T>,
  ): () => void {
    if (!this._listeners.has(event)) {
      this._listeners.set(event, new Set());
    }
    const handlers = this._listeners.get(event)!;
    handlers.add(handler as SteleEventHandler<SteleEventType>);

    return () => {
      handlers.delete(handler as SteleEventHandler<SteleEventType>);
    };
  }

  /**
   * Remove a previously registered event handler.
   *
   * @param event - The event type.
   * @param handler - The handler function to remove.
   */
  off<T extends SteleEventType>(
    event: T,
    handler: SteleEventHandler<T>,
  ): void {
    const handlers = this._listeners.get(event);
    if (handlers) {
      handlers.delete(handler as SteleEventHandler<SteleEventType>);
    }
  }

  /**
   * Remove all event handlers for a specific event type, or all events if
   * no type is specified.
   *
   * @param event - Optional event type. If omitted, removes all handlers.
   */
  removeAllListeners(event?: SteleEventType): void {
    if (event) {
      this._listeners.delete(event);
    } else {
      this._listeners.clear();
    }
  }

  /** Emit an event to all registered handlers. */
  private _emit<T extends SteleEventType>(
    event: T,
    payload: SteleEventMap[T],
  ): void {
    const handlers = this._listeners.get(event);
    if (handlers) {
      for (const handler of handlers) {
        handler(payload);
      }
    }
  }
}

// ─── QuickCovenant convenience builders ─────────────────────────────────────

/**
 * Convenience builders for creating common covenant patterns quickly.
 *
 * These produce CovenantDocument instances with minimal configuration.
 * All methods require an issuer key pair, issuer party, and beneficiary party.
 */
export class QuickCovenant {
  /**
   * Create a simple permit covenant that allows a specific action on a resource.
   *
   * @param action - The action to permit (e.g., `"read"`, `"file.read"`).
   * @param resource - The resource to permit on (e.g., `"/data"`, `"/files/**"`).
   * @param issuer - The issuing party.
   * @param beneficiary - The beneficiary party.
   * @param privateKey - Issuer's private key for signing.
   * @returns A signed CovenantDocument with a single permit rule.
   *
   * @example
   * ```typescript
   * const doc = await QuickCovenant.permit('read', '/data/**', issuer, beneficiary, kp.privateKey);
   * ```
   */
  static async permit(
    action: string,
    resource: string,
    issuer: Issuer,
    beneficiary: Beneficiary,
    privateKey: Uint8Array,
  ): Promise<CovenantDocument> {
    const constraints = `permit ${action} on '${resource}'`;
    return buildCovenant({
      issuer,
      beneficiary,
      constraints,
      privateKey,
    });
  }

  /**
   * Create a simple deny covenant that denies a specific action on a resource.
   *
   * @param action - The action to deny.
   * @param resource - The resource to deny on.
   * @param issuer - The issuing party.
   * @param beneficiary - The beneficiary party.
   * @param privateKey - Issuer's private key for signing.
   * @returns A signed CovenantDocument with a single deny rule.
   *
   * @example
   * ```typescript
   * const doc = await QuickCovenant.deny('delete', '/system/**', issuer, beneficiary, kp.privateKey);
   * ```
   */
  static async deny(
    action: string,
    resource: string,
    issuer: Issuer,
    beneficiary: Beneficiary,
    privateKey: Uint8Array,
  ): Promise<CovenantDocument> {
    const constraints = `deny ${action} on '${resource}'`;
    return buildCovenant({
      issuer,
      beneficiary,
      constraints,
      privateKey,
    });
  }

  /**
   * Create a standard covenant with common constraints:
   * - Permits read on all resources
   * - Denies write on system resources
   * - Limits API calls to 1000 per 1 hour
   *
   * @param issuer - The issuing party.
   * @param beneficiary - The beneficiary party.
   * @param privateKey - Issuer's private key for signing.
   * @returns A signed CovenantDocument with standard constraints.
   *
   * @example
   * ```typescript
   * const doc = await QuickCovenant.standard(issuer, beneficiary, kp.privateKey);
   * ```
   */
  static async standard(
    issuer: Issuer,
    beneficiary: Beneficiary,
    privateKey: Uint8Array,
  ): Promise<CovenantDocument> {
    const constraints = [
      "permit read on '**'",
      "deny write on '/system/**'",
      'limit api.call 1000 per 1 hours',
    ].join('\n');

    return buildCovenant({
      issuer,
      beneficiary,
      constraints,
      privateKey,
    });
  }
}

// Re-export adapters
export * from './adapters/index.js';

// ─── Store ────────────────────────────────────────────────────────────────────
export { MemoryStore, FileStore, SqliteStore, QueryBuilder, createQuery, StoreIndex, IndexedStore, createTransaction } from '@stele/store';
export type {
  CovenantStore,
  StoreFilter,
  StoreEvent,
  StoreEventType,
  StoreEventCallback,
  SQLiteDriver,
  PaginationOptions,
  PaginatedResult,
  SortField,
  SortOrder,
  IndexField,
  Transaction,
} from '@stele/store';

// ─── Breach Detection ─────────────────────────────────────────────────────────
export {
  createBreachAttestation,
  verifyBreachAttestation,
  TrustGraph,
  ExponentialDegradation,
  BreachStateMachine,
  RecoveryModel,
  RepeatOffenderDetector,
  createPlaybook,
  matchIncident,
  createIncidentReport,
  escalateIncident,
  resolveIncident,
} from '@stele/breach';
export type {
  BreachAttestation,
  TrustStatus,
  TrustNode,
  BreachEvent,
} from '@stele/breach';

// ─── Reputation ───────────────────────────────────────────────────────────────
export {
  computeReputationScore,
  createReceipt,
  verifyReceipt,
  countersignReceipt,
  verifyReceiptChain,
  computeReceiptsMerkleRoot,
  DEFAULT_SCORING_CONFIG,
  createStake,
  releaseStake,
  burnStake,
  createDelegation,
  burnDelegation,
  coBurnDelegation,
  createEndorsement,
  verifyEndorsement,
  ReceiptDAG,
  ReputationDecayModel,
  GraduatedBurner,
  ReputationAggregator,
  createResourcePool,
  allocateTrust,
  releaseTrust,
  slashStake,
  collateralizationRatio,
  computeProfile,
  compareProfiles,
  STAKE_TIERS,
  assignTier,
  createStakedAgent,
  recordQuery,
  computeGovernanceVote,
} from '@stele/reputation';
export type {
  ReputationScore,
  ExecutionReceipt,
  ReputationStake,
  ReputationDelegation,
  Endorsement,
  ScoringConfig,
  ResourcePool,
  SlashingEvent,
  TrustDimension,
  MultidimensionalProfile,
  StakeTier,
  StakeTierConfig,
  StakedAgent,
} from '@stele/reputation';

// ─── Proof ────────────────────────────────────────────────────────────────────
export {
  generateComplianceProof,
  verifyComplianceProof,
  computeAuditCommitment,
  computeConstraintCommitment,
  poseidonHash,
  hashToField,
  fieldToHex,
  FIELD_PRIME,
} from '@stele/proof';
export type {
  ComplianceProof,
  ProofVerificationResult,
  ProofGenerationOptions,
  AuditEntryData,
} from '@stele/proof';

// ─── Attestation ──────────────────────────────────────────────────────────────
export {
  createAttestation,
  verifyAttestation,
  signAttestation,
  isSigned,
  reconcile,
  getDiscrepancies,
  attestationChainVerify,
  computeAttestationCoverage,
  createEntanglement,
  buildEntanglementNetwork,
  verifyEntangled,
  assessConditionalRisk,
} from '@stele/attestation';
export type {
  ExternalAttestation,
  AttestationReconciliation,
  Discrepancy,
  ReceiptSummary,
  AttestationChainLink,
  ChainVerificationResult,
  AgentAction,
  AttestationCoverageResult,
} from '@stele/attestation';

// ─── Verifier ─────────────────────────────────────────────────────────────────
export { Verifier, verifyBatch } from '@stele/verifier';
export type {
  VerifierOptions,
  VerificationReport,
  ChainVerificationReport,
  ChainDocumentResult,
  ChainIntegrityCheck,
  NarrowingCheckResult,
  ActionVerificationReport,
  BatchVerificationReport,
  BatchSummary,
  VerificationRecord,
  VerificationKind,
} from '@stele/verifier';

// ─── Discovery ─────────────────────────────────────────────────────────────────
export {
  DiscoveryClient,
  DiscoveryServer,
  buildDiscoveryDocument,
  validateDiscoveryDocument,
  buildKeyEntry,
  buildKeySet,
  WELL_KNOWN_PATH,
  CONFIGURATION_PATH,
  STELE_MEDIA_TYPE,
  MAX_DOCUMENT_AGE_MS,
  createFederationConfig,
  addResolver,
  removeResolver,
  resolveAgent,
  selectOptimalResolvers,
  createMarketplace,
  listAgent,
  searchMarketplace,
  createTransaction as createMarketplaceTransaction,
  completeTransaction,
  disputeTransaction,
} from '@stele/discovery';
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
  BuildDiscoveryDocumentOptions,
  DiscoveryValidationResult,
  DiscoveryClientOptions,
  DiscoveryServerOptions,
  RouteHandler,
  FederatedResolver,
  FederationConfig,
  ResolutionResult,
  MarketplaceListing,
  MarketplaceConfig,
  MarketplaceQuery,
  MarketplaceTransaction,
} from '@stele/discovery';

// ─── Schema ────────────────────────────────────────────────────────────────────
export {
  COVENANT_SCHEMA,
  DISCOVERY_DOCUMENT_SCHEMA,
  AGENT_KEY_SCHEMA,
  CCL_EVALUATION_CONTEXT_SCHEMA,
  validateCovenantSchema,
  validateDiscoverySchema,
  validateAgentKeySchema,
  getAllSchemas,
} from '@stele/schema';
export type {
  SchemaValidationError,
  SchemaValidationResult,
} from '@stele/schema';

// ─── Temporal ─────────────────────────────────────────────────────────────────
export {
  defineEvolution,
  evaluateTriggers,
  canEvolve,
  evolve,
  evolutionHistory,
  computeDecaySchedule,
  expirationForecast,
  DecayModel,
  ContinuousTrigger,
  ViolationForecaster,
  TemporalConstraintAlgebra,
  DEFAULT_GOVERNANCE_BOOTSTRAP,
  initializeGovernance,
  evaluatePhaseTransition,
  transitionPhase,
  computeVotingPower,
} from '@stele/temporal';
export type {
  TriggerType,
  TriggerAction,
  EvolutionPolicy as TemporalEvolutionPolicy,
  EvolutionTrigger,
  TransitionFunction,
  EvolutionEvent,
  AgentState,
  CovenantState,
  DecayPoint,
  ViolationRecord,
  ExpirationForecastResult,
  DecayModelType,
  DecayModelConfig,
  ContinuousTriggerConfig,
  ContinuousTriggerResult,
  ForecastConfig,
  ForecastPoint,
  ForecastResult,
  TemporalConstraint,
  TemporalAlgebraResult,
  GovernancePhase,
  GovernanceState,
  GovernanceBootstrapConfig,
} from '@stele/temporal';

// ─── Trust Gate ───────────────────────────────────────────────────────────────
export { createTrustGate, evaluateAccess, calculateRevenueLift } from './trust-gate.js';
export type { TrustGateConfig, AccessLevel, GateDecision } from './trust-gate.js';

// ─── Certification ────────────────────────────────────────────────────────────
export {
  CERTIFICATION_REQUIREMENTS,
  createAuthority,
  issueCertificate,
  revokeCertificate,
  verifyCertificate,
} from './certification.js';
export type { Certificate, CertificationAuthority, CertificationRequirements } from './certification.js';

// ─── Dashboard ────────────────────────────────────────────────────────────────
export {
  STANDARD_METRICS,
  createDashboard,
  addMetric,
  createStandardDashboard,
  aggregateMetric,
  pruneOldData,
} from './dashboard.js';
export type { DashboardConfig, MetricPoint, MetricSeries, DashboardPanel, Dashboard } from './dashboard.js';

// ─── Analytics ────────────────────────────────────────────────────────────────
export { aggregateData, anonymizeDataset, computeTrends } from './analytics.js';
export type { TrustDataPoint, AggregatedInsight, AnonymizedDataset } from './analytics.js';

// ─── Gateway ──────────────────────────────────────────────────────────────────
export {
  createGateway,
  isResourceAllowed,
  processRequest,
  aggregateMetrics as aggregateGatewayMetrics,
} from './gateway.js';
export type { GatewayConfig, GatewayRequest, GatewayResponse, GatewayMetrics } from './gateway.js';

// ─── Governance ───────────────────────────────────────────────────────────────
export {
  createGovernancePolicy,
  registerAgent as registerGovernanceAgent,
  updateAgentStatus,
  quarantineAgent,
  unquarantineAgent,
  buildDashboard as buildGovernanceDashboard,
} from './governance.js';
export type { GovernancePolicy, AgentStatus, GovernanceDashboard } from './governance.js';

// ─── i18n ─────────────────────────────────────────────────────────────────────
export {
  TRANSLATION_KEYS,
  CATALOGS,
  t,
  setDefaultLocale,
  getDefaultLocale,
  addTranslation,
  getSupportedLocales,
} from './i18n.js';

// ─── Payments ─────────────────────────────────────────────────────────────────
export {
  createLedger,
  createAccount,
  recordQueryIncome,
  processPayment,
  getAccountSummary,
} from './payments.js';
export type { PaymentAccount, PaymentTransaction, PaymentLedger } from './payments.js';

// ─── Rail ─────────────────────────────────────────────────────────────────────
export {
  createRail,
  initiateRailTransaction,
  executeRailTransaction,
  rollbackRailTransaction,
  computeRailVolume,
} from './rail.js';
export type { RailTransaction, RailConfig } from './rail.js';

// ─── Fees ─────────────────────────────────────────────────────────────────────
export {
  createFeeSchedule,
  calculateFee,
  aggregateFees,
  projectRevenue,
} from './fees.js';
export type { FeeSchedule, FeeCalculation, FeeAggregate } from './fees.js';

// ─── Canary ───────────────────────────────────────────────────────────────────
export {
  generateCanary,
  evaluateCanary,
  detectionProbability,
  isExpired as isCanaryExpired,
  canarySchedule,
  canaryCorrelation,
} from '@stele/canary';
export type {
  ChallengePayload,
  Canary,
  CanaryResult,
  CanaryScheduleEntry,
  CanaryScheduleResult,
  CanaryCorrelationResult,
} from '@stele/canary';

// ─── Game Theory ──────────────────────────────────────────────────────────────
export {
  validateParameters as validateGameTheoryParameters,
  proveHonesty,
  minimumStake,
  minimumDetection,
  expectedCostOfBreach,
  honestyMargin,
  repeatedGameEquilibrium,
  coalitionStability,
  mechanismDesign,
  modelPrincipalAgent,
  analyzeTier,
  defineConjecture,
  getStandardConjectures,
  analyzeImpossibilityBounds,
} from '@stele/gametheory';
export type {
  HonestyParameters,
  HonestyProof,
  RepeatedGameParams,
  RepeatedGameResult,
  CoalitionValue,
  CoalitionStabilityResult,
  MechanismDesignParams,
  MechanismDesignResult,
  OperatorPrincipal,
  PrincipalAgentModel,
  AdoptionTier,
  TierAnalysis,
  ConjectureStatus,
  Conjecture,
  ImpossibilityBound,
} from '@stele/gametheory';

// ─── Composition ──────────────────────────────────────────────────────────────
export {
  compose,
  proveSystemProperty,
  validateComposition,
  intersectConstraints,
  findConflicts,
  decomposeCovenants,
  compositionComplexity,
  TRUST_IDENTITY,
  TRUST_ZERO,
  trustCompose,
  trustIntersect,
  trustNegate,
  trustTensorProduct,
  trustInverse,
  proveAlgebraicProperties,
  defineSafetyEnvelope,
  proposeImprovement,
  applyImprovement,
  verifyEnvelopeIntegrity,
} from '@stele/composition';
export type {
  CompositionProof,
  ComposedConstraint,
  SystemProperty,
  CovenantSummary,
  DecomposedCovenant,
  CompositionComplexityResult,
  TrustValue,
  AlgebraicProof,
  SafetyEnvelope,
  ImprovementProposal,
  ImprovementResult,
} from '@stele/composition';

// ─── Antifragile ──────────────────────────────────────────────────────────────
export {
  generateAntibody,
  proposeToGovernance,
  networkHealth,
  adoptAntibody,
  forceAdopt,
  rejectAntibody,
  voteForAntibody,
  antibodyExists,
  stressTest,
  antifragilityIndex,
  StressResponseCurve,
  PhaseTransitionDetector,
  FitnessEvolution,
  calibratedAntifragilityIndex,
} from '@stele/antifragile';
export type {
  BreachAntibody,
  NetworkHealth,
  GovernanceProposal as AntifragileGovernanceProposal,
  BreachSummary,
  StressTestResult,
  AntifragilityIndexResult,
  StressResponseConfig,
  MetricObservation,
  PhaseTransitionResult,
  ScoredAntibody,
  FitnessEvolutionConfig,
  CalibratedAntifragilityResult,
} from '@stele/antifragile';

// ─── Consensus ────────────────────────────────────────────────────────────────
export {
  validateConfig as validateConsensusConfig,
  validateProtocolData,
  validatePolicy as validateConsensusPolicy,
  tierToMinScore,
  compareTiers,
  computeAccountability,
  evaluateCounterparty,
  networkAccountabilityRate,
  byzantineFaultTolerance,
  quorumSize,
  consensusLatency,
  StreamlinedBFT,
  DynamicQuorum,
  PipelineSimulator,
  QuorumIntersectionVerifier,
} from '@stele/consensus';
export type {
  AccountabilityTier,
  AccountabilityScore,
  InteractionPolicy,
  AccessDecision,
  ProtocolData,
  AccountabilityConfig,
  BFTResult,
  ConsensusProtocol,
  QuorumResult,
  ConsensusLatencyParams,
  ConsensusLatencyResult,
  BFTPhase,
  BFTVote,
  QuorumCertificate,
  BFTBlock,
  BFTViewState,
  Epoch,
  ReconfigRequest,
  NetworkCondition,
  PipelineSimulationResult,
  QuorumIntersectionResult,
} from '@stele/consensus';

// ─── Robustness ───────────────────────────────────────────────────────────────
export {
  assessSeverity,
  proveRobustness,
  fuzz,
  generateAdversarialInputs,
  formalVerification,
  robustnessScore,
} from '@stele/robustness';
export type {
  RobustnessProof,
  InputBound,
  RobustnessReport,
  Vulnerability,
  CovenantSpec,
  ConstraintSpec,
  RobustnessOptions,
  FormalVerificationResult,
  Contradiction,
  RobustnessScoreResult,
  RobustnessFactor,
} from '@stele/robustness';

// ─── Recursive ────────────────────────────────────────────────────────────────
export {
  createMetaCovenant,
  verifyRecursively,
  proveTermination,
  trustBase,
  addLayer,
  computeTrustTransitivity,
  findMinimalVerificationSet,
} from '@stele/recursive';
export type {
  MetaTargetType,
  MetaCovenant,
  RecursiveVerification,
  TerminationProof,
  TrustBase as RecursiveTrustBase,
  VerificationEntity,
  TrustEdge,
  TransitiveTrustResult,
  VerifierNode,
  MinimalVerificationSetResult,
} from '@stele/recursive';

// ─── Alignment ────────────────────────────────────────────────────────────────
export {
  STANDARD_ALIGNMENT_PROPERTIES,
  defineAlignment,
  assessAlignment,
  alignmentGap,
  alignmentDrift,
  alignmentDecomposition,
  AdaptiveAlignmentTracker,
  PropertyAnomalyDetector,
  DriftForecaster,
  AlignmentSurface,
  AlignmentFeedbackLoop,
} from '@stele/alignment';
export type {
  AlignmentProperty,
  AlignmentCovenant,
  AlignmentReport,
  ExecutionRecord as AlignmentExecutionRecord,
  AlignmentDriftResult,
  AlignmentDecompositionResult,
  PropertyContribution,
  WeightObservation,
  AdaptiveWeightSnapshot,
  PropertyStatistics,
  AnomalyResult,
  DriftForecast,
  DimensionGradient,
  AlignmentSurfaceResult,
  FeedbackLoopConfig,
  AlignmentOutcome,
  FeedbackLoopState,
} from '@stele/alignment';

// ─── Norms ────────────────────────────────────────────────────────────────────
export {
  analyzeNorms,
  discoverNorms,
  proposeStandard,
  generateTemplate,
  normConflictDetection,
  normPrecedence,
} from '@stele/norms';
export type {
  DiscoveredNorm,
  NormAnalysis,
  NormCluster,
  GovernanceProposal as NormGovernanceProposal,
  CovenantData,
  CovenantTemplate,
  NormDefinition,
  NormConflict,
  NormPrecedenceResult,
} from '@stele/norms';

// ─── Substrate ────────────────────────────────────────────────────────────────
export {
  SUBSTRATE_DEFAULTS,
  createAdapter,
  physicalCovenant,
  translateCovenant,
  checkPhysicalConstraint,
  checkSafetyBound,
  substrateCompatibility,
  constraintTranslation,
  substrateCapabilityMatrix,
} from '@stele/substrate';
export type {
  SubstrateType,
  SubstrateAdapter,
  PhysicalConstraint,
  SafetyBound,
  UniversalCovenant,
  AdapterConfig,
  SafetyBoundResult,
  CompatibilityResult,
  EnforcementRule,
  ConstraintTranslationResult,
  CapabilityEntry,
  CapabilityMatrixRow,
  CapabilityMatrix,
} from '@stele/substrate';

// ─── Derivatives ──────────────────────────────────────────────────────────────
export {
  assessRisk,
  priceInsurance,
  createPolicy,
  createFuture,
  settleFuture,
  claimPolicy,
  blackScholesPrice,
  valueAtRisk,
  hedgeRatio,
} from '@stele/derivatives';
export type {
  TrustFuture,
  AgentInsurancePolicy,
  RiskAssessment,
  RiskFactor,
  Settlement,
  ReputationData,
  PricingConfig,
  BlackScholesParams,
  BlackScholesResult,
  VaRParams,
  VaRResult,
  HedgeRatioParams,
  HedgeRatioResult,
} from '@stele/derivatives';

// ─── Legal ────────────────────────────────────────────────────────────────────
export {
  JURISDICTIONS,
  registerJurisdiction,
  COMPLIANCE_STANDARDS,
  exportLegalPackage,
  mapToJurisdiction,
  generateComplianceReport,
  crossJurisdictionCompliance,
  auditTrailExport,
  regulatoryGapAnalysis,
  ComplianceSurface,
  ComplianceTrajectory,
  RemediationPlanner,
  JurisdictionConflictResolver,
  RegulatoryImpactAnalyzer,
  createComplianceMonitor,
  takeSnapshot,
  analyzeTrajectory,
  generateRegulatoryReport,
} from '@stele/legal';
export type {
  LegalIdentityPackage,
  ComplianceRecord,
  JurisdictionalMapping,
  CovenantRecord,
  ReputationSnapshot,
  AttestationRecord,
  InsuranceRecord,
  ComplianceStandard,
  JurisdictionComplianceEntry,
  CrossJurisdictionResult,
  AuditTrailEntry,
  AuditTrailExport,
  RegulatoryGap,
  RegulatoryGapAnalysisResult,
  JurisdictionInfo,
  ComplianceStandardInfo,
  ComplianceWeights,
  RequirementDependency,
  RequirementScore,
  ComplianceSurfaceResult,
  ComplianceObservation,
  ComplianceTrajectoryResult,
  RemediationAction,
  RemediationPlanResult,
  JurisdictionalRequirement,
  JurisdictionConflict,
  ResolutionStrategy,
  ConflictResolution,
  JurisdictionConflictResult,
  RegulatoryChange,
  CovenantImpact,
  RegulatoryImpactResult,
  ComplianceMonitorConfig,
  ComplianceSnapshot,
  ComplianceAlert,
  ComplianceAutopilotTrajectory,
} from '@stele/legal';

// ─── Enforcement ──────────────────────────────────────────────────────────────
export {
  MonitorDeniedError,
  CapabilityError,
  verifyMerkleProof,
  Monitor,
  CapabilityGate,
  createProvenanceRecord,
  buildProvenanceChain,
  verifyProvenance,
  queryProvenance,
  createDefenseConfig,
  analyzeDefense,
  addDefenseLayer,
  disableLayer,
  AuditChain,
} from '@stele/enforcement';
export type {
  ExecutionOutcome,
  AuditEntry,
  AuditLog,
  CapabilityManifest,
  ActionHandler,
  ExecutionLogEntry,
  MonitorConfig,
  RateLimitState,
  MerkleProof,
  ProvenanceRecord,
  ProvenanceChain,
  DefenseLayer,
  DefenseInDepthConfig,
  DefenseAnalysis,
  ChainedAuditEntry,
} from '@stele/enforcement';

// ─── Negotiation ──────────────────────────────────────────────────────────────
export {
  initiate as initiateNegotiation,
  propose,
  counter,
  agree,
  evaluate as evaluateNegotiation,
  isExpired as isNegotiationExpired,
  fail as failNegotiation,
  roundCount,
  computeNashBargainingSolution,
  paretoFrontier,
  computeNPartyNash,
  ConcessionProtocol,
  IncrementalParetoFrontier,
  zeuthenStrategy,
  runZeuthenNegotiation,
} from '@stele/negotiation';
export type {
  NegotiationSession,
  Proposal,
  NegotiationPolicy,
  UtilityFunction,
  Outcome,
  NashBargainingSolution,
  ParetoOutcome,
  NPartyNashConfig,
  NPartyNashResult,
  ConcessionState,
  ConcessionEvent,
  ConcessionConfig,
  ZeuthenResult,
} from '@stele/negotiation';
