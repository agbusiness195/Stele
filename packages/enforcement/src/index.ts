import {
  sha256String,
  sha256Object,
  canonicalizeJson,
  signString,
  verify as cryptoVerify,
  toHex,
  fromHex,
  timestamp,
  generateId,
} from '@stele/crypto';

import type { HashHex, KeyPair } from '@stele/crypto';

import { DocumentedSteleError as SteleError, DocumentedErrorCode as SteleErrorCode } from '@stele/types';

import {
  parse,
  evaluate,
  matchAction,
  checkRateLimit as cclCheckRateLimit,
  serialize as cclSerialize,
  evaluateCondition,
} from '@stele/ccl';

import type {
  CCLDocument,
  Statement,
  Severity,
  EvaluationResult,
  EvaluationContext,
  PermitDenyStatement,
  LimitStatement,
} from '@stele/ccl';

export type {
  ExecutionOutcome,
  AuditEntry,
  AuditLog,
  CapabilityManifest,
  ActionHandler,
  ExecutionLogEntry,
  MonitorConfig,
  RateLimitState,
} from './types.js';

import type {
  ExecutionOutcome,
  AuditEntry,
  AuditLog,
  CapabilityManifest,
  ActionHandler,
  ExecutionLogEntry,
  MonitorConfig,
  RateLimitState,
} from './types.js';

// ─── Constants ────────────────────────────────────────────────────────────────

/** The zero hash used as the previousHash for the first audit entry. */
const GENESIS_HASH: HashHex = '0000000000000000000000000000000000000000000000000000000000000000';

// ─── Error classes ────────────────────────────────────────────────────────────

/**
 * Thrown when the Monitor denies an action in 'enforce' mode.
 */
export class MonitorDeniedError extends SteleError {
  readonly action: string;
  readonly resource: string;
  readonly matchedRule: Statement | undefined;
  readonly severity: Severity | undefined;

  constructor(
    action: string,
    resource: string,
    matchedRule: Statement | undefined,
    severity: Severity | undefined,
  ) {
    const ruleDesc = matchedRule
      ? `matched ${matchedRule.type} rule`
      : 'no matching permit rule';
    super(
      SteleErrorCode.ACTION_DENIED,
      `Action '${action}' on resource '${resource}' denied: ${ruleDesc}`,
      {
        hint: `Check the CCL constraints for action '${action}' on resource '${resource}'.`,
        context: { action, resource },
      },
    );
    this.name = 'MonitorDeniedError';
    this.action = action;
    this.resource = resource;
    this.matchedRule = matchedRule;
    this.severity = severity;
  }
}

/**
 * Thrown when a CapabilityGate operation fails due to missing or invalid capabilities.
 */
export class CapabilityError extends SteleError {
  readonly action: string;

  constructor(action: string, message?: string) {
    super(
      SteleErrorCode.ACTION_DENIED,
      message ?? `No capability registered for action '${action}'`,
      {
        hint: `Ensure the action '${action}' is permitted by the CCL constraints before registering a handler.`,
        context: { action },
      },
    );
    this.name = 'CapabilityError';
    this.action = action;
  }
}

// ─── MerkleProof ──────────────────────────────────────────────────────────────

/**
 * A Merkle inclusion proof for a single audit entry.
 */
export interface MerkleProof {
  entryHash: HashHex;
  proof: HashHex[];
  index: number;
  merkleRoot: HashHex;
}

/**
 * Verify a Merkle inclusion proof.
 *
 * Walks from the leaf hash up through the sibling hashes in the proof,
 * combining pairs with SHA-256 until reaching the root. Returns true
 * if the computed root matches the expected root in the proof.
 *
 * @param proof - The Merkle inclusion proof to verify.
 * @returns True if the proof is valid (computed root matches expected root).
 *
 * @example
 * ```ts
 * const proof = monitor.generateMerkleProof(0);
 * const valid = verifyMerkleProof(proof);
 * console.log(valid); // true
 * ```
 */
export function verifyMerkleProof(proof: MerkleProof): boolean {
  let currentHash = proof.entryHash;
  let idx = proof.index;

  for (const siblingHash of proof.proof) {
    if (idx % 2 === 0) {
      // Current node is left child
      currentHash = sha256String(currentHash + siblingHash);
    } else {
      // Current node is right child
      currentHash = sha256String(siblingHash + currentHash);
    }
    idx = Math.floor(idx / 2);
  }

  return currentHash === proof.merkleRoot;
}

// ─── Monitor ──────────────────────────────────────────────────────────────────

/**
 * Runtime constraint monitor that evaluates actions against CCL constraints,
 * maintains a tamper-evident audit log with hash chaining and Merkle trees,
 * and enforces rate limits.
 */
export class Monitor {
  private readonly covenantId: HashHex;
  private readonly doc: CCLDocument;
  private readonly config: MonitorConfig;
  private readonly entries: AuditEntry[] = [];
  private readonly rateLimits: Map<string, RateLimitState> = new Map();

  /**
   * Create a new Monitor.
   *
   * @param covenantId - The ID of the covenant being monitored.
   * @param constraints - CCL constraint source text.
   * @param config - Optional monitor configuration overrides.
   */
  constructor(
    covenantId: HashHex,
    constraints: string,
    config?: Partial<MonitorConfig>,
  ) {
    if (!covenantId || typeof covenantId !== 'string' || covenantId.trim().length === 0) {
      throw new SteleError(
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
        'Monitor requires a non-empty covenantId',
        { hint: 'Pass the covenant document ID (a hex-encoded hash) as the first argument.' }
      );
    }
    if (!constraints || typeof constraints !== 'string' || constraints.trim().length === 0) {
      throw new SteleError(
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
        'Monitor requires a non-empty constraints string',
        { hint: 'Pass valid CCL constraint text as the second argument.' }
      );
    }
    this.covenantId = covenantId;
    this.doc = parse(constraints);
    this.config = {
      mode: config?.mode ?? 'enforce',
      failureMode: config?.failureMode ?? 'fail_closed',
      onViolation: config?.onViolation,
      onAction: config?.onAction,
    };
  }

  /**
   * Evaluate an action against the constraints.
   *
   * Creates an audit entry, checks rate limits, invokes callbacks, and
   * in 'enforce' mode throws MonitorDeniedError if the action is denied.
   *
   * @param action - The action to evaluate (e.g. "file.read").
   * @param resource - The resource being acted upon (e.g. "/data/users").
   * @param context - Optional evaluation context for condition matching.
   * @returns The CCL evaluation result.
   * @throws {MonitorDeniedError} If the action is denied and the monitor is in 'enforce' mode.
   *
   * @example
   * ```ts
   * const result = await monitor.evaluate('file.read', '/data/users');
   * console.log(result.permitted); // true or false
   * ```
   */
  async evaluate(
    action: string,
    resource: string,
    context?: Record<string, unknown>,
  ): Promise<EvaluationResult> {
    if (!action || typeof action !== 'string' || action.trim().length === 0) {
      throw new SteleError(
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
        'Monitor.evaluate() requires a non-empty action string',
        { hint: 'Pass an action name like "file.read" or "data.write".' }
      );
    }
    if (typeof resource !== 'string') {
      throw new SteleError(
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
        'Monitor.evaluate() requires a resource string',
        { hint: 'Pass a resource path like "/data/users" or "**".' }
      );
    }
    const ctx = context ?? {};
    const now = timestamp();

    // Evaluate against CCL constraints
    let result = evaluate(this.doc, action, resource, ctx);

    // Check rate limits if the action would otherwise be permitted
    if (result.permitted) {
      const rateResult = this.checkRateLimitInternal(action);
      if (rateResult.exceeded) {
        result = {
          permitted: false,
          matchedRule: result.matchedRule,
          allMatches: result.allMatches,
          reason: `Rate limit exceeded for action '${action}'`,
          severity: 'high',
        };
      }
    }

    // Determine outcome
    let outcome: ExecutionOutcome;
    if (result.permitted) {
      outcome = 'EXECUTED';
      // Increment rate limit counter on permitted actions
      this.incrementRateLimit(action);
    } else {
      outcome = 'DENIED';
    }

    // In log_only mode, override outcome to EXECUTED even if denied
    if (!result.permitted && this.config.mode === 'log_only') {
      outcome = 'EXECUTED';
    }

    // Build audit entry
    const entry = this.createAuditEntry(action, resource, ctx, result, outcome, undefined, now);

    // Fire callbacks
    if (!result.permitted && this.config.onViolation) {
      this.config.onViolation(entry);
    }
    if (this.config.onAction) {
      this.config.onAction(entry);
    }

    // In enforce mode, throw on denial
    if (!result.permitted && this.config.mode === 'enforce') {
      throw new MonitorDeniedError(
        action,
        resource,
        result.matchedRule,
        result.severity,
      );
    }

    return result;
  }

  /**
   * Evaluate and execute an action handler if permitted.
   *
   * @param action - The action to evaluate.
   * @param resource - The resource being acted upon.
   * @param handler - The handler function to execute if permitted.
   * @param context - Optional evaluation context.
   * @returns The result of the handler.
   * @throws {MonitorDeniedError} If the action is denied and the monitor is in 'enforce' mode.
   *
   * @example
   * ```ts
   * const data = await monitor.execute('file.read', '/data/users', async (res) => {
   *   return readFile(res);
   * });
   * ```
   */
  async execute<T>(
    action: string,
    resource: string,
    handler: ActionHandler<T>,
    context?: Record<string, unknown>,
  ): Promise<T> {
    if (!action || typeof action !== 'string' || action.trim().length === 0) {
      throw new SteleError(
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
        'Monitor.execute() requires a non-empty action string',
        { hint: 'Pass an action name like "file.read" or "data.write".' }
      );
    }
    if (typeof resource !== 'string') {
      throw new SteleError(
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
        'Monitor.execute() requires a resource string',
        { hint: 'Pass a resource path like "/data/users" or "**".' }
      );
    }
    if (typeof handler !== 'function') {
      throw new SteleError(
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
        'Monitor.execute() requires a handler function',
        { hint: 'Pass an async function (resource, context) => T as the handler.' }
      );
    }
    const ctx = context ?? {};
    const now = timestamp();

    // Evaluate constraints
    let result = evaluate(this.doc, action, resource, ctx);

    // Check rate limits
    if (result.permitted) {
      const rateResult = this.checkRateLimitInternal(action);
      if (rateResult.exceeded) {
        result = {
          permitted: false,
          matchedRule: result.matchedRule,
          allMatches: result.allMatches,
          reason: `Rate limit exceeded for action '${action}'`,
          severity: 'high',
        };
      }
    }

    if (!result.permitted && this.config.mode === 'enforce') {
      // Log the denial
      const entry = this.createAuditEntry(action, resource, ctx, result, 'DENIED', undefined, now);
      if (this.config.onViolation) {
        this.config.onViolation(entry);
      }
      if (this.config.onAction) {
        this.config.onAction(entry);
      }
      throw new MonitorDeniedError(
        action,
        resource,
        result.matchedRule,
        result.severity,
      );
    }

    // Increment rate limit counter for permitted actions
    if (result.permitted) {
      this.incrementRateLimit(action);
    }

    // Execute the handler
    try {
      const handlerResult = await handler(resource, ctx);
      const entry = this.createAuditEntry(action, resource, ctx, result, 'EXECUTED', undefined, now);
      if (!result.permitted && this.config.onViolation) {
        this.config.onViolation(entry);
      }
      if (this.config.onAction) {
        this.config.onAction(entry);
      }
      return handlerResult;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      const entry = this.createAuditEntry(action, resource, ctx, result, 'EXECUTED', errorMessage, now);
      if (this.config.onAction) {
        this.config.onAction(entry);
      }
      throw err;
    }
  }

  /**
   * Get the full audit log for this monitor.
   *
   * Returns a snapshot of all audit entries, the current Merkle root,
   * and the total entry count.
   *
   * @returns A copy of the audit log with entries, Merkle root, and count.
   *
   * @example
   * ```ts
   * const log = monitor.getAuditLog();
   * console.log(log.count, log.merkleRoot);
   * ```
   */
  getAuditLog(): AuditLog {
    return {
      covenantId: this.covenantId,
      entries: [...this.entries],
      merkleRoot: this.computeMerkleRoot(),
      count: this.entries.length,
    };
  }

  /**
   * Get a specific audit entry by index.
   *
   * @param index - The zero-based index of the audit entry to retrieve.
   * @returns The audit entry at the given index, or undefined if out of range.
   *
   * @example
   * ```ts
   * const entry = monitor.getAuditEntry(0);
   * if (entry) console.log(entry.action, entry.outcome);
   * ```
   */
  getAuditEntry(index: number): AuditEntry | undefined {
    return this.entries[index];
  }

  /**
   * Verify the integrity of the entire audit log hash chain.
   *
   * Recomputes every entry hash from its content and the previous hash,
   * checking that the stored hash matches the recomputed one.
   *
   * @returns True if the hash chain is intact and no entries have been tampered with.
   *
   * @example
   * ```ts
   * const intact = monitor.verifyAuditLogIntegrity();
   * if (!intact) console.error('Audit log has been tampered with');
   * ```
   */
  verifyAuditLogIntegrity(): boolean {
    if (this.entries.length === 0) {
      return true;
    }

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i]!;

      // Check previousHash linkage
      const expectedPreviousHash = i === 0
        ? GENESIS_HASH
        : this.entries[i - 1]!.hash;

      if (entry.previousHash !== expectedPreviousHash) {
        return false;
      }

      // Recompute the hash and verify it matches
      const recomputedHash = computeEntryHash(entry);
      if (entry.hash !== recomputedHash) {
        return false;
      }
    }

    return true;
  }

  /**
   * Compute the Merkle root of all audit entry hashes.
   *
   * Builds a balanced binary Merkle tree from the entry hashes.
   * If the number of leaves is odd, the last leaf is duplicated.
   *
   * @returns The Merkle root hash, or the genesis hash if the log is empty.
   *
   * @example
   * ```ts
   * const root = monitor.computeMerkleRoot();
   * console.log('Merkle root:', root);
   * ```
   */
  computeMerkleRoot(): HashHex {
    if (this.entries.length === 0) {
      return GENESIS_HASH;
    }

    return computeMerkleRootFromHashes(this.entries.map((e) => e.hash));
  }

  /**
   * Generate a Merkle inclusion proof for a specific audit entry.
   *
   * @param entryIndex - The index of the audit entry.
   * @returns A MerkleProof that can be verified with verifyMerkleProof().
   * @throws {SteleError} If the entry index is out of range.
   *
   * @example
   * ```ts
   * const proof = monitor.generateMerkleProof(0);
   * console.log(verifyMerkleProof(proof)); // true
   * ```
   */
  generateMerkleProof(entryIndex: number): MerkleProof {
    if (entryIndex < 0 || entryIndex >= this.entries.length) {
      throw new SteleError(
        SteleErrorCode.PROTOCOL_INVALID_INPUT,
        `Entry index ${entryIndex} is out of range [0, ${this.entries.length})`,
        { hint: `Provide an entry index between 0 and ${this.entries.length - 1}.` }
      );
    }

    const leaves = this.entries.map((e) => e.hash);
    const proof: HashHex[] = [];
    let idx = entryIndex;

    let level = [...leaves];

    while (level.length > 1) {
      // If odd number, duplicate the last element
      if (level.length % 2 !== 0) {
        level.push(level[level.length - 1]!);
      }

      const nextLevel: HashHex[] = [];

      // Find the sibling and add to proof
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      if (siblingIdx < level.length) {
        proof.push(level[siblingIdx]!);
      }

      // Build next level
      for (let i = 0; i < level.length; i += 2) {
        nextLevel.push(sha256String(level[i]! + level[i + 1]!));
      }

      idx = Math.floor(idx / 2);
      level = nextLevel;
    }

    return {
      entryHash: this.entries[entryIndex]!.hash,
      proof,
      index: entryIndex,
      merkleRoot: level[0]!,
    };
  }

  /**
   * Check whether a rate limit is exceeded for the given action.
   *
   * @param action - The action string to check rate limits for.
   * @returns An object with `exceeded` (boolean) and `remaining` (number of allowed calls left).
   *
   * @example
   * ```ts
   * const { exceeded, remaining } = monitor.checkRateLimit('api.call');
   * if (exceeded) console.log('Rate limit exceeded');
   * ```
   */
  checkRateLimit(action: string): { exceeded: boolean; remaining: number } {
    return this.checkRateLimitInternal(action);
  }

  /**
   * Get the current rate limit state for all tracked actions.
   *
   * @returns An array of rate limit states, one per tracked action pattern.
   *
   * @example
   * ```ts
   * const states = monitor.getRateLimitState();
   * states.forEach(s => console.log(s.action, s.count, s.limit));
   * ```
   */
  getRateLimitState(): RateLimitState[] {
    return Array.from(this.rateLimits.values());
  }

  /**
   * Reset the monitor, clearing all audit entries and rate limit state.
   *
   * After calling this method the audit log is empty and all rate limit
   * counters are zeroed.
   *
   * @example
   * ```ts
   * monitor.reset();
   * console.log(monitor.getAuditLog().count); // 0
   * ```
   */
  reset(): void {
    this.entries.length = 0;
    this.rateLimits.clear();
  }

  // ─── Private helpers ──────────────────────────────────────────────────

  /**
   * Create an audit entry, hash it, and append to the log.
   */
  private createAuditEntry(
    action: string,
    resource: string,
    context: Record<string, unknown>,
    result: EvaluationResult,
    outcome: ExecutionOutcome,
    error: string | undefined,
    ts: string,
  ): AuditEntry {
    const index = this.entries.length;
    const previousHash = index === 0
      ? GENESIS_HASH
      : this.entries[index - 1]!.hash;

    const entry: AuditEntry = {
      index,
      timestamp: ts,
      action,
      resource,
      context,
      result,
      outcome,
      previousHash,
      hash: '' as HashHex,
    };

    if (error !== undefined) {
      entry.error = error;
    }

    // Compute the hash of this entry
    entry.hash = computeEntryHash(entry);

    this.entries.push(entry);
    return entry;
  }

  /**
   * Internal rate limit check using the CCL document's limit statements.
   */
  private checkRateLimitInternal(action: string): { exceeded: boolean; remaining: number } {
    const now = Date.now();

    // Find matching limit statements
    let matchedLimit: LimitStatement | undefined;
    let bestSpecificity = -1;

    for (const limit of this.doc.limits) {
      if (matchAction(limit.action, action)) {
        // Simple specificity: count non-wildcard segments
        const parts = limit.action.split('.');
        let spec = 0;
        for (const p of parts) {
          if (p === '**') spec += 0;
          else if (p === '*') spec += 1;
          else spec += 2;
        }
        if (spec > bestSpecificity) {
          bestSpecificity = spec;
          matchedLimit = limit;
        }
      }
    }

    if (!matchedLimit) {
      return { exceeded: false, remaining: Infinity };
    }

    const key = matchedLimit.action;
    let state = this.rateLimits.get(key);

    if (!state) {
      state = {
        action: key,
        count: 0,
        periodStart: now,
        periodSeconds: matchedLimit.periodSeconds,
        limit: matchedLimit.count,
      };
      this.rateLimits.set(key, state);
    }

    // Check if the period has expired
    const periodMs = state.periodSeconds * 1000;
    if (now - state.periodStart >= periodMs) {
      // Reset the window
      state.count = 0;
      state.periodStart = now;
    }

    const remaining = Math.max(0, state.limit - state.count);
    return {
      exceeded: state.count >= state.limit,
      remaining,
    };
  }

  /**
   * Increment the rate limit counter for an action.
   */
  private incrementRateLimit(action: string): void {
    const now = Date.now();

    for (const limit of this.doc.limits) {
      if (matchAction(limit.action, action)) {
        const key = limit.action;
        let state = this.rateLimits.get(key);

        if (!state) {
          state = {
            action: key,
            count: 0,
            periodStart: now,
            periodSeconds: limit.periodSeconds,
            limit: limit.count,
          };
          this.rateLimits.set(key, state);
        }

        // Check if the period has expired
        const periodMs = state.periodSeconds * 1000;
        if (now - state.periodStart >= periodMs) {
          state.count = 0;
          state.periodStart = now;
        }

        state.count++;
      }
    }
  }
}

// ─── CapabilityGate ───────────────────────────────────────────────────────────

/**
 * A capability-based enforcement gate that restricts execution to only
 * those actions explicitly permitted by CCL constraints.
 *
 * Unlike Monitor which evaluates at runtime, CapabilityGate pre-computes
 * the set of allowed capabilities from permit statements and refuses to
 * even register handlers for non-permitted actions.
 */
export class CapabilityGate {
  private readonly covenantId: HashHex;
  private readonly doc: CCLDocument;
  private readonly runtimeKeyPair: KeyPair;
  private readonly runtimeType: string;
  private readonly handlers: Map<string, ActionHandler<unknown>> = new Map();
  private readonly permittedActions: Set<string> = new Set();
  private readonly executionLog: ExecutionLogEntry[] = [];

  private constructor(
    covenantId: HashHex,
    doc: CCLDocument,
    runtimeKeyPair: KeyPair,
    runtimeType: string,
  ) {
    this.covenantId = covenantId;
    this.doc = doc;
    this.runtimeKeyPair = runtimeKeyPair;
    this.runtimeType = runtimeType;

    // Extract permitted actions from permit statements
    for (const permit of doc.permits) {
      this.permittedActions.add(permit.action);
    }
  }

  /**
   * Create a CapabilityGate from CCL constraints.
   *
   * Parses the constraints and extracts only the permit statements
   * as the set of allowed capabilities.
   *
   * @param covenantId - The ID of the covenant.
   * @param constraints - CCL constraint source text.
   * @param runtimeKeyPair - The key pair identifying this runtime instance.
   * @param runtimeType - A label for the type of runtime (default: "node").
   * @returns A new CapabilityGate instance with capabilities derived from permit statements.
   *
   * @example
   * ```ts
   * const gate = await CapabilityGate.fromConstraints(
   *   covenantId, 'permit file.read on /data/**', keyPair,
   * );
   * ```
   */
  static async fromConstraints(
    covenantId: HashHex,
    constraints: string,
    runtimeKeyPair: KeyPair,
    runtimeType: string = 'node',
  ): Promise<CapabilityGate> {
    const doc = parse(constraints);
    return new CapabilityGate(covenantId, doc, runtimeKeyPair, runtimeType);
  }

  /**
   * Register an action handler for a permitted action.
   *
   * @param action - The action string to register a handler for.
   * @param handler - The handler function to execute when this action is invoked.
   * @throws {CapabilityError} If the action is not in the permitted set.
   *
   * @example
   * ```ts
   * gate.register('file.read', async (resource) => {
   *   return readFile(resource);
   * });
   * ```
   */
  register(action: string, handler: ActionHandler<unknown>): void {
    // Check if any permit statement's pattern matches this action
    let hasPermission = false;
    for (const permitAction of this.permittedActions) {
      if (matchAction(permitAction, action) || permitAction === action) {
        hasPermission = true;
        break;
      }
    }

    if (!hasPermission) {
      throw new CapabilityError(
        action,
        `Cannot register handler for action '${action}': not permitted by constraints`,
      );
    }

    this.handlers.set(action, handler);
  }

  /**
   * Execute a registered action handler, enforcing capability constraints.
   *
   * - If no handler is registered and no capability permits the action: outcome is IMPOSSIBLE.
   * - If constraints deny the action: outcome is DENIED.
   * - Otherwise: the handler is executed with outcome EXECUTED.
   *
   * @param action - The action to execute.
   * @param resource - The resource being acted upon.
   * @param context - Optional evaluation context for condition matching.
   * @returns The result of the handler execution.
   * @throws {CapabilityError} If no capability permits the action or no handler is registered.
   * @throws {MonitorDeniedError} If the action is denied by runtime constraint evaluation.
   *
   * @example
   * ```ts
   * const result = await gate.execute<string>('file.read', '/data/users');
   * ```
   */
  async execute<T>(
    action: string,
    resource: string,
    context?: Record<string, unknown>,
  ): Promise<T> {
    const ctx = context ?? {};
    const now = timestamp();

    // Check if we have a handler for this action
    const handler = this.handlers.get(action);
    if (!handler) {
      // Check if any permitted capability covers this action
      let couldBePermitted = false;
      for (const permitAction of this.permittedActions) {
        if (matchAction(permitAction, action)) {
          couldBePermitted = true;
          break;
        }
      }

      if (!couldBePermitted) {
        this.executionLog.push({
          action,
          resource,
          outcome: 'IMPOSSIBLE',
          timestamp: now,
          error: `No capability exists for action '${action}'`,
        });
        throw new CapabilityError(
          action,
          `Action '${action}' is impossible: no capability permits it`,
        );
      }

      this.executionLog.push({
        action,
        resource,
        outcome: 'IMPOSSIBLE',
        timestamp: now,
        error: `No handler registered for action '${action}'`,
      });
      throw new CapabilityError(
        action,
        `No handler registered for action '${action}'`,
      );
    }

    // Evaluate constraints at runtime (check conditions)
    const result = evaluate(this.doc, action, resource, ctx);

    if (!result.permitted) {
      this.executionLog.push({
        action,
        resource,
        outcome: 'DENIED',
        timestamp: now,
        error: result.reason,
      });
      throw new MonitorDeniedError(
        action,
        resource,
        result.matchedRule,
        result.severity,
      );
    }

    // Execute the handler
    try {
      const handlerResult = await handler(resource, ctx);
      this.executionLog.push({
        action,
        resource,
        outcome: 'EXECUTED',
        timestamp: now,
      });
      return handlerResult as T;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      this.executionLog.push({
        action,
        resource,
        outcome: 'EXECUTED',
        timestamp: now,
        error: errorMessage,
      });
      throw err;
    }
  }

  /**
   * Check if a capability exists for the given action.
   *
   * @param action - The action string to check (e.g. "file.read").
   * @returns True if at least one permit pattern matches the action.
   *
   * @example
   * ```ts
   * if (gate.hasCapability('file.read')) {
   *   console.log('file.read is permitted');
   * }
   * ```
   */
  hasCapability(action: string): boolean {
    for (const permitAction of this.permittedActions) {
      if (matchAction(permitAction, action)) {
        return true;
      }
    }
    return false;
  }

  /**
   * List all permitted action patterns.
   *
   * @returns An array of action pattern strings extracted from permit statements.
   *
   * @example
   * ```ts
   * const caps = gate.listCapabilities();
   * // e.g. ['file.read', 'data.**']
   * ```
   */
  listCapabilities(): string[] {
    return Array.from(this.permittedActions);
  }

  /**
   * Generate a signed capability manifest describing what this runtime can do.
   *
   * The manifest includes all capabilities derived from permit statements,
   * signed by the runtime's key pair for authenticity.
   */
  async generateManifest(): Promise<CapabilityManifest> {
    const generatedAt = timestamp();

    const capabilities = this.doc.permits.map((permit) => {
      const cap: { action: string; resource: string; conditions?: string } = {
        action: permit.action,
        resource: permit.resource,
      };
      if (permit.condition) {
        cap.conditions = JSON.stringify(permit.condition);
      }
      return cap;
    });

    // Build manifest without hash and signature first
    const manifestContent = {
      covenantId: this.covenantId,
      capabilities,
      runtimeType: this.runtimeType,
      runtimePublicKey: this.runtimeKeyPair.publicKeyHex,
      generatedAt,
    };

    const manifestHash = sha256Object(manifestContent);

    // Sign the manifest hash
    const signatureBytes = await signString(manifestHash, this.runtimeKeyPair.privateKey);
    const runtimeSignature = toHex(signatureBytes);

    const manifest: CapabilityManifest = {
      covenantId: this.covenantId,
      capabilities,
      manifestHash,
      runtimeType: this.runtimeType,
      runtimeSignature,
      runtimePublicKey: this.runtimeKeyPair.publicKeyHex,
      generatedAt,
    };

    return manifest;
  }

  /**
   * Verify the signature of a capability manifest.
   *
   * Recomputes the manifest hash from the content fields and verifies
   * the runtime signature against the embedded public key.
   */
  static async verifyManifest(manifest: CapabilityManifest): Promise<boolean> {
    // Recompute the manifest hash from content
    const manifestContent = {
      covenantId: manifest.covenantId,
      capabilities: manifest.capabilities,
      runtimeType: manifest.runtimeType,
      runtimePublicKey: manifest.runtimePublicKey,
      generatedAt: manifest.generatedAt,
    };

    const expectedHash = sha256Object(manifestContent);

    if (manifest.manifestHash !== expectedHash) {
      return false;
    }

    // Verify the signature
    try {
      const messageBytes = new TextEncoder().encode(manifest.manifestHash);
      const sigBytes = fromHex(manifest.runtimeSignature);
      const pubKeyBytes = fromHex(manifest.runtimePublicKey);
      return await cryptoVerify(messageBytes, sigBytes, pubKeyBytes);
    } catch {
      return false;
    }
  }

  /**
   * Prove which actions from a given list are impossible (not permitted)
   * and which are possible (permitted by at least one capability).
   *
   * @param actions - An array of action strings to test.
   * @returns An object with `possible`, `impossible` arrays and the `manifestHash`.
   *
   * @example
   * ```ts
   * const result = await gate.proveImpossible(['file.read', 'file.delete']);
   * console.log(result.impossible); // e.g. ['file.delete']
   * ```
   */
  async proveImpossible(
    actions: string[],
  ): Promise<{ possible: string[]; impossible: string[]; manifestHash: HashHex }> {
    const possible: string[] = [];
    const impossible: string[] = [];

    for (const action of actions) {
      if (this.hasCapability(action)) {
        possible.push(action);
      } else {
        impossible.push(action);
      }
    }

    const manifest = await this.generateManifest();

    return {
      possible,
      impossible,
      manifestHash: manifest.manifestHash,
    };
  }

  /**
   * Get the execution log of all actions attempted through this gate.
   *
   * @returns A copy of all execution log entries recorded by this gate.
   *
   * @example
   * ```ts
   * const log = gate.getExecutionLog();
   * log.forEach(e => console.log(e.action, e.outcome));
   * ```
   */
  getExecutionLog(): ExecutionLogEntry[] {
    return [...this.executionLog];
  }
}

// ─── Utility functions ────────────────────────────────────────────────────────

/**
 * Compute the hash of an audit entry.
 *
 * The hash is the SHA-256 of the canonical JSON of the entry's content
 * fields (excluding the hash field itself) concatenated with the previousHash.
 */
function computeEntryHash(entry: AuditEntry): HashHex {
  const content: Record<string, unknown> = {
    index: entry.index,
    timestamp: entry.timestamp,
    action: entry.action,
    resource: entry.resource,
    context: entry.context,
    result: {
      permitted: entry.result.permitted,
      reason: entry.result.reason,
      severity: entry.result.severity,
    },
    outcome: entry.outcome,
    previousHash: entry.previousHash,
  };

  if (entry.error !== undefined) {
    content.error = entry.error;
  }

  return sha256Object(content);
}

/**
 * Compute a Merkle root from an array of hashes.
 *
 * If the number of leaves at any level is odd, the last leaf is duplicated
 * before pairing, producing a balanced tree.
 */
function computeMerkleRootFromHashes(hashes: HashHex[]): HashHex {
  if (hashes.length === 0) {
    return GENESIS_HASH;
  }

  let level = [...hashes];

  while (level.length > 1) {
    // If odd number, duplicate the last hash
    if (level.length % 2 !== 0) {
      level.push(level[level.length - 1]!);
    }

    const nextLevel: HashHex[] = [];
    for (let i = 0; i < level.length; i += 2) {
      nextLevel.push(sha256String(level[i]! + level[i + 1]!));
    }
    level = nextLevel;
  }

  return level[0]!;
}

// ─── Behavioral Provenance ────────────────────────────────────────────────────

/**
 * A single provenance record linking an action to the specific covenant
 * authorization that permitted it.
 *
 * Each record carries a cryptographic chain linking it to the exact CCL
 * rule that justified the action — not "didn't violate" but "here is the
 * exact justification."
 */
export interface ProvenanceRecord {
  /** Unique identifier for this record. */
  actionId: string;
  /** The action that was performed. */
  action: string;
  /** The resource targeted by the action. */
  resource: string;
  /** Unix epoch timestamp (milliseconds) when the action occurred. */
  timestamp: number;
  /** The covenant ID that governs this action. */
  covenantId: string;
  /** Which specific CCL rule authorized this action. */
  ruleReference: string;
  /** Hash of the covenant rule that permitted this action. */
  authorizationHash: string;
  /** Chain link to the previous record's hash. */
  previousRecordHash: string;
  /** Hash of this entire record. */
  recordHash: string;
}

/**
 * A chain of provenance records for a specific agent, forming a
 * tamper-evident trail of authorized actions.
 */
export interface ProvenanceChain {
  /** The agent whose actions are tracked. */
  agentId: string;
  /** The ordered list of provenance records. */
  records: ProvenanceRecord[];
  /** Hash of the most recent record. */
  chainHead: string;
  /** Total number of records in the chain. */
  chainLength: number;
  /** Whether the chain integrity has been verified. */
  integrityVerified: boolean;
}

/**
 * Create a provenance record linking an action to its covenant authorization.
 *
 * Generates a unique actionId, computes the authorizationHash from the
 * covenant ID and rule reference, and produces a recordHash covering
 * all fields to ensure tamper evidence.
 *
 * @param params - The action, resource, covenant, and rule details.
 * @returns A complete ProvenanceRecord with all hashes computed.
 */
export function createProvenanceRecord(params: {
  action: string;
  resource: string;
  covenantId: string;
  ruleReference: string;
  previousRecordHash?: string;
}): ProvenanceRecord {
  const actionId = generateId();
  const ts = Date.now();
  const previousRecordHash = params.previousRecordHash ?? 'genesis';
  const authorizationHash = sha256String(params.covenantId + '|' + params.ruleReference);
  const recordHash = sha256String(
    actionId + '|' +
    params.action + '|' +
    params.resource + '|' +
    String(ts) + '|' +
    authorizationHash + '|' +
    previousRecordHash,
  );

  return {
    actionId,
    action: params.action,
    resource: params.resource,
    timestamp: ts,
    covenantId: params.covenantId,
    ruleReference: params.ruleReference,
    authorizationHash,
    previousRecordHash,
    recordHash,
  };
}

/**
 * Build a provenance chain from an ordered array of records.
 *
 * Verifies that each record correctly links to the previous record
 * via the previousRecordHash field. The chain head is set to the
 * hash of the last record.
 *
 * @param agentId - The agent whose actions are tracked.
 * @param records - The ordered list of provenance records.
 * @returns A ProvenanceChain with integrity verification results.
 */
export function buildProvenanceChain(agentId: string, records: ProvenanceRecord[]): ProvenanceChain {
  if (records.length === 0) {
    return {
      agentId,
      records: [],
      chainHead: 'genesis',
      chainLength: 0,
      integrityVerified: true,
    };
  }

  let integrityVerified = true;

  // Verify chain linkage
  for (let i = 0; i < records.length; i++) {
    const record = records[i]!;
    if (i === 0) {
      // First record should link to 'genesis'
      if (record.previousRecordHash !== 'genesis') {
        integrityVerified = false;
        break;
      }
    } else {
      // Subsequent records should link to previous record's hash
      if (record.previousRecordHash !== records[i - 1]!.recordHash) {
        integrityVerified = false;
        break;
      }
    }
  }

  const lastRecord = records[records.length - 1]!;

  return {
    agentId,
    records: [...records],
    chainHead: lastRecord.recordHash,
    chainLength: records.length,
    integrityVerified,
  };
}

/**
 * Verify the integrity of a provenance chain.
 *
 * Checks that every record in the chain correctly links to the previous
 * record's hash and identifies any broken links or orphaned records.
 *
 * @param chain - The provenance chain to verify.
 * @returns An object with validity status, broken link indices, and orphaned record indices.
 */
export function verifyProvenance(chain: ProvenanceChain): {
  valid: boolean;
  brokenLinks: number[];
  orphanedRecords: number[];
} {
  const brokenLinks: number[] = [];
  const orphanedRecords: number[] = [];

  if (chain.records.length === 0) {
    return { valid: true, brokenLinks, orphanedRecords };
  }

  // Build a set of all record hashes for orphan detection
  const recordHashes = new Set<string>();
  for (const record of chain.records) {
    recordHashes.add(record.recordHash);
  }

  for (let i = 0; i < chain.records.length; i++) {
    const record = chain.records[i]!;

    if (i === 0) {
      // First record should link to 'genesis'
      if (record.previousRecordHash !== 'genesis') {
        brokenLinks.push(i);
      }
    } else {
      // Check that previousRecordHash matches the previous record's hash
      const expectedPrevious = chain.records[i - 1]!.recordHash;
      if (record.previousRecordHash !== expectedPrevious) {
        brokenLinks.push(i);
      }
    }

    // Check for orphaned records: a record that references a previousRecordHash
    // that is neither 'genesis' nor any record's hash in the chain
    if (
      record.previousRecordHash !== 'genesis' &&
      !recordHashes.has(record.previousRecordHash)
    ) {
      orphanedRecords.push(i);
    }
  }

  return {
    valid: brokenLinks.length === 0 && orphanedRecords.length === 0,
    brokenLinks,
    orphanedRecords,
  };
}

/**
 * Query a provenance chain by filtering on action, resource, covenantId,
 * or time range. All filter criteria are optional and combined with AND logic.
 *
 * @param chain - The provenance chain to query.
 * @param params - Filter criteria.
 * @returns An array of matching provenance records.
 */
export function queryProvenance(chain: ProvenanceChain, params: {
  action?: string;
  resource?: string;
  covenantId?: string;
  timeRange?: { start: number; end: number };
}): ProvenanceRecord[] {
  return chain.records.filter((record) => {
    if (params.action !== undefined && record.action !== params.action) {
      return false;
    }
    if (params.resource !== undefined && record.resource !== params.resource) {
      return false;
    }
    if (params.covenantId !== undefined && record.covenantId !== params.covenantId) {
      return false;
    }
    if (params.timeRange !== undefined) {
      if (record.timestamp < params.timeRange.start || record.timestamp > params.timeRange.end) {
        return false;
      }
    }
    return true;
  });
}

// ─── Defense in Depth ─────────────────────────────────────────────────────────

/**
 * A single layer in a defense-in-depth security model.
 *
 * Each layer represents an independent security mechanism (runtime restriction,
 * external attestation, or ZK proof) with its own bypass probability.
 */
export interface DefenseLayer {
  /** Human-readable name for this defense layer. */
  name: string;
  /** The type of defense mechanism. */
  type: 'runtime' | 'attestation' | 'proof';
  /** Probability of bypassing this layer (0-1). */
  bypassProbability: number;
  /** Whether this layer is currently active. */
  active: boolean;
  /** Timestamp of last verification (milliseconds since epoch). */
  lastVerified: number;
}

/**
 * Configuration for a defense-in-depth security model.
 *
 * Specifies the layers, minimum active layer count, and the maximum
 * acceptable breach probability threshold.
 */
export interface DefenseInDepthConfig {
  /** The defense layers in this configuration. */
  layers: DefenseLayer[];
  /** Minimum number of layers that must be active. */
  minimumLayers: number;
  /** Maximum acceptable compound breach probability. */
  maxAcceptableBreachProbability: number;
}

/**
 * Analysis result for a defense-in-depth configuration.
 *
 * Contains the computed compound breach probability (product of all
 * active layer bypass probabilities), threshold comparison, and
 * improvement recommendations.
 */
export interface DefenseAnalysis {
  /** The configuration that was analyzed. */
  config: DefenseInDepthConfig;
  /** Number of currently active layers. */
  activeLayers: number;
  /** Product of all active layers' bypass probabilities. */
  independentBreachProbability: number;
  /** Whether the breach probability meets the configured threshold. */
  meetsThreshold: boolean;
  /** The active layer with the highest bypass probability. */
  weakestLayer: DefenseLayer | null;
  /** Human-readable recommendation for improving the defense posture. */
  recommendation: string;
}

/**
 * Create a defense-in-depth configuration with three standard layers:
 * runtime restriction, external attestation, and ZK proof.
 *
 * P(undetected breach) = P(bypass runtime) x P(bypass attestation) x P(bypass proof)
 *
 * @param params - Optional overrides for bypass probabilities and thresholds.
 * @returns A DefenseInDepthConfig with three active layers.
 */
export function createDefenseConfig(params?: {
  runtimeBypass?: number;
  attestationBypass?: number;
  proofBypass?: number;
  minimumLayers?: number;
  maxBreachProb?: number;
}): DefenseInDepthConfig {
  const now = Date.now();

  return {
    layers: [
      {
        name: 'runtime',
        type: 'runtime',
        bypassProbability: params?.runtimeBypass ?? 0.1,
        active: true,
        lastVerified: now,
      },
      {
        name: 'attestation',
        type: 'attestation',
        bypassProbability: params?.attestationBypass ?? 0.05,
        active: true,
        lastVerified: now,
      },
      {
        name: 'proof',
        type: 'proof',
        bypassProbability: params?.proofBypass ?? 0.01,
        active: true,
        lastVerified: now,
      },
    ],
    minimumLayers: params?.minimumLayers ?? 2,
    maxAcceptableBreachProbability: params?.maxBreachProb ?? 0.001,
  };
}

/**
 * Analyze a defense-in-depth configuration.
 *
 * Computes the independent breach probability as the product of all
 * active layers' bypass probabilities, identifies the weakest layer,
 * and generates a recommendation if the threshold is not met.
 *
 * @param config - The defense configuration to analyze.
 * @returns A DefenseAnalysis with breach probability and recommendations.
 */
export function analyzeDefense(config: DefenseInDepthConfig): DefenseAnalysis {
  const activeLayers = config.layers.filter((l) => l.active);
  const activeCount = activeLayers.length;

  // Compute compound breach probability (product of independent bypasses)
  let independentBreachProbability = 1;
  for (const layer of activeLayers) {
    independentBreachProbability *= layer.bypassProbability;
  }

  // If no active layers, breach probability is 1 (certain breach)
  if (activeCount === 0) {
    independentBreachProbability = 1;
  }

  const meetsThreshold = independentBreachProbability <= config.maxAcceptableBreachProbability;

  // Find the weakest layer (highest bypass probability among active layers)
  let weakestLayer: DefenseLayer | null = null;
  for (const layer of activeLayers) {
    if (weakestLayer === null || layer.bypassProbability > weakestLayer.bypassProbability) {
      weakestLayer = layer;
    }
  }

  // Generate recommendation
  let recommendation: string;
  if (activeCount < config.minimumLayers) {
    recommendation = `Only ${activeCount} layer(s) active, but ${config.minimumLayers} required. Enable additional defense layers to meet minimum requirements.`;
  } else if (!meetsThreshold) {
    if (weakestLayer) {
      recommendation = `Breach probability ${independentBreachProbability.toExponential(2)} exceeds threshold ${config.maxAcceptableBreachProbability}. Strengthen the '${weakestLayer.name}' layer (bypass probability: ${weakestLayer.bypassProbability}) to reduce overall risk.`;
    } else {
      recommendation = `Breach probability ${independentBreachProbability.toExponential(2)} exceeds threshold ${config.maxAcceptableBreachProbability}. Add more defense layers.`;
    }
  } else {
    recommendation = `Defense posture meets threshold. Breach probability: ${independentBreachProbability.toExponential(2)}.`;
  }

  return {
    config,
    activeLayers: activeCount,
    independentBreachProbability,
    meetsThreshold,
    weakestLayer,
    recommendation,
  };
}

/**
 * Add a custom defense layer to an existing configuration.
 *
 * Returns a new configuration with the additional layer appended.
 * The original configuration is not modified.
 *
 * @param config - The existing defense configuration.
 * @param layer - The new defense layer to add.
 * @returns A new DefenseInDepthConfig with the added layer.
 */
export function addDefenseLayer(config: DefenseInDepthConfig, layer: DefenseLayer): DefenseInDepthConfig {
  return {
    ...config,
    layers: [...config.layers, layer],
  };
}

/**
 * Disable a named defense layer in the configuration.
 *
 * Returns a new configuration with the named layer set to inactive.
 * If disabling the layer would drop the active count below the minimum,
 * a warning is included in the analysis recommendation.
 *
 * @param config - The existing defense configuration.
 * @param layerName - The name of the layer to disable.
 * @returns A new DefenseInDepthConfig with the named layer disabled.
 */
export function disableLayer(config: DefenseInDepthConfig, layerName: string): DefenseInDepthConfig {
  return {
    ...config,
    layers: config.layers.map((layer) =>
      layer.name === layerName ? { ...layer, active: false } : { ...layer },
    ),
  };
}

// ─── Audit Chain ──────────────────────────────────────────────────────────────

export { AuditChain } from './audit-chain';
export type { ChainedAuditEntry } from './audit-chain';
