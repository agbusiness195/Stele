/**
 * Middleware system for the Stele SDK.
 *
 * Provides a composable pipeline that intercepts SteleClient operations
 * (create, verify, evaluate, etc.) for cross-cutting concerns like
 * logging, metrics, validation, caching, and rate limiting.
 */

import { Logger, defaultLogger, SteleError, SteleErrorCode } from '@stele/types';

// ─── Types ───────────────────────────────────────────────────────────────────

/** Context passed to each middleware in the pipeline. */
export interface MiddlewareContext {
  /** The operation being performed (e.g., "createCovenant", "verifyCovenant"). */
  operation: string;
  /** Arguments passed to the operation. */
  args: Record<string, unknown>;
  /** ISO 8601 timestamp of when the pipeline execution started. */
  timestamp: string;
  /** Arbitrary metadata that middleware can read and write. */
  metadata: Record<string, unknown>;
}

/** Result returned by a middleware's `before` hook. */
export interface MiddlewareResult {
  /** Whether the pipeline should continue to the next middleware and the operation. */
  proceed: boolean;
  /** Optional modified arguments to pass downstream. */
  modifiedArgs?: Record<string, unknown>;
  /** Optional metadata to merge into the context. */
  metadata?: Record<string, unknown>;
}

/** Functional middleware signature for simple use cases. */
export type MiddlewareFn = (
  ctx: MiddlewareContext,
  next: () => Promise<unknown>,
) => Promise<unknown>;

/** Structured middleware with named lifecycle hooks. */
export interface SteleMiddleware {
  /** Unique name identifying this middleware. */
  name: string;
  /** Called before the operation executes. Can modify args or prevent execution. */
  before?: (ctx: MiddlewareContext) => Promise<MiddlewareResult>;
  /** Called after the operation succeeds. Can transform the result. */
  after?: (ctx: MiddlewareContext, result: unknown) => Promise<unknown>;
  /** Called when the operation throws an error. */
  onError?: (ctx: MiddlewareContext, error: Error) => Promise<void>;
  /**
   * Called when the middleware is removed from the pipeline via {@link MiddlewarePipeline.dispose}
   * or when the owning SteleClient is disposed.
   *
   * Use this hook to release resources such as timers, connections, or file handles.
   */
  dispose?: () => Promise<void> | void;
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

/**
 * Composable middleware pipeline for intercepting SteleClient operations.
 *
 * Middleware is executed in registration order for `before` hooks,
 * and in reverse order for `after` hooks (onion model).
 */
export class MiddlewarePipeline {
  private readonly _middlewares: SteleMiddleware[] = [];

  /** Add a middleware to the end of the pipeline. Returns `this` for chaining. */
  use(middleware: SteleMiddleware): this {
    // Prevent duplicate names
    const existing = this._middlewares.findIndex((m) => m.name === middleware.name);
    if (existing !== -1) {
      this._middlewares[existing] = middleware;
    } else {
      this._middlewares.push(middleware);
    }
    return this;
  }

  /** Remove a middleware by name. Returns `this` for chaining. */
  remove(name: string): this {
    const idx = this._middlewares.findIndex((m) => m.name === name);
    if (idx !== -1) {
      this._middlewares.splice(idx, 1);
    }
    return this;
  }

  /** List middleware names in execution order. */
  list(): string[] {
    return this._middlewares.map((m) => m.name);
  }

  /** Remove all middleware from the pipeline. */
  clear(): void {
    this._middlewares.length = 0;
  }

  /**
   * Dispose all middleware in the pipeline and remove them.
   *
   * Calls each middleware's {@link SteleMiddleware.dispose} hook (if defined)
   * before clearing the pipeline. Unlike {@link clear}, this method awaits
   * async dispose hooks so resources are properly released.
   */
  async dispose(): Promise<void> {
    for (const mw of this._middlewares) {
      if (mw.dispose) {
        await mw.dispose();
      }
    }
    this._middlewares.length = 0;
  }

  /**
   * Execute the middleware pipeline around an operation.
   *
   * Runs `before` hooks in order, then the operation function,
   * then `after` hooks in reverse order. If any `before` hook
   * returns `{ proceed: false }`, the operation is skipped and
   * `undefined` is returned. If the operation or any hook throws,
   * `onError` hooks are called in order.
   *
   * @param operation - Name of the operation (e.g., "createCovenant").
   * @param args - Arguments for the operation.
   * @param fn - The actual operation to execute.
   * @returns The (possibly transformed) result of the operation.
   */
  async execute<T>(
    operation: string,
    args: Record<string, unknown>,
    fn: () => Promise<T>,
  ): Promise<T | undefined> {
    const ctx: MiddlewareContext = {
      operation,
      args: { ...args },
      timestamp: new Date().toISOString(),
      metadata: {},
    };

    try {
      // Run before hooks in order
      for (const mw of this._middlewares) {
        if (mw.before) {
          const result = await mw.before(ctx);

          // Merge metadata
          if (result.metadata) {
            Object.assign(ctx.metadata, result.metadata);
          }

          // Apply modified args
          if (result.modifiedArgs) {
            Object.assign(ctx.args, result.modifiedArgs);
          }

          // Short-circuit: when a middleware vetoes the operation, return
          // undefined rather than executing fn(). Callers must handle the
          // `T | undefined` return type accordingly.
          if (!result.proceed) {
            return undefined;
          }
        }
      }

      // Execute the actual operation
      let result: unknown = await fn();

      // Run after hooks in reverse order (onion model)
      for (let i = this._middlewares.length - 1; i >= 0; i--) {
        const mw = this._middlewares[i]!;
        if (mw.after) {
          result = await mw.after(ctx, result);
        }
      }

      return result as T;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));

      // Run onError hooks in order
      for (const mw of this._middlewares) {
        if (mw.onError) {
          await mw.onError(ctx, err);
        }
      }

      throw err;
    }
  }
}

// ─── Built-in middleware factories ───────────────────────────────────────────

/**
 * Creates a logging middleware that logs operation start, completion, and errors.
 *
 * @param logger - Optional Logger instance. Defaults to the @stele/types defaultLogger.
 */
export function loggingMiddleware(logger?: Logger): SteleMiddleware {
  const log = logger ?? defaultLogger;

  return {
    name: 'logging',
    async before(ctx) {
      log.info(`[stele] ${ctx.operation} started`, {
        operation: ctx.operation,
        args: ctx.args,
        timestamp: ctx.timestamp,
      });
      return { proceed: true };
    },
    async after(ctx, result) {
      log.info(`[stele] ${ctx.operation} completed`, {
        operation: ctx.operation,
        timestamp: ctx.timestamp,
      });
      return result;
    },
    async onError(ctx, error) {
      // Build structured error fields, including SteleError properties when available
      const errorFields: Record<string, unknown> = {
        operation: ctx.operation,
        error: error.message,
        timestamp: ctx.timestamp,
      };

      // Enrich with SteleError structured data if present
      const steleErr = error as { code?: string; context?: Record<string, unknown>; hint?: string };
      if (steleErr.code) {
        errorFields.errorCode = steleErr.code;
      }
      if (steleErr.context) {
        errorFields.errorContext = steleErr.context;
      }
      if (steleErr.hint) {
        errorFields.hint = steleErr.hint;
      }

      // Include operation context from pipeline metadata
      if (Object.keys(ctx.metadata).length > 0) {
        errorFields.pipelineMetadata = ctx.metadata;
      }

      log.error(`[stele] ${ctx.operation} failed: ${error.message}`, errorFields);
    },
  };
}

/**
 * Creates a validation middleware that checks common arguments.
 *
 * Validates:
 * - `constraints` argument is a non-empty string (if present)
 * - `privateKey` argument has valid size (32 or 64 bytes for Ed25519, if present)
 */
export function validationMiddleware(): SteleMiddleware {
  return {
    name: 'validation',
    async before(ctx) {
      const { args } = ctx;

      // Validate constraints is non-empty
      if ('constraints' in args) {
        const constraints = args.constraints;
        if (typeof constraints !== 'string' || constraints.trim().length === 0) {
          throw new Error('Validation failed: constraints must be a non-empty string');
        }
      }

      // Validate key sizes (Ed25519 private keys are 32 or 64 bytes)
      if ('privateKey' in args) {
        const key = args.privateKey;
        if (key instanceof Uint8Array) {
          if (key.length !== 32 && key.length !== 64) {
            throw new Error(
              `Validation failed: privateKey must be 32 or 64 bytes, got ${key.length}`,
            );
          }
        }
      }

      return { proceed: true };
    },
  };
}

/**
 * Creates a timing middleware that records operation duration in metadata.
 *
 * After execution, `ctx.metadata.durationMs` contains the elapsed time
 * in milliseconds.
 */
export function timingMiddleware(): SteleMiddleware {
  return {
    name: 'timing',
    async before(ctx) {
      ctx.metadata._timingStart = performance.now();
      return { proceed: true };
    },
    async after(ctx, result) {
      const start = ctx.metadata._timingStart as number;
      ctx.metadata.durationMs = performance.now() - start;
      delete ctx.metadata._timingStart;
      return result;
    },
  };
}

/**
 * Creates a rate-limiting middleware using a simple token bucket algorithm.
 *
 * @param options - Rate limit configuration.
 * @param options.maxPerSecond - Maximum number of operations allowed per second.
 */
export function rateLimitMiddleware(options: { maxPerSecond: number }): SteleMiddleware {
  const { maxPerSecond } = options;
  let tokens = maxPerSecond;
  let lastRefill = Date.now();

  return {
    name: 'rateLimit',
    async before(_ctx) {
      const now = Date.now();
      const elapsed = (now - lastRefill) / 1000;

      // Refill tokens based on elapsed time
      tokens = Math.min(maxPerSecond, tokens + elapsed * maxPerSecond);
      lastRefill = now;

      if (tokens < 1) {
        throw new Error('Rate limit exceeded');
      }

      tokens -= 1;
      return { proceed: true };
    },
  };
}
