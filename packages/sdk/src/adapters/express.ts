/**
 * Express/HTTP middleware adapter for the Nobulex SDK.
 *
 * Provides zero-config HTTP middleware that wraps any Express/Connect-compatible
 * handler with Nobulex covenant enforcement. Uses generic request/response types
 * so it works with Express, Koa, Hono, Fastify, and any Connect-compatible server.
 *
 * **Status: Stable** (promoted from beta in v1.0.0)
 *
 * @packageDocumentation
 */

import type { CovenantDocument } from '@nobulex/core';
import type { EvaluationResult } from '../types.js';

/**
 * Minimal interface for covenant evaluation. NobulexClient satisfies this.
 */
export interface NobulexEvaluator {
  evaluateAction(
    covenant: CovenantDocument,
    action: string,
    resource: string,
  ): Promise<EvaluationResult>;
}

// ─── Generic HTTP types ──────────────────────────────────────────────────────

/**
 * Generic incoming request interface.
 *
 * Compatible with Express, Koa, Hono, Fastify, and Node.js http.IncomingMessage.
 */
export interface IncomingRequest {
  /** HTTP method (GET, POST, PUT, DELETE, etc.). */
  method?: string;
  /** Full URL string. */
  url?: string;
  /** Parsed path component of the URL (Express-style). */
  path?: string;
  /** Request headers. */
  headers?: Record<string, string | string[] | undefined>;
}

/**
 * Generic outgoing response interface.
 *
 * Compatible with Express, Koa, Hono, Fastify, and Node.js http.ServerResponse.
 */
export interface OutgoingResponse {
  /** HTTP status code. */
  statusCode?: number;
  /** Set a response header. */
  setHeader?: (name: string, value: string) => void;
  /** End the response with an optional body. */
  end?: (body?: string) => void;
}

/**
 * Connect/Express-style next function.
 */
export type NextFunction = (err?: unknown) => void;

// ─── Middleware options ──────────────────────────────────────────────────────

/**
 * Options for the nobulexMiddleware factory.
 */
export interface NobulexMiddlewareOptions {
  /** The NobulexClient (or any NobulexEvaluator) instance to use for covenant evaluation. */
  client: NobulexEvaluator;
  /** The covenant document to enforce. */
  covenant: CovenantDocument;
  /**
   * Extract the action string from the incoming request.
   * Defaults to `req.method?.toLowerCase() ?? 'read'`.
   */
  actionExtractor?: (req: IncomingRequest) => string;
  /**
   * Extract the resource string from the incoming request.
   * Defaults to `req.path ?? req.url ?? '/'`.
   */
  resourceExtractor?: (req: IncomingRequest) => string;
  /**
   * Custom handler for denied requests. If not provided, responds
   * with a 403 JSON body.
   */
  onDenied?: (req: IncomingRequest, res: OutgoingResponse, result: EvaluationResult) => void;
  /**
   * Custom handler for errors during evaluation. If not provided,
   * responds with a 500 JSON body.
   */
  onError?: (req: IncomingRequest, res: OutgoingResponse, error: unknown) => void;
}

// ─── Guard handler options ───────────────────────────────────────────────────

/**
 * Options for the nobulexGuardHandler factory.
 */
export interface NobulexGuardHandlerOptions {
  /** The NobulexClient (or any NobulexEvaluator) instance to use for covenant evaluation. */
  client: NobulexEvaluator;
  /** The covenant document to enforce. */
  covenant: CovenantDocument;
  /**
   * Extract the action string from the incoming request.
   * Defaults to `req.method?.toLowerCase() ?? 'read'`.
   */
  actionExtractor?: (req: IncomingRequest) => string;
  /**
   * Extract the resource string from the incoming request.
   * Defaults to `req.path ?? req.url ?? '/'`.
   */
  resourceExtractor?: (req: IncomingRequest) => string;
  /**
   * Custom handler for denied requests. If not provided, responds
   * with a 403 JSON body.
   */
  onDenied?: (req: IncomingRequest, res: OutgoingResponse, result: EvaluationResult) => void;
  /**
   * Custom handler for errors during evaluation. If not provided,
   * responds with a 500 JSON body.
   */
  onError?: (req: IncomingRequest, res: OutgoingResponse, error: unknown) => void;
}

// ─── Router options ──────────────────────────────────────────────────────────

/**
 * Options for the createCovenantRouter factory.
 */
export interface CovenantRouterOptions {
  /** The NobulexClient (or any NobulexEvaluator) instance to use for covenant evaluation. */
  client: NobulexEvaluator;
  /** The covenant document to enforce. */
  covenant: CovenantDocument;
}

// ─── Default extractors ──────────────────────────────────────────────────────

/**
 * Default action extractor: maps HTTP method to a lowercase action string.
 */
function defaultActionExtractor(req: IncomingRequest): string {
  return req.method?.toLowerCase() ?? 'read';
}

/**
 * Default resource extractor: uses the request path or URL.
 */
function defaultResourceExtractor(req: IncomingRequest): string {
  return req.path ?? req.url ?? '/';
}

/**
 * Default denied handler: sends a 403 JSON response.
 */
function defaultOnDenied(
  _req: IncomingRequest,
  res: OutgoingResponse,
  result: EvaluationResult,
): void {
  if (res.statusCode !== undefined) {
    res.statusCode = 403;
  }
  if (res.setHeader) {
    res.setHeader('content-type', 'application/json');
    res.setHeader('x-nobulex-permitted', 'false');
  }
  if (res.end) {
    res.end(JSON.stringify({
      error: 'Forbidden',
      permitted: false,
      reason: result.reason ?? 'Request denied by covenant',
    }));
  }
}

/**
 * Default error handler: sends a 500 JSON response.
 */
function defaultOnError(
  _req: IncomingRequest,
  res: OutgoingResponse,
  error: unknown,
): void {
  if (res.statusCode !== undefined) {
    res.statusCode = 500;
  }
  if (res.setHeader) {
    res.setHeader('content-type', 'application/json');
  }
  if (res.end) {
    res.end(JSON.stringify({
      error: 'Internal Server Error',
      message: error instanceof Error ? error.message : 'Covenant evaluation failed',
    }));
  }
}

// ─── nobulexMiddleware ─────────────────────────────────────────────────────────

/**
 * Connect-compatible middleware factory that enforces a Nobulex covenant
 * on every incoming HTTP request.
 *
 * For each request:
 * - Extracts the action and resource using configurable extractors
 * - Evaluates them against the covenant's CCL constraints
 * - If permitted: sets `x-nobulex-permitted: true` header and calls `next()`
 * - If denied: calls `onDenied` handler (default: 403 JSON response)
 * - On error: calls `onError` handler (default: 500 JSON response)
 *
 * @param options - Middleware configuration options.
 * @returns A Connect-compatible middleware function `(req, res, next) => void`.
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { NobulexClient, nobulexMiddleware } from '@nobulex/sdk';
 *
 * const client = new NobulexClient();
 * const app = express();
 *
 * app.use(nobulexMiddleware({
 *   client,
 *   covenant: myCovenantDoc,
 * }));
 *
 * app.get('/data', (req, res) => {
 *   res.json({ data: 'allowed!' });
 * });
 * ```
 */
export function nobulexMiddleware(
  options: NobulexMiddlewareOptions,
): (req: IncomingRequest, res: OutgoingResponse, next: NextFunction) => void {
  const {
    client,
    covenant,
    actionExtractor = defaultActionExtractor,
    resourceExtractor = defaultResourceExtractor,
    onDenied = defaultOnDenied,
    onError = defaultOnError,
  } = options;

  return (req: IncomingRequest, res: OutgoingResponse, next: NextFunction): void => {
    const action = actionExtractor(req);
    const resource = resourceExtractor(req);

    client
      .evaluateAction(covenant, action, resource)
      .then((result: EvaluationResult) => {
        if (result.permitted) {
          if (res.setHeader) {
            res.setHeader('x-nobulex-permitted', 'true');
          }
          next();
        } else {
          onDenied(req, res, result);
        }
      })
      .catch((error: unknown) => {
        onError(req, res, error);
      });
  };
}

// ─── nobulexGuardHandler ───────────────────────────────────────────────────────

/**
 * Async handler type compatible with any HTTP framework.
 */
export type AsyncHandler = (req: IncomingRequest, res: OutgoingResponse) => Promise<void>;

/**
 * Wraps an async handler with Nobulex covenant enforcement for standalone use
 * (no next function required).
 *
 * Evaluates the request against the covenant before invoking the handler.
 * If denied, the handler is never called and a 403 response is sent.
 *
 * @param options - Guard handler configuration options.
 * @param handler - The async handler to wrap.
 * @returns A new handler function that enforces the covenant before delegation.
 *
 * @example
 * ```typescript
 * const guardedHandler = nobulexGuardHandler(
 *   { client, covenant: myDoc },
 *   async (req, res) => {
 *     res.end(JSON.stringify({ data: 'success' }));
 *   },
 * );
 *
 * // Use with any framework
 * http.createServer(guardedHandler);
 * ```
 */
export function nobulexGuardHandler(
  options: NobulexGuardHandlerOptions,
  handler: AsyncHandler,
): (req: IncomingRequest, res: OutgoingResponse) => Promise<void> {
  const {
    client,
    covenant,
    actionExtractor = defaultActionExtractor,
    resourceExtractor = defaultResourceExtractor,
    onDenied = defaultOnDenied,
    onError = defaultOnError,
  } = options;

  return async (req: IncomingRequest, res: OutgoingResponse): Promise<void> => {
    const action = actionExtractor(req);
    const resource = resourceExtractor(req);

    try {
      const result = await client.evaluateAction(covenant, action, resource);

      if (result.permitted) {
        if (res.setHeader) {
          res.setHeader('x-nobulex-permitted', 'true');
        }
        await handler(req, res);
      } else {
        onDenied(req, res, result);
      }
    } catch (error: unknown) {
      onError(req, res, error);
    }
  };
}

// ─── createCovenantRouter ────────────────────────────────────────────────────

/**
 * A covenant router that provides fine-grained enforcement helpers.
 */
export interface CovenantRouter {
  /**
   * Returns middleware that enforces a specific action/resource pair.
   *
   * Unlike `nobulexMiddleware` which extracts action/resource from the request,
   * this allows you to specify exact values for route-level enforcement.
   *
   * @param action - The action to enforce (e.g., `"read"`, `"write"`).
   * @param resource - The resource to enforce (e.g., `"/data/users"`).
   * @returns A Connect-compatible middleware function.
   *
   * @example
   * ```typescript
   * const router = createCovenantRouter({ client, covenant });
   *
   * app.get('/users', router.protect('read', '/users'), getUsers);
   * app.post('/users', router.protect('write', '/users'), createUser);
   * ```
   */
  protect: (
    action: string,
    resource: string,
  ) => (req: IncomingRequest, res: OutgoingResponse, next: NextFunction) => void;

  /**
   * Evaluates a request against the covenant and returns the result
   * without sending a response.
   *
   * Useful for custom enforcement logic or logging.
   *
   * @param req - The incoming request to evaluate.
   * @returns A promise resolving to the EvaluationResult.
   *
   * @example
   * ```typescript
   * const router = createCovenantRouter({ client, covenant });
   * const result = await router.evaluateRequest(req);
   * if (result.permitted) {
   *   // custom handling
   * }
   * ```
   */
  evaluateRequest: (req: IncomingRequest) => Promise<EvaluationResult>;
}

/**
 * Creates a covenant router with fine-grained enforcement helpers.
 *
 * Provides `.protect(action, resource)` for route-level enforcement and
 * `.evaluateRequest(req)` for programmatic access to evaluation results.
 *
 * @param options - Router configuration options.
 * @returns A CovenantRouter instance.
 *
 * @example
 * ```typescript
 * const router = createCovenantRouter({ client, covenant: myDoc });
 *
 * // Route-level protection
 * app.get('/data', router.protect('read', '/data'), handler);
 *
 * // Programmatic evaluation
 * const result = await router.evaluateRequest(req);
 * ```
 */
export function createCovenantRouter(options: CovenantRouterOptions): CovenantRouter {
  const { client, covenant } = options;

  return {
    protect(
      action: string,
      resource: string,
    ): (req: IncomingRequest, res: OutgoingResponse, next: NextFunction) => void {
      return (_req: IncomingRequest, res: OutgoingResponse, next: NextFunction): void => {
        client
          .evaluateAction(covenant, action, resource)
          .then((result: EvaluationResult) => {
            if (result.permitted) {
              if (res.setHeader) {
                res.setHeader('x-nobulex-permitted', 'true');
              }
              next();
            } else {
              defaultOnDenied(_req, res, result);
            }
          })
          .catch((error: unknown) => {
            defaultOnError(_req, res, error);
          });
      };
    },

    async evaluateRequest(req: IncomingRequest): Promise<EvaluationResult> {
      const action = defaultActionExtractor(req);
      const resource = defaultResourceExtractor(req);
      return client.evaluateAction(covenant, action, resource);
    },
  };
}
