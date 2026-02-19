/**
 * Kova adapter for Vercel AI SDK.
 *
 * Wraps AI SDK tool definitions with covenant enforcement.
 * Before a tool's `execute()` is called, the action/resource pair is
 * evaluated against the covenant's CCL constraints. If denied, a
 * `KovaAccessDeniedError` is thrown (or the custom `onDenied` handler
 * is invoked). If permitted, the original `execute()` runs normally.
 *
 * **Status: Stable** (promoted from beta in v1.0.0)
 *
 * @packageDocumentation
 *
 * @example
 * ```typescript
 * import { KovaClient, withKova, withKovaTools } from '@usekova/sdk';
 *
 * const protectedTool = withKova(myTool, { client, covenant });
 * const protectedTools = withKovaTools({ search, browse }, { client, covenant });
 * ```
 */

import type { KovaClient } from '../index.js';
import type { CovenantDocument } from '@usekova/core';
import type { EvaluationResult } from '../types.js';

// ─── Error ───────────────────────────────────────────────────────────────────

/**
 * Error thrown when a tool call is denied by a Kova covenant.
 *
 * Carries the full `EvaluationResult` so callers can inspect the
 * matched rule, severity, and reason for the denial.
 */
export class KovaAccessDeniedError extends Error {
  /** The evaluation result that triggered the denial. */
  readonly evaluationResult: EvaluationResult;

  constructor(message: string, result: EvaluationResult) {
    super(message);
    this.name = 'KovaAccessDeniedError';
    this.evaluationResult = result;
  }
}

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * Minimal tool shape compatible with the Vercel AI SDK.
 *
 * Only `execute` is required for wrapping; `name` and `description`
 * are used for default action/resource derivation.
 */
export interface ToolLike {
  name?: string;
  description?: string;
  execute?: (...args: unknown[]) => Promise<unknown>;
  [key: string]: unknown;
}

/**
 * Options for wrapping Vercel AI SDK tools with Kova enforcement.
 */
export interface KovaToolOptions {
  /** The KovaClient instance for covenant evaluation. */
  client: KovaClient;
  /** The covenant document whose constraints are enforced. */
  covenant: CovenantDocument;
  /**
   * Custom function to derive the CCL action string from a tool and its args.
   * Defaults to `tool.name ?? 'execute'`.
   */
  actionFromTool?: (tool: ToolLike, args: unknown[]) => string;
  /**
   * Custom function to derive the CCL resource string from a tool and its args.
   * Defaults to `'/' + (tool.name ?? 'unknown')`.
   */
  resourceFromTool?: (tool: ToolLike, args: unknown[]) => string;
  /**
   * Custom handler invoked when a tool call is denied. If provided,
   * its return value is returned instead of throwing. If not provided,
   * a `KovaAccessDeniedError` is thrown.
   */
  onDenied?: (tool: ToolLike, result: EvaluationResult) => unknown;
}

// ─── withKova ───────────────────────────────────────────────────────────────

/**
 * Wrap a single Vercel AI SDK tool with Kova covenant enforcement.
 *
 * Returns a new tool object whose `execute()` evaluates the
 * action/resource against the covenant before delegating to the
 * original implementation.
 *
 * @param tool    - The tool to wrap.
 * @param options - Enforcement options including client and covenant.
 * @returns A new tool with a guarded `execute()` method.
 *
 * @example
 * ```typescript
 * const protectedTool = withKova(myTool, { client, covenant });
 * await protectedTool.execute('arg1'); // throws if denied
 * ```
 */
export function withKova<T extends ToolLike>(tool: T, options: KovaToolOptions): T {
  const { client, covenant, actionFromTool, resourceFromTool, onDenied } = options;

  const originalExecute = tool.execute;
  if (!originalExecute) {
    return { ...tool } as T;
  }

  const wrapped = { ...tool } as T;

  (wrapped as ToolLike).execute = async (...args: unknown[]): Promise<unknown> => {
    const action = actionFromTool
      ? actionFromTool(tool, args)
      : (tool.name ?? 'execute');
    const resource = resourceFromTool
      ? resourceFromTool(tool, args)
      : ('/' + (tool.name ?? 'unknown'));

    const result = await client.evaluateAction(covenant, action, resource);

    if (!result.permitted) {
      if (onDenied) {
        return onDenied(tool, result);
      }
      throw new KovaAccessDeniedError(
        `Action '${action}' on resource '${resource}' denied by covenant`,
        result,
      );
    }

    return originalExecute.apply(tool, args);
  };

  return wrapped;
}

// ─── withKovaTools ──────────────────────────────────────────────────────────

/**
 * Wrap an array of tools with Kova covenant enforcement.
 *
 * @param tools   - Array of tools to wrap.
 * @param options - Enforcement options.
 * @returns A new array of wrapped tools.
 */
export function withKovaTools(
  tools: ToolLike[],
  options: KovaToolOptions,
): ToolLike[];

/**
 * Wrap a record of tools with Kova covenant enforcement.
 *
 * @param tools   - Record of named tools to wrap.
 * @param options - Enforcement options.
 * @returns A new record with the same keys and wrapped tool values.
 */
export function withKovaTools(
  tools: Record<string, ToolLike>,
  options: KovaToolOptions,
): Record<string, ToolLike>;

export function withKovaTools(
  tools: ToolLike[] | Record<string, ToolLike>,
  options: KovaToolOptions,
): ToolLike[] | Record<string, ToolLike> {
  if (Array.isArray(tools)) {
    return tools.map((tool) => withKova(tool, options));
  }

  const wrapped: Record<string, ToolLike> = {};
  for (const [key, tool] of Object.entries(tools)) {
    wrapped[key] = withKova(tool, options);
  }
  return wrapped;
}

// ─── createToolGuard ─────────────────────────────────────────────────────────

/**
 * Create a reusable guard function that enforces a covenant on any tool call.
 *
 * Unlike `withKova` which returns a new tool, `createToolGuard` returns a
 * function you call manually, passing the tool and arguments each time.
 *
 * @param options - Enforcement options.
 * @returns An async function `(tool, ...args) => Promise<unknown>` that
 *          evaluates the covenant and delegates to `tool.execute()`.
 *
 * @example
 * ```typescript
 * const guard = createToolGuard({ client, covenant });
 * const result = await guard(myTool, 'arg1', 'arg2');
 * ```
 */
export function createToolGuard(
  options: KovaToolOptions,
): (tool: ToolLike, ...args: unknown[]) => Promise<unknown> {
  const { client, covenant, actionFromTool, resourceFromTool, onDenied } = options;

  return async (tool: ToolLike, ...args: unknown[]): Promise<unknown> => {
    const action = actionFromTool
      ? actionFromTool(tool, args)
      : (tool.name ?? 'execute');
    const resource = resourceFromTool
      ? resourceFromTool(tool, args)
      : ('/' + (tool.name ?? 'unknown'));

    const result = await client.evaluateAction(covenant, action, resource);

    if (!result.permitted) {
      if (onDenied) {
        return onDenied(tool, result);
      }
      throw new KovaAccessDeniedError(
        `Action '${action}' on resource '${resource}' denied by covenant`,
        result,
      );
    }

    if (!tool.execute) {
      throw new Error(`Tool '${tool.name ?? 'unknown'}' has no execute method`);
    }

    return tool.execute(...args);
  };
}
