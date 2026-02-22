/**
 * Framework adapters for the Nobulex SDK.
 *
 * Re-exports all adapter factories and their associated types for
 * Express/HTTP, Vercel AI SDK, and LangChain integrations.
 *
 * All adapters are **stable** as of v1.0.0.
 *
 * @packageDocumentation
 */

// ─── Express / HTTP adapter (stable) ─────────────────────────────────────────

export {
  nobulexMiddleware,
  nobulexGuardHandler,
  createCovenantRouter,
} from './express.js';

export type {
  IncomingRequest,
  OutgoingResponse,
  NextFunction,
  NobulexMiddlewareOptions,
  NobulexGuardHandlerOptions,
  CovenantRouterOptions,
  CovenantRouter,
  AsyncHandler,
} from './express.js';

// ─── Vercel AI SDK adapter (stable) ──────────────────────────────────────────

export {
  NobulexAccessDeniedError,
  withNobulex,
  withNobulexTools,
  createToolGuard,
} from './vercel-ai.js';

export type {
  ToolLike,
  NobulexToolOptions,
} from './vercel-ai.js';

// ─── LangChain adapter (stable) ──────────────────────────────────────────────

export {
  NobulexCallbackHandler,
  withNobulexTool,
  createChainGuard,
} from './langchain.js';

export type {
  LangChainToolLike,
  NobulexLangChainOptions,
  CallbackEvent,
} from './langchain.js';
