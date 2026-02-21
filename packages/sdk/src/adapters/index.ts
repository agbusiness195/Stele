/**
 * Framework adapters for the Kova SDK.
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
  kovaMiddleware,
  kovaGuardHandler,
  createCovenantRouter,
} from './express.js';

export type {
  IncomingRequest,
  OutgoingResponse,
  NextFunction,
  KovaMiddlewareOptions,
  KovaGuardHandlerOptions,
  CovenantRouterOptions,
  CovenantRouter,
  AsyncHandler,
} from './express.js';

// ─── Vercel AI SDK adapter (stable) ──────────────────────────────────────────

export {
  KovaAccessDeniedError,
  withKova,
  withKovaTools,
  createToolGuard,
} from './vercel-ai.js';

export type {
  ToolLike,
  KovaToolOptions,
} from './vercel-ai.js';

// ─── LangChain adapter (stable) ──────────────────────────────────────────────

export {
  KovaCallbackHandler,
  withKovaTool,
  createChainGuard,
} from './langchain.js';

export type {
  LangChainToolLike,
  KovaLangChainOptions,
  CallbackEvent,
} from './langchain.js';
