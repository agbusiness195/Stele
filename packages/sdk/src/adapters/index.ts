/**
 * Framework adapters for the Kervyx SDK.
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
  kervyxMiddleware,
  kervyxGuardHandler,
  createCovenantRouter,
} from './express.js';

export type {
  IncomingRequest,
  OutgoingResponse,
  NextFunction,
  KervyxMiddlewareOptions,
  KervyxGuardHandlerOptions,
  CovenantRouterOptions,
  CovenantRouter,
  AsyncHandler,
} from './express.js';

// ─── Vercel AI SDK adapter (stable) ──────────────────────────────────────────

export {
  KervyxAccessDeniedError,
  withKervyx,
  withKervyxTools,
  createToolGuard,
} from './vercel-ai.js';

export type {
  ToolLike,
  KervyxToolOptions,
} from './vercel-ai.js';

// ─── LangChain adapter (stable) ──────────────────────────────────────────────

export {
  KervyxCallbackHandler,
  withKervyxTool,
  createChainGuard,
} from './langchain.js';

export type {
  LangChainToolLike,
  KervyxLangChainOptions,
  CallbackEvent,
} from './langchain.js';
