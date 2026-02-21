/**
 * Framework adapters for the Grith SDK.
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
  grithMiddleware,
  grithGuardHandler,
  createCovenantRouter,
} from './express.js';

export type {
  IncomingRequest,
  OutgoingResponse,
  NextFunction,
  GrithMiddlewareOptions,
  GrithGuardHandlerOptions,
  CovenantRouterOptions,
  CovenantRouter,
  AsyncHandler,
} from './express.js';

// ─── Vercel AI SDK adapter (stable) ──────────────────────────────────────────

export {
  GrithAccessDeniedError,
  withGrith,
  withGrithTools,
  createToolGuard,
} from './vercel-ai.js';

export type {
  ToolLike,
  GrithToolOptions,
} from './vercel-ai.js';

// ─── LangChain adapter (stable) ──────────────────────────────────────────────

export {
  GrithCallbackHandler,
  withGrithTool,
  createChainGuard,
} from './langchain.js';

export type {
  LangChainToolLike,
  GrithLangChainOptions,
  CallbackEvent,
} from './langchain.js';
