import { describe, it, expect, vi, beforeAll } from 'vitest';
import { generateKeyPair } from '@usekova/crypto';
import type { CovenantDocument } from '@usekova/core';

import { KovaClient } from '../index.js';
import { steleMiddleware, steleGuardHandler, createCovenantRouter } from './express.js';
import type { IncomingRequest, OutgoingResponse, NextFunction } from './express.js';
import { withStele, withSteleTools, createToolGuard, SteleAccessDeniedError } from './vercel-ai.js';
import type { ToolLike } from './vercel-ai.js';
import { SteleCallbackHandler, withSteleTool, createChainGuard } from './langchain.js';
import type { LangChainToolLike } from './langchain.js';

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

let client: KovaClient;
let covenant: CovenantDocument;

beforeAll(async () => {
  client = new KovaClient();
  const kp = await client.generateKeyPair();
  const kp2 = await generateKeyPair();
  covenant = await client.createCovenant({
    issuer: { id: 'test-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
    beneficiary: { id: 'test-beneficiary', publicKey: kp2.publicKeyHex, role: 'beneficiary' },
    constraints: "permit read on '/data/**'\ndeny write on '/system/**'",
  });
});

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function createMockRequest(overrides: Partial<IncomingRequest> = {}): IncomingRequest {
  return {
    method: 'GET',
    url: '/',
    path: '/',
    headers: {},
    ...overrides,
  };
}

function createMockResponse(): OutgoingResponse & {
  _statusCode: number | undefined;
  _headers: Record<string, string>;
  _body: string | undefined;
} {
  const res = {
    _statusCode: undefined as number | undefined,
    _headers: {} as Record<string, string>,
    _body: undefined as string | undefined,
    get statusCode() {
      return this._statusCode;
    },
    set statusCode(v: number | undefined) {
      this._statusCode = v;
    },
    setHeader(name: string, value: string) {
      res._headers[name] = value;
    },
    end(body?: string) {
      res._body = body;
    },
  };
  // Initialize statusCode so the adapter can assign to it
  res._statusCode = 200;
  return res;
}

function createMockNext(): NextFunction & { called: boolean; error: unknown } {
  const fn = ((err?: unknown) => {
    fn.called = true;
    fn.error = err;
  }) as NextFunction & { called: boolean; error: unknown };
  fn.called = false;
  fn.error = undefined;
  return fn;
}

// ===========================================================================
// 1. Express middleware adapter
// ===========================================================================

describe('Express middleware adapter', () => {
  // ── steleMiddleware ─────────────────────────────────────────────────────

  describe('steleMiddleware', () => {
    it('calls next() and sets x-stele-permitted header for permitted requests', async () => {
      const mw = steleMiddleware({
        client,
        covenant,
        actionExtractor: () => 'read',
        resourceExtractor: (req) => req.path ?? '/',
      });
      const req = createMockRequest({ method: 'GET', path: '/data/users' });
      const res = createMockResponse();
      const next = createMockNext();

      mw(req, res, next);

      // The middleware is async internally, wait for microtask queue
      await new Promise((r) => setTimeout(r, 50));

      expect(next.called).toBe(true);
      expect(next.error).toBeUndefined();
      expect(res._headers['x-stele-permitted']).toBe('true');
    });

    it('returns 403 for denied requests', async () => {
      const mw = steleMiddleware({ client, covenant });
      const req = createMockRequest({ method: 'PUT', path: '/system/config' });
      const res = createMockResponse();
      const next = createMockNext();

      // Default action extractor maps method to lowercase, so PUT -> 'put'
      // But the covenant denies 'write' on '/system/**', not 'put'.
      // We need to use a custom extractor or use method 'WRITE'.
      // Actually, let's use a custom actionExtractor to map to 'write'.
      const mw2 = steleMiddleware({
        client,
        covenant,
        actionExtractor: () => 'write',
      });

      mw2(req, res, next);
      await new Promise((r) => setTimeout(r, 50));

      expect(next.called).toBe(false);
      expect(res._statusCode).toBe(403);
      expect(res._headers['x-stele-permitted']).toBe('false');
      expect(res._headers['content-type']).toBe('application/json');

      const body = JSON.parse(res._body!);
      expect(body.error).toBe('Forbidden');
      expect(body.permitted).toBe(false);
    });

    it('uses default action extractor (method.toLowerCase)', async () => {
      // 'get' action on '/data/file' -- should match 'read'? No, the CCL says "permit read on '/data/**'"
      // 'get' won't match 'read' unless the CCL uses wildcards for action.
      // So let's test that the default extractor is producing the method name.
      // A GET on /data/anything with action='get' will be default-deny (no rule matches 'get')
      const mw = steleMiddleware({ client, covenant });
      const req = createMockRequest({ method: 'GET', path: '/data/something' });
      const res = createMockResponse();
      const next = createMockNext();

      mw(req, res, next);
      await new Promise((r) => setTimeout(r, 50));

      // Default deny: action 'get' doesn't match 'read', so denied
      expect(next.called).toBe(false);
      expect(res._statusCode).toBe(403);
    });

    it('uses custom action and resource extractors', async () => {
      const mw = steleMiddleware({
        client,
        covenant,
        actionExtractor: () => 'read',
        resourceExtractor: () => '/data/custom',
      });

      const req = createMockRequest({ method: 'POST', path: '/irrelevant' });
      const res = createMockResponse();
      const next = createMockNext();

      mw(req, res, next);
      await new Promise((r) => setTimeout(r, 50));

      expect(next.called).toBe(true);
      expect(res._headers['x-stele-permitted']).toBe('true');
    });

    it('calls custom onDenied handler instead of default 403', async () => {
      const onDenied = vi.fn();
      const mw = steleMiddleware({
        client,
        covenant,
        actionExtractor: () => 'write',
        resourceExtractor: () => '/system/secrets',
        onDenied,
      });

      const req = createMockRequest();
      const res = createMockResponse();
      const next = createMockNext();

      mw(req, res, next);
      await new Promise((r) => setTimeout(r, 50));

      expect(next.called).toBe(false);
      expect(onDenied).toHaveBeenCalledTimes(1);
      expect(onDenied).toHaveBeenCalledWith(req, res, expect.objectContaining({ permitted: false }));
    });

    it('calls onError handler when evaluation throws', async () => {
      const onError = vi.fn();
      // Create a middleware with a broken client to force an error
      const brokenClient = {
        evaluateAction: () => Promise.reject(new Error('boom')),
      } as unknown as KovaClient;

      const mw = steleMiddleware({
        client: brokenClient,
        covenant,
        onError,
      });

      const req = createMockRequest();
      const res = createMockResponse();
      const next = createMockNext();

      mw(req, res, next);
      await new Promise((r) => setTimeout(r, 50));

      expect(next.called).toBe(false);
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onError).toHaveBeenCalledWith(req, res, expect.any(Error));
    });

    it('default onError handler returns 500 JSON', async () => {
      const brokenClient = {
        evaluateAction: () => Promise.reject(new Error('evaluation failed')),
      } as unknown as KovaClient;

      const mw = steleMiddleware({ client: brokenClient, covenant });
      const req = createMockRequest();
      const res = createMockResponse();
      const next = createMockNext();

      mw(req, res, next);
      await new Promise((r) => setTimeout(r, 50));

      expect(res._statusCode).toBe(500);
      expect(res._headers['content-type']).toBe('application/json');
      const body = JSON.parse(res._body!);
      expect(body.error).toBe('Internal Server Error');
      expect(body.message).toBe('evaluation failed');
    });
  });

  // ── steleGuardHandler ───────────────────────────────────────────────────

  describe('steleGuardHandler', () => {
    it('calls the wrapped handler for permitted requests', async () => {
      const handler = vi.fn(async (_req, res) => {
        res.end?.('ok');
      });

      const guarded = steleGuardHandler(
        {
          client,
          covenant,
          actionExtractor: () => 'read',
          resourceExtractor: () => '/data/report',
        },
        handler,
      );

      const req = createMockRequest();
      const res = createMockResponse();

      await guarded(req, res);

      expect(handler).toHaveBeenCalledTimes(1);
      expect(res._headers['x-stele-permitted']).toBe('true');
    });

    it('blocks the handler and returns 403 for denied requests', async () => {
      const handler = vi.fn();
      const guarded = steleGuardHandler(
        {
          client,
          covenant,
          actionExtractor: () => 'write',
          resourceExtractor: () => '/system/config',
        },
        handler,
      );

      const req = createMockRequest();
      const res = createMockResponse();

      await guarded(req, res);

      expect(handler).not.toHaveBeenCalled();
      expect(res._statusCode).toBe(403);
    });

    it('calls custom onDenied handler for denied requests', async () => {
      const onDenied = vi.fn();
      const handler = vi.fn();
      const guarded = steleGuardHandler(
        {
          client,
          covenant,
          actionExtractor: () => 'write',
          resourceExtractor: () => '/system/config',
          onDenied,
        },
        handler,
      );

      const req = createMockRequest();
      const res = createMockResponse();

      await guarded(req, res);

      expect(handler).not.toHaveBeenCalled();
      expect(onDenied).toHaveBeenCalledWith(req, res, expect.objectContaining({ permitted: false }));
    });

    it('calls onError handler when evaluation throws', async () => {
      const onError = vi.fn();
      const handler = vi.fn();
      const brokenClient = {
        evaluateAction: () => Promise.reject(new Error('fail')),
      } as unknown as KovaClient;

      const guarded = steleGuardHandler(
        { client: brokenClient, covenant, onError },
        handler,
      );

      const req = createMockRequest();
      const res = createMockResponse();

      await guarded(req, res);

      expect(handler).not.toHaveBeenCalled();
      expect(onError).toHaveBeenCalledTimes(1);
    });
  });

  // ── createCovenantRouter ────────────────────────────────────────────────

  describe('createCovenantRouter', () => {
    describe('protect()', () => {
      it('calls next() for a permitted action/resource pair', async () => {
        const router = createCovenantRouter({ client, covenant });
        const mw = router.protect('read', '/data/users');

        const req = createMockRequest();
        const res = createMockResponse();
        const next = createMockNext();

        mw(req, res, next);
        await new Promise((r) => setTimeout(r, 50));

        expect(next.called).toBe(true);
        expect(res._headers['x-stele-permitted']).toBe('true');
      });

      it('returns 403 for a denied action/resource pair', async () => {
        const router = createCovenantRouter({ client, covenant });
        const mw = router.protect('write', '/system/config');

        const req = createMockRequest();
        const res = createMockResponse();
        const next = createMockNext();

        mw(req, res, next);
        await new Promise((r) => setTimeout(r, 50));

        expect(next.called).toBe(false);
        expect(res._statusCode).toBe(403);
        expect(res._headers['x-stele-permitted']).toBe('false');
      });
    });

    describe('evaluateRequest()', () => {
      it('returns evaluation result for the request', async () => {
        const router = createCovenantRouter({ client, covenant });
        const req = createMockRequest({ method: 'read', path: '/data/report' });

        const result = await router.evaluateRequest(req);

        expect(result).toHaveProperty('permitted');
        expect(result.permitted).toBe(true);
      });

      it('returns denied result for disallowed action', async () => {
        const router = createCovenantRouter({ client, covenant });
        const req = createMockRequest({ method: 'write', path: '/system/secrets' });

        const result = await router.evaluateRequest(req);

        expect(result.permitted).toBe(false);
      });
    });
  });
});

// ===========================================================================
// 2. Vercel AI adapter
// ===========================================================================

describe('Vercel AI adapter', () => {
  // ── withStele ───────────────────────────────────────────────────────────

  describe('withStele', () => {
    it('wraps tool execute with covenant enforcement', async () => {
      const tool: ToolLike = {
        name: 'read',
        description: 'Read data',
        execute: vi.fn(async () => 'result'),
      };

      const wrapped = withStele(tool, {
        client,
        covenant,
        resourceFromTool: () => '/data/file',
      });

      expect(wrapped.execute).toBeDefined();
      expect(wrapped.execute).not.toBe(tool.execute);
    });

    it('permits tool execution when action is allowed', async () => {
      const executeFn = vi.fn(async () => 'success');
      const tool: ToolLike = {
        name: 'read',
        execute: executeFn,
      };

      const wrapped = withStele(tool, {
        client,
        covenant,
        actionFromTool: () => 'read',
        resourceFromTool: () => '/data/file',
      });

      const result = await wrapped.execute!('arg1');

      expect(result).toBe('success');
      expect(executeFn).toHaveBeenCalledTimes(1);
    });

    it('throws SteleAccessDeniedError when action is denied', async () => {
      const tool: ToolLike = {
        name: 'write',
        execute: vi.fn(async () => 'should not reach'),
      };

      const wrapped = withStele(tool, {
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/config',
      });

      await expect(wrapped.execute!()).rejects.toThrow(SteleAccessDeniedError);
      expect(tool.execute).not.toHaveBeenCalled();
    });

    it('SteleAccessDeniedError carries evaluationResult', async () => {
      const tool: ToolLike = {
        name: 'write',
        execute: vi.fn(async () => 'nope'),
      };

      const wrapped = withStele(tool, {
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/data',
      });

      try {
        await wrapped.execute!();
        expect.unreachable('should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(SteleAccessDeniedError);
        const denied = err as SteleAccessDeniedError;
        expect(denied.evaluationResult).toBeDefined();
        expect(denied.evaluationResult.permitted).toBe(false);
        expect(denied.name).toBe('SteleAccessDeniedError');
      }
    });

    it('calls custom onDenied handler instead of throwing', async () => {
      const tool: ToolLike = {
        name: 'write',
        execute: vi.fn(async () => 'nope'),
      };

      const onDenied = vi.fn(() => 'custom-denied-result');

      const wrapped = withStele(tool, {
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/files',
        onDenied,
      });

      const result = await wrapped.execute!();

      expect(result).toBe('custom-denied-result');
      expect(onDenied).toHaveBeenCalledTimes(1);
      expect(onDenied).toHaveBeenCalledWith(
        tool,
        expect.objectContaining({ permitted: false }),
      );
      expect(tool.execute).not.toHaveBeenCalled();
    });

    it('returns a copy without wrapping when tool has no execute method', () => {
      const tool: ToolLike = {
        name: 'noop-tool',
        description: 'A tool without execute',
      };

      const wrapped = withStele(tool, { client, covenant });

      expect(wrapped).not.toBe(tool);
      expect(wrapped.execute).toBeUndefined();
      expect(wrapped.name).toBe('noop-tool');
      expect(wrapped.description).toBe('A tool without execute');
    });

    it('uses default action (tool.name) and resource (/tool.name) when no extractors provided', async () => {
      // tool.name = 'read', resource = '/read'. The covenant permits 'read on /data/**'
      // but '/read' does not match '/data/**', so this should be denied by default-deny
      const tool: ToolLike = {
        name: 'read',
        execute: vi.fn(async () => 'result'),
      };

      const wrapped = withStele(tool, { client, covenant });

      // Default resource is '/read' which does not match '/data/**', so denied
      await expect(wrapped.execute!()).rejects.toThrow(SteleAccessDeniedError);
    });
  });

  // ── withSteleTools ──────────────────────────────────────────────────────

  describe('withSteleTools', () => {
    it('wraps an array of tools', async () => {
      const tool1: ToolLike = {
        name: 'reader',
        execute: vi.fn(async () => 'r1'),
      };
      const tool2: ToolLike = {
        name: 'writer',
        execute: vi.fn(async () => 'w1'),
      };

      const opts = {
        client,
        covenant,
        actionFromTool: (t: ToolLike) =>
          t.name === 'reader' ? 'read' : 'write',
        resourceFromTool: (t: ToolLike) =>
          t.name === 'reader' ? '/data/file' : '/system/file',
      };

      const wrapped = withSteleTools([tool1, tool2], opts) as ToolLike[];

      expect(Array.isArray(wrapped)).toBe(true);
      expect(wrapped).toHaveLength(2);

      // reader is permitted (read on /data/**)
      const result1 = await wrapped[0]!.execute!();
      expect(result1).toBe('r1');

      // writer is denied (write on /system/**)
      await expect(wrapped[1]!.execute!()).rejects.toThrow(SteleAccessDeniedError);
    });

    it('wraps a record of tools', async () => {
      const tools: Record<string, ToolLike> = {
        search: {
          name: 'read',
          execute: vi.fn(async () => 'found'),
        },
        delete: {
          name: 'write',
          execute: vi.fn(async () => 'deleted'),
        },
      };

      const opts = {
        client,
        covenant,
        actionFromTool: (t: ToolLike) => t.name ?? 'unknown',
        resourceFromTool: (t: ToolLike) =>
          t.name === 'read' ? '/data/records' : '/system/records',
      };

      const wrapped = withSteleTools(tools, opts) as Record<string, ToolLike>;

      expect(wrapped).toHaveProperty('search');
      expect(wrapped).toHaveProperty('delete');

      // search -> read on /data/records -> permitted
      const result = await wrapped['search']!.execute!();
      expect(result).toBe('found');

      // delete -> write on /system/records -> denied
      await expect(wrapped['delete']!.execute!()).rejects.toThrow(SteleAccessDeniedError);
    });

    it('handles tools without execute in a record', () => {
      const tools: Record<string, ToolLike> = {
        passive: { name: 'passive', description: 'No execute' },
      };

      const wrapped = withSteleTools(tools, { client, covenant }) as Record<string, ToolLike>;

      expect(wrapped['passive']!.execute).toBeUndefined();
      expect(wrapped['passive']!.name).toBe('passive');
    });
  });

  // ── createToolGuard ─────────────────────────────────────────────────────

  describe('createToolGuard', () => {
    it('permits execution through the guard for allowed actions', async () => {
      const guard = createToolGuard({
        client,
        covenant,
        actionFromTool: () => 'read',
        resourceFromTool: () => '/data/report',
      });

      const tool: ToolLike = {
        name: 'read-tool',
        execute: vi.fn(async (...args: unknown[]) => `result:${args[0]}`),
      };

      const result = await guard(tool, 'hello');
      expect(result).toBe('result:hello');
      expect(tool.execute).toHaveBeenCalledTimes(1);
    });

    it('throws SteleAccessDeniedError for denied actions', async () => {
      const guard = createToolGuard({
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/data',
      });

      const tool: ToolLike = {
        name: 'write-tool',
        execute: vi.fn(async () => 'nope'),
      };

      await expect(guard(tool)).rejects.toThrow(SteleAccessDeniedError);
      expect(tool.execute).not.toHaveBeenCalled();
    });

    it('throws Error when tool has no execute method and action is permitted', async () => {
      const guard = createToolGuard({
        client,
        covenant,
        actionFromTool: () => 'read',
        resourceFromTool: () => '/data/file',
      });

      const tool: ToolLike = {
        name: 'no-exec',
      };

      await expect(guard(tool)).rejects.toThrow("Tool 'no-exec' has no execute method");
    });

    it('calls custom onDenied handler instead of throwing', async () => {
      const onDenied = vi.fn(() => 'fallback');
      const guard = createToolGuard({
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/data',
        onDenied,
      });

      const tool: ToolLike = { name: 'guarded' };
      const result = await guard(tool);

      expect(result).toBe('fallback');
      expect(onDenied).toHaveBeenCalledTimes(1);
    });
  });
});

// ===========================================================================
// 3. LangChain adapter
// ===========================================================================

describe('LangChain adapter', () => {
  // ── SteleCallbackHandler ────────────────────────────────────────────────

  describe('SteleCallbackHandler', () => {
    it('records tool:start events', async () => {
      const handler = new SteleCallbackHandler({ client, covenant });

      await handler.handleToolStart({ name: 'search' }, 'query text');

      expect(handler.events).toHaveLength(1);
      expect(handler.events[0]!.type).toBe('tool:start');
      expect(handler.events[0]!.data).toEqual({
        tool: 'search',
        input: 'query text',
      });
      expect(handler.events[0]!.timestamp).toBeDefined();
    });

    it('records tool:end events', async () => {
      const handler = new SteleCallbackHandler({ client, covenant });

      await handler.handleToolEnd({ result: 42 });

      expect(handler.events).toHaveLength(1);
      expect(handler.events[0]!.type).toBe('tool:end');
      expect(handler.events[0]!.data).toEqual({ output: { result: 42 } });
    });

    it('records tool:error events', async () => {
      const handler = new SteleCallbackHandler({ client, covenant });

      await handler.handleToolError(new Error('tool broke'));

      expect(handler.events).toHaveLength(1);
      expect(handler.events[0]!.type).toBe('tool:error');
      expect(handler.events[0]!.data).toEqual({ error: 'tool broke' });
    });

    it('records chain:start events', async () => {
      const handler = new SteleCallbackHandler({ client, covenant });

      await handler.handleChainStart({ name: 'qa-chain' }, { question: 'why?' });

      expect(handler.events).toHaveLength(1);
      expect(handler.events[0]!.type).toBe('chain:start');
      expect(handler.events[0]!.data).toEqual({
        chain: 'qa-chain',
        inputs: { question: 'why?' },
      });
    });

    it('records chain:end events', async () => {
      const handler = new SteleCallbackHandler({ client, covenant });

      await handler.handleChainEnd({ answer: 'because' });

      expect(handler.events).toHaveLength(1);
      expect(handler.events[0]!.type).toBe('chain:end');
      expect(handler.events[0]!.data).toEqual({ outputs: { answer: 'because' } });
    });

    it('records chain:error events', async () => {
      const handler = new SteleCallbackHandler({ client, covenant });

      await handler.handleChainError(new Error('chain crashed'));

      expect(handler.events).toHaveLength(1);
      expect(handler.events[0]!.type).toBe('chain:error');
      expect(handler.events[0]!.data).toEqual({ error: 'chain crashed' });
    });

    it('records all event types in order across multiple calls', async () => {
      const handler = new SteleCallbackHandler({ client, covenant });

      await handler.handleChainStart({ name: 'pipeline' }, 'input');
      await handler.handleToolStart({ name: 'search' }, 'query');
      await handler.handleToolEnd('search-result');
      await handler.handleToolError(new Error('oops'));
      await handler.handleChainEnd('final-output');
      await handler.handleChainError(new Error('chain-fail'));

      expect(handler.events).toHaveLength(6);
      const types = handler.events.map((e) => e.type);
      expect(types).toEqual([
        'chain:start',
        'tool:start',
        'tool:end',
        'tool:error',
        'chain:end',
        'chain:error',
      ]);
    });

    it('stores client and covenant references', () => {
      const handler = new SteleCallbackHandler({ client, covenant });

      expect(handler.client).toBe(client);
      expect(handler.covenant).toBe(covenant);
    });

    it('produces ISO 8601 timestamps', async () => {
      const handler = new SteleCallbackHandler({ client, covenant });
      await handler.handleToolStart({ name: 'ts-test' }, null);

      const ts = handler.events[0]!.timestamp;
      // ISO 8601 date-time pattern
      expect(ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
  });

  // ── withSteleTool ──────────────────────────────────────────────────────

  describe('withSteleTool', () => {
    it('wraps call method with enforcement', async () => {
      const tool: LangChainToolLike = {
        name: 'read',
        call: vi.fn(async (input) => `called:${input}`),
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'read',
        resourceFromTool: () => '/data/file',
      });

      const result = await wrapped.call!('hello');
      expect(result).toBe('called:hello');
    });

    it('wraps invoke method with enforcement', async () => {
      const tool: LangChainToolLike = {
        name: 'read',
        invoke: vi.fn(async (input) => `invoked:${input}`),
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'read',
        resourceFromTool: () => '/data/query',
      });

      const result = await wrapped.invoke!('test');
      expect(result).toBe('invoked:test');
    });

    it('wraps _call method with enforcement', async () => {
      const tool: LangChainToolLike = {
        name: 'read',
        _call: vi.fn(async (input) => `_called:${input}`),
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'read',
        resourceFromTool: () => '/data/internal',
      });

      const result = await wrapped._call!('internal-input');
      expect(result).toBe('_called:internal-input');
    });

    it('wraps all three methods simultaneously', async () => {
      const tool: LangChainToolLike = {
        name: 'read',
        call: vi.fn(async () => 'c'),
        invoke: vi.fn(async () => 'i'),
        _call: vi.fn(async () => '_c'),
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'read',
        resourceFromTool: () => '/data/all',
      });

      expect(await wrapped.call!('x')).toBe('c');
      expect(await wrapped.invoke!('y')).toBe('i');
      expect(await wrapped._call!('z')).toBe('_c');
    });

    it('throws SteleAccessDeniedError on denied call', async () => {
      const tool: LangChainToolLike = {
        name: 'write',
        call: vi.fn(async () => 'nope'),
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/data',
      });

      await expect(wrapped.call!('input')).rejects.toThrow(SteleAccessDeniedError);
      expect(tool.call).not.toHaveBeenCalled();
    });

    it('throws SteleAccessDeniedError on denied invoke', async () => {
      const tool: LangChainToolLike = {
        name: 'write',
        invoke: vi.fn(async () => 'nope'),
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/config',
      });

      await expect(wrapped.invoke!('input')).rejects.toThrow(SteleAccessDeniedError);
      expect(tool.invoke).not.toHaveBeenCalled();
    });

    it('throws SteleAccessDeniedError on denied _call', async () => {
      const tool: LangChainToolLike = {
        name: 'write',
        _call: vi.fn(async () => 'nope'),
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/internal',
      });

      await expect(wrapped._call!('input')).rejects.toThrow(SteleAccessDeniedError);
      expect(tool._call).not.toHaveBeenCalled();
    });

    it('calls custom onDenied handler instead of throwing', async () => {
      const onDenied = vi.fn(() => 'denied-fallback');
      const tool: LangChainToolLike = {
        name: 'write',
        call: vi.fn(async () => 'nope'),
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'write',
        resourceFromTool: () => '/system/file',
        onDenied,
      });

      const result = await wrapped.call!('input');

      expect(result).toBe('denied-fallback');
      expect(onDenied).toHaveBeenCalledWith(
        tool,
        expect.objectContaining({ permitted: false }),
      );
      expect(tool.call).not.toHaveBeenCalled();
    });

    it('uses default action (tool.name) and resource (/tool.name) without extractors', async () => {
      // tool.name = 'read', resource = '/read'. The covenant permits 'read on /data/**'
      // '/read' does not match '/data/**' so this should be denied
      const tool: LangChainToolLike = {
        name: 'read',
        call: vi.fn(async () => 'result'),
      };

      const wrapped = withSteleTool(tool, { client, covenant });

      await expect(wrapped.call!('input')).rejects.toThrow(SteleAccessDeniedError);
    });

    it('does not wrap methods that do not exist on the original tool', () => {
      const tool: LangChainToolLike = {
        name: 'minimal',
      };

      const wrapped = withSteleTool(tool, {
        client,
        covenant,
        actionFromTool: () => 'read',
        resourceFromTool: () => '/data/file',
      });

      expect(wrapped.call).toBeUndefined();
      expect(wrapped.invoke).toBeUndefined();
      expect(wrapped._call).toBeUndefined();
      expect(wrapped.name).toBe('minimal');
    });
  });

  // ── createChainGuard ───────────────────────────────────────────────────

  describe('createChainGuard', () => {
    it('permits execution for allowed chain names', async () => {
      const guard = createChainGuard({ client, covenant });

      const fn = vi.fn(async () => 'chain-result');

      // chainName = 'read', resource = '/read'.
      // '/read' doesn't match '/data/**', so default deny.
      // We need a chain name that maps to a permitted action/resource.
      // createChainGuard uses action = chainName, resource = '/' + chainName
      // So we need the covenant to permit action 'read' on resource matching '/read'
      // But our covenant has 'permit read on /data/**' which won't match '/read'.
      // Let's use a covenant-level permitted pattern. The covenant denies 'write on /system/**'
      // but permits 'read on /data/**'. We need chainName that results in action/resource match.
      // Since action = chainName and resource = '/' + chainName, we'd need e.g. chainName = 'data/file'
      // That gives action = 'data/file' and resource = '/data/file'.
      // But action 'data/file' won't match 'read' in the CCL.
      // Actually, for this test we can create a dedicated guard with custom options
      // to use actionFromTool. But createChainGuard doesn't have actionFromTool the same way.
      // Wait, let me re-read the source... createChainGuard does accept SteleLangChainOptions
      // but ignores actionFromTool and resourceFromTool, hardcoding action=chainName and resource='/'+chainName.
      // Hmm, actually it only uses onDenied from options. Let me re-check.
      // Yes: const action = chainName; const resource = '/' + chainName;
      // So we need a covenant where chainName maps to a permitted action+resource.
      // Our covenant: permit read on '/data/**'. If chainName='read', action='read', resource='/read'.
      // '/read' doesn't match '/data/**'. Default deny.
      // The only way to make this pass is if we have a covenant that's more permissive.
      // But we're stuck with the shared covenant. Let me think...
      // Actually, we can't really use the shared covenant for this directly.
      // But let's verify: maybe default-deny applies and we can just test the deny case.
      // For a permit case, let's create a local covenant.
      const localKp = await client.generateKeyPair();
      const localKp2 = await generateKeyPair();
      const localCovenant = await client.createCovenant({
        issuer: { id: 'chain-issuer', publicKey: localKp.publicKeyHex, role: 'issuer' },
        beneficiary: { id: 'chain-beneficiary', publicKey: localKp2.publicKeyHex, role: 'beneficiary' },
        constraints: "permit read on '/read'",
      });

      const localGuard = createChainGuard({ client, covenant: localCovenant });
      const result = await localGuard('read', 'input', fn);

      expect(result).toBe('chain-result');
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it('throws SteleAccessDeniedError for denied chain names', async () => {
      const guard = createChainGuard({ client, covenant });
      const fn = vi.fn(async () => 'should-not-reach');

      // chainName = 'write', resource = '/write'. Neither matches any permit rule.
      // Also doesn't match deny rule (/system/**). But default deny applies.
      await expect(guard('write', 'input', fn)).rejects.toThrow(SteleAccessDeniedError);
      expect(fn).not.toHaveBeenCalled();
    });

    it('throws SteleAccessDeniedError when chain name triggers explicit deny', async () => {
      // Create a covenant that explicitly denies 'write' on '/write'
      const localKp = await client.generateKeyPair();
      const localKp2 = await generateKeyPair();
      const localCovenant = await client.createCovenant({
        issuer: { id: 'deny-issuer', publicKey: localKp.publicKeyHex, role: 'issuer' },
        beneficiary: { id: 'deny-beneficiary', publicKey: localKp2.publicKeyHex, role: 'beneficiary' },
        constraints: "permit read on '**'\ndeny write on '/write'",
      });

      const guard = createChainGuard({ client, covenant: localCovenant });
      const fn = vi.fn(async () => 'nope');

      await expect(guard('write', 'data', fn)).rejects.toThrow(SteleAccessDeniedError);
      expect(fn).not.toHaveBeenCalled();
    });

    it('calls custom onDenied handler instead of throwing', async () => {
      const onDenied = vi.fn(() => 'chain-fallback');
      const guard = createChainGuard({
        client,
        covenant,
        onDenied,
      });

      const fn = vi.fn(async () => 'nope');
      const result = await guard('write', 'input', fn);

      expect(result).toBe('chain-fallback');
      expect(onDenied).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'write' }),
        expect.objectContaining({ permitted: false }),
      );
      expect(fn).not.toHaveBeenCalled();
    });

    it('passes the chain function result through on permit', async () => {
      const localKp = await client.generateKeyPair();
      const localKp2 = await generateKeyPair();
      const localCovenant = await client.createCovenant({
        issuer: { id: 'pass-issuer', publicKey: localKp.publicKeyHex, role: 'issuer' },
        beneficiary: { id: 'pass-beneficiary', publicKey: localKp2.publicKeyHex, role: 'beneficiary' },
        constraints: "permit summarize on '/summarize'",
      });

      const guard = createChainGuard({ client, covenant: localCovenant });
      const result = await guard('summarize', 'document text', async () => {
        return { summary: 'This is a summary' };
      });

      expect(result).toEqual({ summary: 'This is a summary' });
    });
  });
});
