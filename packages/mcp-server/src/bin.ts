#!/usr/bin/env node
/**
 * Stele MCP Server — stdio transport.
 *
 * Reads newline-delimited JSON-RPC 2.0 messages from stdin,
 * dispatches them to the SteleServer, and writes responses to stdout.
 *
 * Usage:
 *   npx stele-mcp
 *   echo '{"jsonrpc":"2.0","method":"initialize","id":1}' | npx stele-mcp
 */

import { SteleServer } from './index';
import { MemoryStore } from '@stele/store';
import type { JsonRpcRequest } from './types';

const store = new MemoryStore();
const server = new SteleServer(store);

let buffer = '';

process.stdin.setEncoding('utf8');

process.stdin.on('data', (chunk: string) => {
  buffer += chunk;

  // Process complete lines (newline-delimited JSON-RPC)
  let newlineIndex: number;
  while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, newlineIndex).trim();
    buffer = buffer.slice(newlineIndex + 1);

    if (line.length === 0) continue;

    void processLine(line);
  }
});

process.stdin.on('end', () => {
  // Process any remaining buffer content
  const line = buffer.trim();
  if (line.length > 0) {
    void processLine(line);
  }
});

async function processLine(line: string): Promise<void> {
  try {
    const message = JSON.parse(line) as JsonRpcRequest;
    const response = await server.handleMessage(message);
    process.stdout.write(JSON.stringify(response) + '\n');
  } catch (err) {
    // JSON parse error
    const errorResponse = {
      jsonrpc: '2.0' as const,
      error: {
        code: -32700,
        message: `Parse error: ${err instanceof Error ? err.message : String(err)}`,
      },
      id: null,
    };
    process.stdout.write(JSON.stringify(errorResponse) + '\n');
  }
}

// ─── Graceful shutdown ─────────────────────────────────────────────────────

/** Maximum time (ms) to wait for in-flight requests before force-exiting. */
const SHUTDOWN_TIMEOUT_MS = 5_000;

let shuttingDown = false;

async function gracefulShutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;

  process.stderr.write(`[stele-mcp] Received ${signal}, shutting down gracefully...\n`);

  // Set a hard deadline so we don't hang indefinitely
  const forceExitTimer = setTimeout(() => {
    process.stderr.write('[stele-mcp] Shutdown timeout exceeded, forcing exit.\n');
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);

  // Ensure the timer doesn't keep the event loop alive if cleanup finishes early
  if (forceExitTimer.unref) {
    forceExitTimer.unref();
  }

  try {
    // Stop accepting new input
    process.stdin.destroy();

    // Flush stdout to ensure all pending responses are sent
    await new Promise<void>((resolve) => {
      if (process.stdout.writableFinished) {
        resolve();
      } else {
        process.stdout.once('drain', resolve);
        // If nothing to drain, resolve immediately
        setTimeout(resolve, 100);
      }
    });

    process.stderr.write('[stele-mcp] Cleanup complete.\n');
  } catch (err) {
    process.stderr.write(
      `[stele-mcp] Error during shutdown: ${err instanceof Error ? err.message : String(err)}\n`,
    );
  } finally {
    clearTimeout(forceExitTimer);
    process.exit(0);
  }
}

process.on('SIGINT', () => void gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => void gracefulShutdown('SIGTERM'));
