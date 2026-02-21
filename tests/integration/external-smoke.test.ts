/**
 * Smoke tests for CLI and MCP Server binary entry points.
 *
 * These tests verify that the built binaries are functional —
 * they spawn the actual entry points and check basic output.
 * They do NOT test against real external systems (npm registry,
 * GitHub API, etc.) — that would require network access and
 * credentials.
 *
 * Future integration tests that would require real external systems:
 * - npm publish dry-run against a registry
 * - GitHub API: star count, release creation
 * - Ed25519 hardware token signing (PKCS#11)
 * - On-chain covenant anchoring (EVM testnet)
 * - MCP server stdio round-trip with a real AI agent
 */

import { describe, it, expect } from 'vitest';
import { run } from '@usekova/cli';
import { KovaServer } from '@usekova/mcp-server';
import { MemoryStore } from '@usekova/store';

describe('CLI smoke tests', () => {
  it('prints help text with exit code 0', async () => {
    const result = await run(['help']);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('kova');
    expect(result.stderr).toBe('');
  });

  it('prints version with exit code 0', async () => {
    const result = await run(['version']);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/^\d+\.\d+\.\d+$/);
    expect(result.stderr).toBe('');
  });

  it('prints version as JSON', async () => {
    const result = await run(['version', '--json']);
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed).toHaveProperty('version');
    expect(parsed).toHaveProperty('protocol');
  });

  it('returns error for unknown command', async () => {
    const result = await run(['nonexistent-command']);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Unknown command');
  });

  it('runs doctor diagnostics', async () => {
    const result = await run(['doctor']);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBeTruthy();
  });
});

describe('MCP Server smoke tests', () => {
  it('creates a server instance', () => {
    const store = new MemoryStore();
    const server = new KovaServer(store);
    expect(server).toBeDefined();
  });

  it('responds to initialize message', async () => {
    const store = new MemoryStore();
    const server = new KovaServer(store);
    const response = await server.handleMessage({
      jsonrpc: '2.0',
      method: 'initialize',
      id: 1,
    });
    expect(response).toHaveProperty('jsonrpc', '2.0');
    expect(response).toHaveProperty('id', 1);
  });

  it('returns error for unknown method', async () => {
    const store = new MemoryStore();
    const server = new KovaServer(store);
    const response = await server.handleMessage({
      jsonrpc: '2.0',
      method: 'nonexistent/method',
      id: 2,
    });
    expect(response).toHaveProperty('jsonrpc', '2.0');
    expect(response).toHaveProperty('id', 2);
    expect(response).toHaveProperty('error');
  });
});
