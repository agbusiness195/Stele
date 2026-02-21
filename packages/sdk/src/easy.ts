import { buildCovenant, verifyCovenant } from '@grith/core';
import { generateKeyPair } from '@grith/crypto';

// ── Presets ────────────────────────────────────────────────────────────

const PRESETS: Record<string, string> = {
  'no-data-leak': "deny write on '/external/**'",
  'read-only': "permit read on '/**'",
  'budget-cap-100': "limit spending to 100",
  'budget-cap-1000': "limit spending to 1000",
  'budget-cap-10000': "limit spending to 10000",
  'no-external-calls': "deny call on '/external/**'",
  'log-all': "require log on '/**'",
};

// ── Types ──────────────────────────────────────────────────────────────

export interface ProtectOptions {
  /** Human-readable agent name */
  name?: string;
  /** Array of preset names or raw CCL strings */
  rules: string[];
  /** Optional: who benefits from this covenant (e.g. end user ID) */
  for?: string;
}

export interface ProtectedAgent {
  /** The covenant ID */
  id: string;
  /** The full covenant object */
  covenant: any;
  /** Verify this agent's covenant is still valid */
  verify: () => Promise<{ valid: boolean; checks: any[] }>;
  /** The agent's public key (hex) */
  publicKey: string;
}

// ── Main API ───────────────────────────────────────────────────────────

/**
 * Protect an AI agent with behavioral rules in one call.
 *
 * @example
 * ```typescript
 * import { protect } from '@grith/sdk';
 *
 * const agent = await protect({
 *   name: 'my-agent',
 *   rules: ['no-data-leak', 'budget-cap-1000']
 * });
 *
 * console.log(agent.id);           // covenant ID
 * const result = await agent.verify(); // { valid: true, checks: [...] }
 * ```
 */
export async function protect(options: ProtectOptions): Promise<ProtectedAgent> {
  // Auto-generate keys
  const issuerKeys = await generateKeyPair();
  const beneficiaryKeys = await generateKeyPair();

  // Resolve presets to CCL
  const constraints = options.rules
    .map(rule => PRESETS[rule] || rule)
    .join('\n');

  const agentId = options.name || 'agent-' + Date.now();
  const beneficiaryId = options.for || 'user-default';

  // Build the covenant
  const covenant = await buildCovenant({
    issuer: {
      id: agentId,
      publicKey: Buffer.from(issuerKeys.publicKey).toString('hex'),
      role: 'issuer' as const,
    },
    beneficiary: {
      id: beneficiaryId,
      publicKey: Buffer.from(beneficiaryKeys.publicKey).toString('hex'),
      role: 'beneficiary' as const,
    },
    constraints,
    privateKey: issuerKeys.privateKey,
  });

  return {
    id: covenant.id,
    covenant,
    publicKey: Buffer.from(issuerKeys.publicKey).toString('hex'),
    verify: () => verifyCovenant(covenant),
  };
}

/**
 * List all available preset rules.
 */
export function listPresets(): string[] {
  return Object.keys(PRESETS);
}

/**
 * Get the CCL for a preset.
 */
export function getPreset(name: string): string | undefined {
  return PRESETS[name];
}
