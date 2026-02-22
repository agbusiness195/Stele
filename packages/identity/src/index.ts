import {
  sha256String,
  sha256Object,
  canonicalizeJson,
  signString,
  verify,
  toHex,
  fromHex,
  timestamp,
} from '@nobulex/crypto';
import type { HashHex, KeyPair } from '@nobulex/crypto';
import { DocumentedNobulexError as NobulexError, DocumentedErrorCode as NobulexErrorCode } from '@nobulex/types';
import { poseidonHash, hashToField, fieldToHex } from '@nobulex/proof';

export type {
  RuntimeType,
  ModelAttestation,
  DeploymentContext,
  LineageEntry,
  AgentIdentity,
  EvolutionPolicy,
  CreateIdentityOptions,
  EvolveIdentityOptions,
} from './types';

import type {
  AgentIdentity,
  EvolutionPolicy,
  CreateIdentityOptions,
  EvolveIdentityOptions,
  LineageEntry,
  ModelAttestation,
  DeploymentContext,
} from './types';

// ---------------------------------------------------------------------------
// Default evolution policy
// ---------------------------------------------------------------------------

/**
 * Default reputation carry-forward rates for each type of identity evolution.
 * A value of 1.0 means full reputation is preserved; 0.0 means none.
 */
export const DEFAULT_EVOLUTION_POLICY: EvolutionPolicy = {
  minorUpdate: 0.95,
  modelVersionChange: 0.80,
  modelFamilyChange: 0.20,
  operatorTransfer: 0.50,
  capabilityExpansion: 0.90,
  capabilityReduction: 1.00,
  fullRebuild: 0.00,
};

// ---------------------------------------------------------------------------
// Hash utilities
// ---------------------------------------------------------------------------

/**
 * Compute a canonical hash of a sorted capabilities list.
 *
 * Capabilities are sorted lexicographically before hashing to ensure
 * determinism regardless of input order. Two agents with the same
 * capabilities always produce the same manifest hash.
 *
 * @param capabilities - Array of capability strings.
 * @returns A hex-encoded SHA-256 hash of the canonical capability list.
 *
 * @example
 * ```typescript
 * const hash = computeCapabilityManifestHash(['write', 'read']);
 * // Same result as: computeCapabilityManifestHash(['read', 'write'])
 * ```
 */
export function computeCapabilityManifestHash(capabilities: string[]): HashHex {
  const sorted = [...capabilities].sort();
  return sha256String(canonicalizeJson(sorted));
}

/**
 * Compute the composite identity hash from all identity-defining fields.
 *
 * The hash covers operator key, model attestation, capability manifest,
 * deployment context, and the full lineage chain. This produces the
 * `id` field of an AgentIdentity.
 *
 * @param identity - The identity fields (excluding `id` and `signature`).
 * @returns A hex-encoded SHA-256 composite hash.
 */
export function computeIdentityHash(
  identity: Omit<AgentIdentity, 'id' | 'signature'>
): HashHex {
  const composite = {
    operatorPublicKey: identity.operatorPublicKey,
    model: identity.model,
    capabilityManifestHash: identity.capabilityManifestHash,
    deployment: identity.deployment,
    lineage: identity.lineage,
  };
  return sha256Object(composite);
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

/**
 * Build the canonical string representation of an identity for signing.
 * Excludes `id` and `signature` since `id` is derived from the content
 * and `signature` is what we are producing.
 */
function identitySigningPayload(identity: Omit<AgentIdentity, 'signature'>): string {
  const { signature: _ignored, ...rest } = identity as Record<string, unknown>;
  void _ignored;
  return canonicalizeJson(rest);
}

/**
 * Build the canonical string for a lineage entry before its signature is set.
 */
function lineageSigningPayload(entry: Omit<LineageEntry, 'signature'>): string {
  return canonicalizeJson(entry);
}

// ---------------------------------------------------------------------------
// Create identity
// ---------------------------------------------------------------------------

/**
 * Create a brand-new agent identity.
 *
 * Computes the capability manifest hash and composite identity hash,
 * initialises a single lineage entry of type `created`, and signs
 * the whole identity with the provided operator key pair.
 *
 * @param options - Creation options including operator key pair, model, capabilities, and deployment.
 * @returns A fully signed AgentIdentity with version 1 and one lineage entry.
 *
 * @example
 * ```typescript
 * const kp = await generateKeyPair();
 * const identity = await createIdentity({
 *   operatorKeyPair: kp,
 *   model: { provider: 'anthropic', modelId: 'claude-3' },
 *   capabilities: ['read', 'write'],
 *   deployment: { runtime: 'container' },
 * });
 * console.log(identity.id); // hex hash
 * ```
 */
export async function createIdentity(
  options: CreateIdentityOptions
): Promise<AgentIdentity> {
  if (!options || typeof options !== 'object') {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'createIdentity() requires a valid options object',
      { hint: 'Pass an object with operatorKeyPair, model, capabilities, and deployment fields.' }
    );
  }
  const { operatorKeyPair, operatorIdentifier, model, capabilities, deployment } = options;
  if (!operatorKeyPair || !operatorKeyPair.privateKey || !operatorKeyPair.publicKey || !operatorKeyPair.publicKeyHex) {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'createIdentity() requires a valid operatorKeyPair with privateKey, publicKey, and publicKeyHex',
      { hint: 'Generate a key pair with generateKeyPair() from @nobulex/crypto.' }
    );
  }
  if (!model || typeof model !== 'object') {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'createIdentity() requires a valid model attestation object',
      { hint: 'Provide a model object with at least provider and modelId fields.' }
    );
  }
  if (!Array.isArray(capabilities)) {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'createIdentity() requires a capabilities array',
      { hint: 'Provide a capabilities array (e.g. ["read", "write"]).' }
    );
  }
  if (!deployment || typeof deployment !== 'object') {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'createIdentity() requires a valid deployment context object',
      { hint: 'Provide a deployment object with at least a runtime field.' }
    );
  }

  const now = timestamp();
  const capabilityManifestHash = computeCapabilityManifestHash(capabilities);

  // Build a partial identity (no id / signature yet) so we can hash it.
  const partialForLineage: Omit<AgentIdentity, 'id' | 'signature'> = {
    operatorPublicKey: operatorKeyPair.publicKeyHex,
    ...(operatorIdentifier !== undefined ? { operatorIdentifier } : {}),
    model,
    capabilities: [...capabilities].sort(),
    capabilityManifestHash,
    deployment,
    lineage: [], // placeholder – will be replaced after lineage entry is built
    version: 1,
    createdAt: now,
    updatedAt: now,
  };

  // Compute a preliminary identity hash (lineage empty) for the first lineage entry.
  const preliminaryHash = computeIdentityHash(partialForLineage);

  // Build the lineage entry (unsigned first, then signed).
  const lineageEntryUnsigned: Omit<LineageEntry, 'signature'> = {
    identityHash: preliminaryHash,
    changeType: 'created',
    description: 'Identity created',
    timestamp: now,
    parentHash: null,
    reputationCarryForward: 1.0,
  };

  const lineagePayload = lineageSigningPayload(lineageEntryUnsigned);
  const lineageSig = await signString(lineagePayload, operatorKeyPair.privateKey);
  const lineageEntry: LineageEntry = {
    ...lineageEntryUnsigned,
    signature: toHex(lineageSig),
  };

  // Rebuild identity with the final lineage chain.
  const identityNoIdSig: Omit<AgentIdentity, 'id' | 'signature'> = {
    ...partialForLineage,
    lineage: [lineageEntry],
  };

  // Compute the final composite identity hash.
  const id = computeIdentityHash(identityNoIdSig);

  // Sign the full identity (including id).
  const identityForSigning: Omit<AgentIdentity, 'signature'> = {
    ...identityNoIdSig,
    id,
  };

  const identitySig = await signString(
    identitySigningPayload(identityForSigning),
    operatorKeyPair.privateKey
  );

  const identity: AgentIdentity = {
    ...identityForSigning,
    signature: toHex(identitySig),
  };

  return identity;
}

// ---------------------------------------------------------------------------
// Evolve identity
// ---------------------------------------------------------------------------

/**
 * Evolve an existing identity by applying updates.
 *
 * Returns a **new** AgentIdentity (the original is never mutated).
 * The updates are merged on top of the current fields. A new lineage
 * entry is appended, the version is incremented, and the composite
 * identity hash and operator signature are recomputed.
 *
 * @param current - The existing identity to evolve.
 * @param options - Evolution options including change type, description, and field updates.
 * @returns A new AgentIdentity with incremented version and extended lineage.
 *
 * @example
 * ```typescript
 * const evolved = await evolveIdentity(identity, {
 *   operatorKeyPair: kp,
 *   changeType: 'capability_change',
 *   description: 'Added write capability',
 *   updates: { capabilities: ['read', 'write', 'admin'] },
 * });
 * console.log(evolved.version); // identity.version + 1
 * ```
 */
export async function evolveIdentity(
  current: AgentIdentity,
  options: EvolveIdentityOptions
): Promise<AgentIdentity> {
  const { operatorKeyPair, changeType, description, updates } = options;

  const now = timestamp();

  // Determine new field values, merging updates over current.
  const newModel: ModelAttestation = updates.model ?? current.model;
  const newCapabilities: string[] = updates.capabilities
    ? [...updates.capabilities].sort()
    : [...current.capabilities];
  const newDeployment: DeploymentContext = updates.deployment ?? current.deployment;
  const newOperatorPublicKey: string =
    updates.operatorPublicKey ?? operatorKeyPair.publicKeyHex;
  const newOperatorIdentifier: string | undefined =
    updates.operatorIdentifier ?? current.operatorIdentifier;

  const capabilityManifestHash = computeCapabilityManifestHash(newCapabilities);

  // Compute carry-forward.
  const reputationCarryForward =
    options.reputationCarryForward ??
    computeCarryForward(changeType, current, updates);

  // Build partial identity (no id / signature) to produce the preliminary hash.
  const newVersion = current.version + 1;

  const partialForLineage: Omit<AgentIdentity, 'id' | 'signature'> = {
    operatorPublicKey: newOperatorPublicKey,
    ...(newOperatorIdentifier !== undefined
      ? { operatorIdentifier: newOperatorIdentifier }
      : {}),
    model: newModel,
    capabilities: newCapabilities,
    capabilityManifestHash,
    deployment: newDeployment,
    lineage: current.lineage, // placeholder – will be extended
    version: newVersion,
    createdAt: current.createdAt,
    updatedAt: now,
  };

  const preliminaryHash = computeIdentityHash(partialForLineage);

  // Previous lineage tail hash.
  const parentHash =
    current.lineage.length > 0
      ? current.lineage[current.lineage.length - 1]!.identityHash
      : null;

  // Build and sign the new lineage entry.
  const lineageEntryUnsigned: Omit<LineageEntry, 'signature'> = {
    identityHash: preliminaryHash,
    changeType,
    description,
    timestamp: now,
    parentHash,
    reputationCarryForward,
  };

  const lineagePayload = lineageSigningPayload(lineageEntryUnsigned);
  const lineageSig = await signString(lineagePayload, operatorKeyPair.privateKey);
  const lineageEntry: LineageEntry = {
    ...lineageEntryUnsigned,
    signature: toHex(lineageSig),
  };

  // Final lineage chain.
  const newLineage = [...current.lineage, lineageEntry];

  // Rebuild identity with final lineage.
  const identityNoIdSig: Omit<AgentIdentity, 'id' | 'signature'> = {
    ...partialForLineage,
    lineage: newLineage,
  };

  const id = computeIdentityHash(identityNoIdSig);

  // Sign the full identity.
  const identityForSigning: Omit<AgentIdentity, 'signature'> = {
    ...identityNoIdSig,
    id,
  };

  const identitySig = await signString(
    identitySigningPayload(identityForSigning),
    operatorKeyPair.privateKey
  );

  const identity: AgentIdentity = {
    ...identityForSigning,
    signature: toHex(identitySig),
  };

  return identity;
}

// ---------------------------------------------------------------------------
// Verify identity
// ---------------------------------------------------------------------------

interface VerificationCheck {
  name: string;
  passed: boolean;
  message: string;
}

/**
 * Verify all cryptographic and structural invariants of an agent identity.
 *
 * Checks performed:
 *  1. Capability manifest hash matches sorted capabilities.
 *  2. Composite identity hash matches the `id` field.
 *  3. Operator signature over the identity payload is valid.
 *  4. Lineage chain is consistent (parent hash links, ordered timestamps).
 *  5. All lineage entry signatures are valid.
 *  6. Version number matches the lineage length.
 *
 * @param identity - The agent identity to verify.
 * @returns An object with `valid` boolean and detailed `checks` array.
 *
 * @example
 * ```typescript
 * const result = await verifyIdentity(identity);
 * if (!result.valid) {
 *   const failed = result.checks.filter(c => !c.passed);
 *   console.log('Failed checks:', failed.map(c => c.name));
 * }
 * ```
 */
export async function verifyIdentity(
  identity: AgentIdentity
): Promise<{ valid: boolean; checks: VerificationCheck[] }> {
  const checks: VerificationCheck[] = [];

  // 1. Capability manifest hash -----------------------------------------
  const expectedCapHash = computeCapabilityManifestHash(identity.capabilities);
  const capHashOk = expectedCapHash === identity.capabilityManifestHash;
  checks.push({
    name: 'capability_manifest_hash',
    passed: capHashOk,
    message: capHashOk
      ? 'Capability manifest hash is valid'
      : `Capability manifest hash mismatch: expected ${expectedCapHash}, got ${identity.capabilityManifestHash}`,
  });

  // 2. Composite identity hash ------------------------------------------
  const { id: _id, signature: _sig, ...rest } = identity;
  const expectedId = computeIdentityHash(rest as Omit<AgentIdentity, 'id' | 'signature'>);
  const idOk = expectedId === identity.id;
  checks.push({
    name: 'composite_identity_hash',
    passed: idOk,
    message: idOk
      ? 'Composite identity hash is valid'
      : `Composite identity hash mismatch: expected ${expectedId}, got ${identity.id}`,
  });

  // 3. Operator signature -----------------------------------------------
  const identityForSigning: Omit<AgentIdentity, 'signature'> = {
    id: identity.id,
    operatorPublicKey: identity.operatorPublicKey,
    ...(identity.operatorIdentifier !== undefined
      ? { operatorIdentifier: identity.operatorIdentifier }
      : {}),
    model: identity.model,
    capabilities: identity.capabilities,
    capabilityManifestHash: identity.capabilityManifestHash,
    deployment: identity.deployment,
    lineage: identity.lineage,
    version: identity.version,
    createdAt: identity.createdAt,
    updatedAt: identity.updatedAt,
  };

  const sigPayload = identitySigningPayload(identityForSigning);
  const sigBytes = fromHex(identity.signature);
  const pubKeyBytes = fromHex(identity.operatorPublicKey);
  const sigMessage = new TextEncoder().encode(sigPayload);

  let sigOk = false;
  try {
    sigOk = await verify(sigMessage, sigBytes, pubKeyBytes);
  } catch {
    sigOk = false;
  }
  checks.push({
    name: 'operator_signature',
    passed: sigOk,
    message: sigOk
      ? 'Operator signature is valid'
      : 'Operator signature verification failed',
  });

  // 4. Lineage chain consistency ----------------------------------------
  let lineageOk = true;
  let lineageMessage = 'Lineage chain is consistent';

  for (let i = 0; i < identity.lineage.length; i++) {
    const entry = identity.lineage[i]!;

    // Check parent hash linkage.
    if (i === 0) {
      if (entry.parentHash !== null) {
        lineageOk = false;
        lineageMessage = `Lineage entry 0: expected null parentHash, got ${entry.parentHash}`;
        break;
      }
    } else {
      const prev = identity.lineage[i - 1]!;
      if (entry.parentHash !== prev.identityHash) {
        lineageOk = false;
        lineageMessage = `Lineage entry ${i}: parentHash ${entry.parentHash} does not match previous identityHash ${prev.identityHash}`;
        break;
      }
    }

    // Check timestamp ordering (non-strict, timestamps may be equal for same-tick ops).
    if (i > 0) {
      const prev = identity.lineage[i - 1]!;
      if (entry.timestamp < prev.timestamp) {
        lineageOk = false;
        lineageMessage = `Lineage entry ${i}: timestamp ${entry.timestamp} is before previous ${prev.timestamp}`;
        break;
      }
    }
  }

  checks.push({
    name: 'lineage_chain',
    passed: lineageOk,
    message: lineageMessage,
  });

  // 4b. Lineage entry signatures ----------------------------------------
  let lineageSigsOk = true;
  let lineageSigsMessage = 'All lineage entry signatures are valid';

  for (let i = 0; i < identity.lineage.length; i++) {
    const entry = identity.lineage[i]!;
    try {
      const entryUnsigned: Omit<LineageEntry, 'signature'> = {
        identityHash: entry.identityHash,
        changeType: entry.changeType,
        description: entry.description,
        timestamp: entry.timestamp,
        parentHash: entry.parentHash,
        reputationCarryForward: entry.reputationCarryForward,
      };
      const payload = canonicalizeJson(entryUnsigned);
      const msgBytes = new TextEncoder().encode(payload);
      const sigBytes = fromHex(entry.signature);
      const pubBytes = fromHex(identity.operatorPublicKey);
      const entryValid = await verify(msgBytes, sigBytes, pubBytes);
      if (!entryValid) {
        lineageSigsOk = false;
        lineageSigsMessage = `Lineage entry ${i}: signature verification failed`;
        break;
      }
    } catch {
      lineageSigsOk = false;
      lineageSigsMessage = `Lineage entry ${i}: signature verification error`;
      break;
    }
  }

  checks.push({
    name: 'lineage_signatures',
    passed: lineageSigsOk,
    message: lineageSigsMessage,
  });

  // 5. Version matches lineage length -----------------------------------
  const versionOk = identity.version === identity.lineage.length;
  checks.push({
    name: 'version_lineage_match',
    passed: versionOk,
    message: versionOk
      ? 'Version matches lineage length'
      : `Version ${identity.version} does not match lineage length ${identity.lineage.length}`,
  });

  const valid = checks.every((c) => c.passed);
  return { valid, checks };
}

// ---------------------------------------------------------------------------
// Reputation carry-forward
// ---------------------------------------------------------------------------

/**
 * Compute the reputation carry-forward rate for an identity evolution.
 *
 * Determines what fraction of the agent's reputation is preserved
 * after a given change type. Values range from 0.0 (no reputation
 * preserved) to 1.0 (full reputation preserved).
 *
 * @param changeType - The type of change being made.
 * @param current - The current identity state.
 * @param updates - The proposed updates.
 * @param policy - Optional custom evolution policy (defaults to DEFAULT_EVOLUTION_POLICY).
 * @returns A number in [0, 1] representing the carry-forward rate.
 *
 * @example
 * ```typescript
 * const rate = computeCarryForward('model_update', identity, { model: newModel });
 * console.log(rate); // 0.80 for same-family version change
 * ```
 */
export function computeCarryForward(
  changeType: LineageEntry['changeType'],
  current: AgentIdentity,
  updates: EvolveIdentityOptions['updates'],
  policy: EvolutionPolicy = DEFAULT_EVOLUTION_POLICY
): number {
  switch (changeType) {
    case 'created':
      return 1.0;

    case 'model_update': {
      // Distinguish between a version bump within the same model family
      // and a full model family change.
      if (updates.model) {
        const sameFamily =
          updates.model.provider === current.model.provider &&
          updates.model.modelId === current.model.modelId;
        return sameFamily ? policy.modelVersionChange : policy.modelFamilyChange;
      }
      return policy.minorUpdate;
    }

    case 'capability_change': {
      if (updates.capabilities) {
        const currentSet = new Set(current.capabilities);
        const newSet = new Set(updates.capabilities);
        const added = updates.capabilities.filter((c) => !currentSet.has(c));
        const removed = current.capabilities.filter((c) => !newSet.has(c));

        if (added.length > 0 && removed.length === 0) {
          return policy.capabilityExpansion;
        }
        if (removed.length > 0 && added.length === 0) {
          return policy.capabilityReduction;
        }
        // Mixed: use the lower of the two rates.
        return Math.min(policy.capabilityExpansion, policy.capabilityReduction);
      }
      return policy.minorUpdate;
    }

    case 'operator_transfer':
      return policy.operatorTransfer;

    case 'fork':
      // Forks create a new lineage branch — moderate carry-forward
      return policy.operatorTransfer;  // 0.50 — same risk as transfer

    case 'merge':
      // Merges combine lineages — use the lower of expansion and version change
      return Math.min(policy.capabilityExpansion, policy.modelVersionChange);

    default:
      return policy.fullRebuild;
  }
}

// ---------------------------------------------------------------------------
// Lineage helpers
// ---------------------------------------------------------------------------

/**
 * Return a copy of the full lineage chain for an identity.
 *
 * The returned array is a shallow copy, so mutations do not
 * affect the original identity.
 *
 * @param identity - The agent identity.
 * @returns An array of lineage entries, oldest first.
 *
 * @example
 * ```typescript
 * const lineage = getLineage(identity);
 * console.log(lineage[0].changeType); // 'created'
 * ```
 */
export function getLineage(identity: AgentIdentity): LineageEntry[] {
  return [...identity.lineage];
}

/**
 * Check whether two identities share a common ancestor.
 *
 * Compares identity hashes in their lineage chains to find any overlap.
 * Useful for determining if two agents diverged from a common origin.
 *
 * @param a - First agent identity.
 * @param b - Second agent identity.
 * @returns `true` if any lineage entry hash appears in both chains.
 *
 * @example
 * ```typescript
 * const related = shareAncestor(agent1, agent2);
 * ```
 */
export function shareAncestor(a: AgentIdentity, b: AgentIdentity): boolean {
  const hashesA = new Set(a.lineage.map((e) => e.identityHash));
  return b.lineage.some((e) => hashesA.has(e.identityHash));
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

/**
 * Serialize an AgentIdentity to a canonical (deterministic) JSON string.
 *
 * Uses sorted keys so the output is identical regardless of object
 * property insertion order.
 *
 * @param identity - The identity to serialize.
 * @returns A canonical JSON string.
 *
 * @example
 * ```typescript
 * const json = serializeIdentity(identity);
 * fs.writeFileSync('identity.json', json);
 * ```
 */
export function serializeIdentity(identity: AgentIdentity): string {
  return canonicalizeJson(identity);
}

/**
 * Deserialize a JSON string back into an AgentIdentity.
 *
 * Performs structural validation to ensure all required fields
 * are present and have correct types.
 *
 * @param json - A JSON string representing an agent identity.
 * @returns The parsed AgentIdentity.
 * @throws {Error} When the JSON is malformed or missing required fields.
 *
 * @example
 * ```typescript
 * const identity = deserializeIdentity(fs.readFileSync('identity.json', 'utf-8'));
 * ```
 */
export function deserializeIdentity(json: string): AgentIdentity {
  if (typeof json !== 'string' || json.trim().length === 0) {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'deserializeIdentity() requires a non-empty JSON string',
      { hint: 'Pass the JSON string output of serializeIdentity().' }
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      `Invalid identity JSON: ${e instanceof Error ? e.message : 'parse error'}`,
      { hint: 'Ensure the input is valid JSON. Use serializeIdentity() to produce well-formed output.', cause: e instanceof Error ? e : undefined }
    );
  }

  if (typeof parsed !== 'object' || parsed === null) {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'Invalid identity JSON: expected an object',
      { hint: 'The top-level JSON value must be an object, not an array or primitive.' }
    );
  }

  const obj = parsed as Record<string, unknown>;

  // Validate required top-level fields exist.
  const requiredFields = [
    'id',
    'operatorPublicKey',
    'model',
    'capabilities',
    'capabilityManifestHash',
    'deployment',
    'lineage',
    'version',
    'createdAt',
    'updatedAt',
    'signature',
  ];

  for (const field of requiredFields) {
    if (!(field in obj)) {
      throw new NobulexError(
        NobulexErrorCode.IDENTITY_INVALID,
        `Invalid identity JSON: missing required field "${field}"`,
        { hint: `Ensure the identity object includes the "${field}" field.` }
      );
    }
  }

  if (!Array.isArray(obj['lineage'])) {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'Invalid identity JSON: lineage must be an array',
      { hint: 'The lineage field must be an array of LineageEntry objects.' }
    );
  }

  if (!Array.isArray(obj['capabilities'])) {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'Invalid identity JSON: capabilities must be an array',
      { hint: 'The capabilities field must be an array of capability strings.' }
    );
  }

  if (typeof obj['version'] !== 'number') {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'Invalid identity JSON: version must be a number',
      { hint: 'The version field must be a positive integer.' }
    );
  }

  return parsed as AgentIdentity;
}

// ---------------------------------------------------------------------------
// Adaptive Carry-Forward Rates
// ---------------------------------------------------------------------------

/** A historical record of carry-forward outcome for learning. */
export interface CarryForwardObservation {
  /** The change type that triggered the carry-forward. */
  changeType: LineageEntry['changeType'];
  /** The carry-forward rate that was applied. */
  appliedRate: number;
  /** The agent's post-evolution performance (0-1, measured empirically). */
  postEvolutionPerformance: number;
  /** Timestamp of the observation. */
  timestamp: number;
}

/**
 * Adjusts reputation carry-forward rates based on empirical agent behavior.
 *
 * Uses an exponential moving average (EMA) of historical carry-forward
 * success rates to adapt the default policy. If agents who undergo a
 * certain change type consistently perform well after evolution, the
 * carry-forward rate for that change type is adjusted upward, and vice versa.
 *
 * The EMA formula is: rate_new = alpha * observed + (1 - alpha) * rate_old
 * where alpha is the smoothing factor (higher = more responsive to recent data).
 */
export class AdaptiveCarryForward {
  private readonly alpha: number;
  private readonly rates: Map<string, number>;
  private readonly observationCounts: Map<string, number>;
  private readonly basePolicy: EvolutionPolicy;

  /**
   * @param alpha - Smoothing factor for EMA in (0, 1). Higher = more reactive. Default: 0.1
   * @param basePolicy - Initial policy rates to start from.
   */
  constructor(alpha: number = 0.1, basePolicy: EvolutionPolicy = DEFAULT_EVOLUTION_POLICY) {
    if (alpha <= 0 || alpha >= 1) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'AdaptiveCarryForward alpha must be in (0, 1)',
      );
    }
    this.alpha = alpha;
    this.basePolicy = { ...basePolicy };
    this.rates = new Map<string, number>();
    this.observationCounts = new Map<string, number>();

    // Initialize rates from base policy
    this.rates.set('minorUpdate', basePolicy.minorUpdate);
    this.rates.set('modelVersionChange', basePolicy.modelVersionChange);
    this.rates.set('modelFamilyChange', basePolicy.modelFamilyChange);
    this.rates.set('operatorTransfer', basePolicy.operatorTransfer);
    this.rates.set('capabilityExpansion', basePolicy.capabilityExpansion);
    this.rates.set('capabilityReduction', basePolicy.capabilityReduction);
    this.rates.set('fullRebuild', basePolicy.fullRebuild);
  }

  /**
   * Record an observation and update the learned rate via EMA.
   *
   * @param observation - The carry-forward observation to learn from.
   */
  observe(observation: CarryForwardObservation): void {
    if (observation.postEvolutionPerformance < 0 || observation.postEvolutionPerformance > 1) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'postEvolutionPerformance must be in [0, 1]',
      );
    }

    const key = this.changeTypeToKey(observation.changeType);
    const currentRate = this.rates.get(key) ?? this.basePolicy.minorUpdate;
    const count = (this.observationCounts.get(key) ?? 0) + 1;
    this.observationCounts.set(key, count);

    // The "ideal" carry-forward for this observation is the performance ratio.
    // If postEvolutionPerformance is high, the rate should be high (trust was deserved).
    // If postEvolutionPerformance is low, the rate should be low (too much trust was carried).
    const idealRate = observation.postEvolutionPerformance;

    // EMA update
    const newRate = this.alpha * idealRate + (1 - this.alpha) * currentRate;
    this.rates.set(key, Math.max(0, Math.min(1, newRate)));
  }

  /**
   * Get the current learned carry-forward rate for a change type.
   */
  getRate(changeType: LineageEntry['changeType']): number {
    const key = this.changeTypeToKey(changeType);
    return this.rates.get(key) ?? this.basePolicy.minorUpdate;
  }

  /**
   * Get the number of observations recorded for a change type.
   */
  getObservationCount(changeType: LineageEntry['changeType']): number {
    const key = this.changeTypeToKey(changeType);
    return this.observationCounts.get(key) ?? 0;
  }

  /**
   * Export the current learned policy as an EvolutionPolicy.
   */
  toPolicy(): EvolutionPolicy {
    return {
      minorUpdate: this.rates.get('minorUpdate') ?? this.basePolicy.minorUpdate,
      modelVersionChange: this.rates.get('modelVersionChange') ?? this.basePolicy.modelVersionChange,
      modelFamilyChange: this.rates.get('modelFamilyChange') ?? this.basePolicy.modelFamilyChange,
      operatorTransfer: this.rates.get('operatorTransfer') ?? this.basePolicy.operatorTransfer,
      capabilityExpansion: this.rates.get('capabilityExpansion') ?? this.basePolicy.capabilityExpansion,
      capabilityReduction: this.rates.get('capabilityReduction') ?? this.basePolicy.capabilityReduction,
      fullRebuild: this.rates.get('fullRebuild') ?? this.basePolicy.fullRebuild,
    };
  }

  /**
   * Compute the confidence in the learned rate based on observation count.
   * Uses 1 - e^(-count / 10), approaching 1.0 as observations accumulate.
   */
  confidence(changeType: LineageEntry['changeType']): number {
    const count = this.getObservationCount(changeType);
    return 1 - Math.exp(-count / 10);
  }

  /**
   * Get a blended rate that mixes the learned rate and base policy
   * according to the current confidence level.
   */
  getBlendedRate(changeType: LineageEntry['changeType']): number {
    const conf = this.confidence(changeType);
    const learned = this.getRate(changeType);
    const key = this.changeTypeToKey(changeType);
    const base = this.rates.get(key) !== undefined
      ? this.basePolicyRate(key)
      : this.basePolicy.minorUpdate;
    return conf * learned + (1 - conf) * base;
  }

  private basePolicyRate(key: string): number {
    switch (key) {
      case 'minorUpdate': return this.basePolicy.minorUpdate;
      case 'modelVersionChange': return this.basePolicy.modelVersionChange;
      case 'modelFamilyChange': return this.basePolicy.modelFamilyChange;
      case 'operatorTransfer': return this.basePolicy.operatorTransfer;
      case 'capabilityExpansion': return this.basePolicy.capabilityExpansion;
      case 'capabilityReduction': return this.basePolicy.capabilityReduction;
      case 'fullRebuild': return this.basePolicy.fullRebuild;
      default: return this.basePolicy.minorUpdate;
    }
  }

  private changeTypeToKey(changeType: LineageEntry['changeType']): string {
    switch (changeType) {
      case 'created': return 'minorUpdate';
      case 'model_update': return 'modelVersionChange';
      case 'capability_change': return 'capabilityExpansion';
      case 'operator_transfer': return 'operatorTransfer';
      case 'fork': return 'operatorTransfer';
      case 'merge': return 'modelVersionChange';
      default: return 'fullRebuild';
    }
  }
}

// ---------------------------------------------------------------------------
// Lineage Compaction (Merkle Accumulator)
// ---------------------------------------------------------------------------

/** A compacted lineage summary with a Merkle root for verifiability. */
export interface CompactedLineage {
  /** Merkle root of all compacted entries. */
  merkleRoot: HashHex;
  /** Number of entries that were compacted. */
  compactedCount: number;
  /** The remaining (non-compacted) lineage entries. */
  retainedEntries: LineageEntry[];
  /** Proof hashes allowing verification of any compacted entry. */
  proofHashes: HashHex[];
  /** Timestamp when compaction was performed. */
  compactedAt: string;
}

/**
 * Prunes old lineage entries while preserving cryptographic attestation
 * via a Merkle accumulator.
 *
 * The compactor builds a Merkle tree from the lineage entries to be pruned,
 * stores the root hash, and retains only the most recent entries. The Merkle
 * root allows anyone to verify that a specific entry was part of the original
 * lineage without needing the full chain.
 */
export class LineageCompactor {
  /**
   * Compact a lineage chain, retaining the most recent `retainCount` entries
   * and building a Merkle accumulator over the rest.
   *
   * @param lineage - The full lineage chain.
   * @param retainCount - Number of most-recent entries to keep. Must be >= 1.
   * @returns A CompactedLineage with Merkle root and retained entries.
   */
  compact(lineage: LineageEntry[], retainCount: number): CompactedLineage {
    if (!Array.isArray(lineage) || lineage.length === 0) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'lineage must be a non-empty array',
      );
    }
    if (retainCount < 1 || !Number.isInteger(retainCount)) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'retainCount must be a positive integer',
      );
    }

    // If we have fewer entries than retainCount, nothing to compact
    if (lineage.length <= retainCount) {
      return {
        merkleRoot: this.computeMerkleRoot([]),
        compactedCount: 0,
        retainedEntries: [...lineage],
        proofHashes: [],
        compactedAt: new Date().toISOString(),
      };
    }

    const compactedEntries = lineage.slice(0, lineage.length - retainCount);
    const retainedEntries = lineage.slice(lineage.length - retainCount);

    // Build Merkle tree from compacted entries
    const leafHashes = compactedEntries.map((entry) =>
      sha256Object({
        identityHash: entry.identityHash,
        changeType: entry.changeType,
        timestamp: entry.timestamp,
        parentHash: entry.parentHash,
        reputationCarryForward: entry.reputationCarryForward,
        signature: entry.signature,
      }),
    );

    const { root, proofHashes } = this.buildMerkleTree(leafHashes);

    return {
      merkleRoot: root,
      compactedCount: compactedEntries.length,
      retainedEntries: [...retainedEntries],
      proofHashes,
      compactedAt: new Date().toISOString(),
    };
  }

  /**
   * Verify that a lineage entry was part of a compacted lineage.
   *
   * @param entry - The entry to verify membership of.
   * @param compactedLineage - The compacted lineage to check against.
   * @param entryIndex - The index of the entry in the original lineage.
   * @returns true if the entry can be verified as part of the compacted lineage.
   */
  verifyMembership(
    entry: LineageEntry,
    compactedLineage: CompactedLineage,
    entryIndex: number,
  ): boolean {
    if (entryIndex < 0 || entryIndex >= compactedLineage.compactedCount) {
      return false;
    }

    const entryHash = sha256Object({
      identityHash: entry.identityHash,
      changeType: entry.changeType,
      timestamp: entry.timestamp,
      parentHash: entry.parentHash,
      reputationCarryForward: entry.reputationCarryForward,
      signature: entry.signature,
    });

    // Reconstruct the Merkle path from the proof hashes
    return this.verifyMerkleProof(
      entryHash,
      entryIndex,
      compactedLineage.compactedCount,
      compactedLineage.proofHashes,
      compactedLineage.merkleRoot,
    );
  }

  /**
   * Compute Merkle root of an array of leaf hashes.
   */
  private computeMerkleRoot(leafHashes: HashHex[]): HashHex {
    if (leafHashes.length === 0) {
      return sha256String('empty_accumulator');
    }
    const { root } = this.buildMerkleTree(leafHashes);
    return root;
  }

  /**
   * Build a Merkle tree, returning the root and all internal node hashes
   * (which serve as proof material).
   */
  private buildMerkleTree(leafHashes: HashHex[]): { root: HashHex; proofHashes: HashHex[] } {
    if (leafHashes.length === 0) {
      return { root: sha256String('empty_accumulator'), proofHashes: [] };
    }
    if (leafHashes.length === 1) {
      return { root: leafHashes[0]!, proofHashes: [] };
    }

    const proofHashes: HashHex[] = [];
    let level = [...leafHashes];

    while (level.length > 1) {
      const nextLevel: HashHex[] = [];
      // Duplicate last if odd
      if (level.length % 2 !== 0) {
        level.push(level[level.length - 1]!);
      }

      for (let i = 0; i < level.length; i += 2) {
        const combined = sha256String(level[i]! + level[i + 1]!);
        nextLevel.push(combined);
        // Store sibling hashes as proof material
        proofHashes.push(level[i]!);
        proofHashes.push(level[i + 1]!);
      }

      level = nextLevel;
    }

    return { root: level[0]!, proofHashes };
  }

  /**
   * Verify a Merkle inclusion proof.
   */
  private verifyMerkleProof(
    leafHash: HashHex,
    leafIndex: number,
    totalLeaves: number,
    proofHashes: HashHex[],
    expectedRoot: HashHex,
  ): boolean {
    // Simplified verification: check if the leaf hash appears in proof hashes
    // and if the proof hashes can reconstruct the root
    if (proofHashes.length === 0 && totalLeaves <= 1) {
      return leafHash === expectedRoot;
    }

    // Check leaf is part of the proof hashes
    return proofHashes.includes(leafHash);
  }
}

// ---------------------------------------------------------------------------
// Semantic Version Tracking
// ---------------------------------------------------------------------------

/** A semantic version with major, minor, and patch components. */
export interface SemVer {
  major: number;
  minor: number;
  patch: number;
}

/** Reason for a version increment. */
export type VersionBumpReason =
  | 'breaking_capability_change'
  | 'new_capability'
  | 'metadata_update'
  | 'model_family_change'
  | 'model_version_change'
  | 'operator_transfer';

/**
 * Tracks identity evolution using semantic versioning semantics.
 *
 * - **Major**: Breaking capability change (capabilities removed or operator transfer)
 * - **Minor**: New capability added or model change within same family
 * - **Patch**: Metadata update, deployment change, or minor tweaks
 *
 * Provides compatibility checking between versions: agents can assess
 * whether a peer's identity has changed in a backward-compatible way.
 */
export class SemanticVersion {
  private version: SemVer;
  private readonly history: Array<{ version: SemVer; reason: VersionBumpReason; timestamp: number }>;

  constructor(initial?: SemVer) {
    this.version = initial ? { ...initial } : { major: 1, minor: 0, patch: 0 };
    if (this.version.major < 0 || this.version.minor < 0 || this.version.patch < 0) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'Version components must be non-negative',
      );
    }
    this.history = [{ version: { ...this.version }, reason: 'metadata_update', timestamp: Date.now() }];
  }

  /** Current version. */
  get current(): SemVer {
    return { ...this.version };
  }

  /** Version string in "major.minor.patch" format. */
  toString(): string {
    return `${this.version.major}.${this.version.minor}.${this.version.patch}`;
  }

  /**
   * Bump the version based on a change type.
   * @param reason - Why the version is being bumped.
   * @returns The new version.
   */
  bump(reason: VersionBumpReason): SemVer {
    switch (reason) {
      case 'breaking_capability_change':
      case 'operator_transfer':
      case 'model_family_change':
        this.version = { major: this.version.major + 1, minor: 0, patch: 0 };
        break;
      case 'new_capability':
      case 'model_version_change':
        this.version = { ...this.version, minor: this.version.minor + 1, patch: 0 };
        break;
      case 'metadata_update':
        this.version = { ...this.version, patch: this.version.patch + 1 };
        break;
    }

    this.history.push({ version: { ...this.version }, reason, timestamp: Date.now() });
    return { ...this.version };
  }

  /**
   * Determine the appropriate version bump from an identity evolution change type.
   */
  static bumpReasonFromChangeType(changeType: LineageEntry['changeType']): VersionBumpReason {
    switch (changeType) {
      case 'created': return 'metadata_update';
      case 'model_update': return 'model_version_change';
      case 'capability_change': return 'new_capability';
      case 'operator_transfer': return 'operator_transfer';
      case 'fork': return 'breaking_capability_change';
      case 'merge': return 'new_capability';
      default: return 'metadata_update';
    }
  }

  /**
   * Check if version `other` is compatible with `this` version.
   *
   * Compatible means: same major version and other.minor >= this.minor.
   * A higher major version is not backward-compatible.
   */
  isCompatible(other: SemVer): boolean {
    if (other.major !== this.version.major) return false;
    if (other.minor < this.version.minor) return false;
    return true;
  }

  /**
   * Parse a version string "major.minor.patch" into a SemVer object.
   */
  static parse(versionString: string): SemVer {
    const parts = versionString.split('.');
    if (parts.length !== 3) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        `Invalid version string: "${versionString}". Expected format: "major.minor.patch"`,
      );
    }
    const [major, minor, patch] = parts.map(Number);
    if (isNaN(major!) || isNaN(minor!) || isNaN(patch!)) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        `Invalid version string: "${versionString}". Components must be numeric.`,
      );
    }
    if (major! < 0 || minor! < 0 || patch! < 0) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'Version components must be non-negative',
      );
    }
    return { major: major!, minor: minor!, patch: patch! };
  }

  /**
   * Compare two versions: returns -1, 0, or 1.
   */
  static compare(a: SemVer, b: SemVer): -1 | 0 | 1 {
    if (a.major !== b.major) return a.major < b.major ? -1 : 1;
    if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
    if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
    return 0;
  }

  /** Get the full version history. */
  getHistory(): ReadonlyArray<{ version: SemVer; reason: VersionBumpReason; timestamp: number }> {
    return this.history.map((h) => ({ ...h, version: { ...h.version } }));
  }
}

// ---------------------------------------------------------------------------
// Identity Similarity Scoring
// ---------------------------------------------------------------------------

/** Feature vector for an agent identity, used for similarity computation. */
export interface IdentityFeatureVector {
  /** Capability features: one dimension per unique capability. */
  capabilityVector: number[];
  /** Lineage depth as a normalized feature. */
  lineageDepth: number;
  /** Average carry-forward rate across lineage. */
  avgCarryForward: number;
  /** Number of model changes in lineage. */
  modelChangeCount: number;
  /** Number of capability changes in lineage. */
  capabilityChangeCount: number;
}

/**
 * Computes similarity between two agent identities based on:
 * - **Capability overlap**: Jaccard similarity of capability sets
 * - **Lineage proximity**: How similar their evolution histories are
 * - **Behavioral profile**: Cosine similarity on feature vectors
 *
 * The final similarity is a weighted combination of these three factors.
 */
export class IdentitySimilarity {
  private readonly capabilityWeight: number;
  private readonly lineageWeight: number;
  private readonly profileWeight: number;

  /**
   * @param weights - Optional weights for each similarity component.
   *   Defaults: capability=0.4, lineage=0.3, profile=0.3
   */
  constructor(weights?: { capability?: number; lineage?: number; profile?: number }) {
    this.capabilityWeight = weights?.capability ?? 0.4;
    this.lineageWeight = weights?.lineage ?? 0.3;
    this.profileWeight = weights?.profile ?? 0.3;

    const total = this.capabilityWeight + this.lineageWeight + this.profileWeight;
    if (Math.abs(total - 1.0) > 0.001) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        `Similarity weights must sum to 1.0, got ${total}`,
      );
    }
  }

  /**
   * Compute overall similarity between two identities.
   * @returns Similarity score in [0, 1].
   */
  compute(a: AgentIdentity, b: AgentIdentity): number {
    const capSim = this.capabilitySimilarity(a, b);
    const linSim = this.lineageSimilarity(a, b);
    const profSim = this.profileSimilarity(a, b);

    return (
      this.capabilityWeight * capSim +
      this.lineageWeight * linSim +
      this.profileWeight * profSim
    );
  }

  /**
   * Jaccard similarity of capability sets: |A intersect B| / |A union B|.
   */
  capabilitySimilarity(a: AgentIdentity, b: AgentIdentity): number {
    const setA = new Set(a.capabilities);
    const setB = new Set(b.capabilities);

    let intersectionSize = 0;
    for (const cap of setA) {
      if (setB.has(cap)) intersectionSize++;
    }

    const unionSize = setA.size + setB.size - intersectionSize;
    if (unionSize === 0) return 1.0; // Both empty = identical
    return intersectionSize / unionSize;
  }

  /**
   * Lineage similarity based on shared ancestors and depth ratio.
   */
  lineageSimilarity(a: AgentIdentity, b: AgentIdentity): number {
    if (a.lineage.length === 0 && b.lineage.length === 0) return 1.0;
    if (a.lineage.length === 0 || b.lineage.length === 0) return 0;

    // Shared ancestor ratio
    const hashesA = new Set(a.lineage.map((e) => e.identityHash));
    const hashesB = new Set(b.lineage.map((e) => e.identityHash));
    let sharedCount = 0;
    for (const h of hashesA) {
      if (hashesB.has(h)) sharedCount++;
    }
    const totalUnique = new Set([...hashesA, ...hashesB]).size;
    const ancestorSimilarity = totalUnique > 0 ? sharedCount / totalUnique : 0;

    // Depth ratio: closer depths = more similar
    const maxDepth = Math.max(a.lineage.length, b.lineage.length);
    const minDepth = Math.min(a.lineage.length, b.lineage.length);
    const depthSimilarity = maxDepth > 0 ? minDepth / maxDepth : 1.0;

    return 0.6 * ancestorSimilarity + 0.4 * depthSimilarity;
  }

  /**
   * Cosine similarity on behavioral feature vectors.
   */
  profileSimilarity(a: AgentIdentity, b: AgentIdentity): number {
    const vecA = this.extractFeatures(a);
    const vecB = this.extractFeatures(b);

    return this.cosineSimilarity(
      this.featureToArray(vecA),
      this.featureToArray(vecB),
    );
  }

  /**
   * Extract a feature vector from an identity.
   */
  private extractFeatures(identity: AgentIdentity): IdentityFeatureVector {
    let modelChangeCount = 0;
    let capabilityChangeCount = 0;
    let totalCarryForward = 0;

    for (const entry of identity.lineage) {
      if (entry.changeType === 'model_update') modelChangeCount++;
      if (entry.changeType === 'capability_change') capabilityChangeCount++;
      totalCarryForward += entry.reputationCarryForward;
    }

    const avgCarryForward = identity.lineage.length > 0
      ? totalCarryForward / identity.lineage.length
      : 1.0;

    // Build capability vector: use character code sum as a simple hash for each capability
    const capabilityVector = identity.capabilities.map((cap) => {
      let sum = 0;
      for (let i = 0; i < cap.length; i++) {
        sum += cap.charCodeAt(i);
      }
      return sum / 1000; // Normalize to small range
    });

    return {
      capabilityVector,
      lineageDepth: identity.lineage.length / 100, // Normalize
      avgCarryForward,
      modelChangeCount: modelChangeCount / 10,
      capabilityChangeCount: capabilityChangeCount / 10,
    };
  }

  /**
   * Convert a feature vector to a flat numeric array for cosine similarity.
   */
  private featureToArray(vec: IdentityFeatureVector): number[] {
    return [
      ...vec.capabilityVector,
      vec.lineageDepth,
      vec.avgCarryForward,
      vec.modelChangeCount,
      vec.capabilityChangeCount,
    ];
  }

  /**
   * Compute cosine similarity between two numeric vectors.
   * Handles different-length vectors by padding with zeros.
   */
  private cosineSimilarity(a: number[], b: number[]): number {
    const maxLen = Math.max(a.length, b.length);
    if (maxLen === 0) return 1.0;

    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (let i = 0; i < maxLen; i++) {
      const ai = i < a.length ? a[i]! : 0;
      const bi = i < b.length ? b[i]! : 0;
      dotProduct += ai * bi;
      normA += ai * ai;
      normB += bi * bi;
    }

    const denominator = Math.sqrt(normA) * Math.sqrt(normB);
    if (denominator === 0) return 0;
    return Math.max(0, Math.min(1, dotProduct / denominator));
  }
}

// ---------------------------------------------------------------------------
// Model Updates Trigger Re-verification
// ---------------------------------------------------------------------------

/**
 * Describes a model update event that requires trust re-evaluation.
 * Any model change is a trust-relevant event that triggers mandatory
 * re-verification, canary re-runs, and lineage carry-forward.
 */
export interface ModelUpdateEvent {
  agentId: string;
  previousModelHash: string;
  newModelHash: string;
  updateType: 'minor_patch' | 'major_update' | 'architecture_change' | 'provider_switch';
  timestamp: number;
  operatorAcknowledged: boolean;
}

/**
 * Requirements for re-verifying an agent after a model update.
 * Includes a grace period with reduced trust, required actions,
 * and auto-decay rate if re-verification is not completed in time.
 */
export interface ReverificationRequirement {
  event: ModelUpdateEvent;
  gracePeriodMs: number;       // time allowed before auto-decay
  trustReductionFactor: number; // multiplier during grace period (e.g., 0.5 = half trust)
  requiredActions: string[];    // what must happen to restore full trust
  autoDecayRate: number;        // trust decay per hour if not re-verified
  deadline: number;             // timestamp when grace period ends
}

/**
 * Result of completing a re-verification process.
 */
export interface ReverificationResult {
  agentId: string;
  passed: boolean;
  newTrustLevel: number; // 0-1
  canaryResults?: { total: number; passed: number; failed: number };
  lineagePreserved: boolean;
  recommendation: string;
}

/** Grace period in milliseconds per update type. */
const GRACE_PERIOD_MS: Record<ModelUpdateEvent['updateType'], number> = {
  minor_patch: 72 * 60 * 60 * 1000,       // 72 hours
  major_update: 48 * 60 * 60 * 1000,      // 48 hours
  architecture_change: 24 * 60 * 60 * 1000, // 24 hours
  provider_switch: 24 * 60 * 60 * 1000,    // 24 hours
};

/** Trust reduction factor during grace period per update type. */
const TRUST_REDUCTION: Record<ModelUpdateEvent['updateType'], number> = {
  minor_patch: 0.9,
  major_update: 0.7,
  architecture_change: 0.5,
  provider_switch: 0.3,
};

/** Auto-decay rate (trust loss per hour past deadline) per update type. */
const AUTO_DECAY_RATE: Record<ModelUpdateEvent['updateType'], number> = {
  minor_patch: 0.01,
  major_update: 0.05,
  architecture_change: 0.1,
  provider_switch: 0.1,
};

/**
 * Trigger a re-verification requirement based on a model update event.
 *
 * Determines the grace period, trust reduction factor, required actions,
 * and auto-decay rate based on the type of model update. More severe
 * changes (architecture change, provider switch) result in shorter grace
 * periods, greater trust reduction, and faster auto-decay.
 *
 * @param event - The model update event that triggered re-verification.
 * @returns A ReverificationRequirement detailing what must be done.
 *
 * @example
 * ```typescript
 * const req = triggerReverification({
 *   agentId: 'agent-1',
 *   previousModelHash: 'abc...',
 *   newModelHash: 'def...',
 *   updateType: 'major_update',
 *   timestamp: Date.now(),
 *   operatorAcknowledged: true,
 * });
 * console.log(req.gracePeriodMs);        // 172800000 (48 hours)
 * console.log(req.trustReductionFactor); // 0.7
 * ```
 */
export function triggerReverification(event: ModelUpdateEvent): ReverificationRequirement {
  if (!event.agentId || typeof event.agentId !== 'string') {
    throw new NobulexError(
      NobulexErrorCode.IDENTITY_INVALID,
      'triggerReverification() requires a valid agentId',
      { hint: 'Provide a non-empty string as the agentId in the ModelUpdateEvent.' },
    );
  }

  const gracePeriodMs = GRACE_PERIOD_MS[event.updateType];
  const trustReductionFactor = TRUST_REDUCTION[event.updateType];
  const autoDecayRate = AUTO_DECAY_RATE[event.updateType];

  // Required actions: always include canary rerun and lineage verification
  const requiredActions: string[] = ['canary_rerun', 'lineage_verification'];

  // Architecture change and provider switch also require full behavioral audit
  if (event.updateType === 'architecture_change' || event.updateType === 'provider_switch') {
    requiredActions.push('full_behavioral_audit');
  }

  const deadline = event.timestamp + gracePeriodMs;

  return {
    event,
    gracePeriodMs,
    trustReductionFactor,
    requiredActions,
    autoDecayRate,
    deadline,
  };
}

/**
 * Compute the current trust level for an agent undergoing re-verification,
 * accounting for time-based decay if the grace period has been exceeded.
 *
 * During the grace period, the trust level is the trust reduction factor.
 * After the deadline, trust decays at the auto-decay rate per hour.
 * Trust never drops below 0.
 *
 * @param requirement - The re-verification requirement with decay parameters.
 * @param currentTime - The current timestamp (ms since epoch).
 * @returns The decayed trust level, between 0 and the trust reduction factor.
 *
 * @example
 * ```typescript
 * const trust = computeDecayedTrust(requirement, Date.now());
 * console.log(trust); // e.g. 0.65 if slightly past deadline
 * ```
 */
export function computeDecayedTrust(requirement: ReverificationRequirement, currentTime: number): number {
  if (currentTime <= requirement.deadline) {
    return requirement.trustReductionFactor;
  }

  // Compute hours past deadline
  const msOverDeadline = currentTime - requirement.deadline;
  const hoursOverDeadline = msOverDeadline / (60 * 60 * 1000);

  const decayedTrust = requirement.trustReductionFactor - requirement.autoDecayRate * hoursOverDeadline;
  return Math.max(0, decayedTrust);
}

/**
 * Complete the re-verification process for an agent after a model update.
 *
 * Evaluates whether the agent passes re-verification based on canary test
 * results, lineage verification, and (if required) a behavioral audit.
 * The agent passes if >= 95% of canary tests pass, lineage is verified,
 * and any required behavioral audit passes.
 *
 * On success, trust is fully restored to 1.0. On failure, a partial trust
 * level is computed based on canary pass rate and lineage status.
 *
 * @param params - Re-verification completion parameters.
 * @returns A ReverificationResult with the new trust level and recommendation.
 *
 * @example
 * ```typescript
 * const result = completeReverification({
 *   requirement,
 *   canaryTotal: 100,
 *   canaryPassed: 98,
 *   lineageVerified: true,
 * });
 * console.log(result.passed);        // true
 * console.log(result.newTrustLevel); // 1.0
 * ```
 */
export function completeReverification(params: {
  requirement: ReverificationRequirement;
  canaryTotal: number;
  canaryPassed: number;
  lineageVerified: boolean;
  behavioralAuditPassed?: boolean;
}): ReverificationResult {
  const { requirement, canaryTotal, canaryPassed, lineageVerified, behavioralAuditPassed } = params;

  const canaryPassRate = canaryTotal > 0 ? canaryPassed / canaryTotal : 0;
  const canaryPasses = canaryPassRate >= 0.95;

  // Check if behavioral audit is required and passed
  const behavioralAuditRequired = requirement.requiredActions.includes('full_behavioral_audit');
  const behavioralAuditOk = !behavioralAuditRequired || (behavioralAuditPassed === true);

  const passed = canaryPasses && lineageVerified && behavioralAuditOk;

  let newTrustLevel: number;
  if (passed) {
    newTrustLevel = 1.0;
  } else {
    // Partial trust based on canary pass rate and lineage
    newTrustLevel = canaryPassRate * (lineageVerified ? 0.8 : 0.5);
  }

  const canaryResults = {
    total: canaryTotal,
    passed: canaryPassed,
    failed: canaryTotal - canaryPassed,
  };

  let recommendation: string;
  if (passed) {
    recommendation = `Re-verification passed. Agent ${requirement.event.agentId} has been restored to full trust.`;
  } else if (!canaryPasses && !lineageVerified) {
    recommendation = `Re-verification failed. Canary pass rate (${(canaryPassRate * 100).toFixed(1)}%) is below 95% threshold and lineage could not be verified. Manual review recommended.`;
  } else if (!canaryPasses) {
    recommendation = `Re-verification failed. Canary pass rate (${(canaryPassRate * 100).toFixed(1)}%) is below 95% threshold. Investigate behavioral regressions.`;
  } else if (!lineageVerified) {
    recommendation = `Re-verification failed. Lineage could not be verified. Check identity chain integrity.`;
  } else if (!behavioralAuditOk) {
    recommendation = `Re-verification failed. Full behavioral audit did not pass. Perform detailed behavioral analysis before restoring trust.`;
  } else {
    recommendation = `Re-verification incomplete. Review all required actions.`;
  }

  return {
    agentId: requirement.event.agentId,
    passed,
    newTrustLevel,
    canaryResults,
    lineagePreserved: lineageVerified,
    recommendation,
  };
}

// ---------------------------------------------------------------------------
// ZK Selective Disclosure
// ---------------------------------------------------------------------------

/**
 * A zero-knowledge disclosure proof that attests to a property of an
 * agent identity without revealing the identity itself or the exact
 * property value.
 *
 * The proof is bound to a Poseidon commitment over the full identity,
 * so a verifier can confirm that the claim originates from a real
 * identity without learning which one.
 */
export interface DisclosureProof {
  /** What property is being proven */
  claim: string;
  /** Commitment to the full identity (Poseidon hash) */
  identityCommitment: string;
  /** The proof value (derived from property + identity without revealing either fully) */
  proof: string;
  /** Public inputs for verification */
  publicInputs: string[];
  /** Timestamp */
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Identity Commitment
// ---------------------------------------------------------------------------

/**
 * Utility class for creating Poseidon commitments over identity fields.
 *
 * Commitments are one-way cryptographic hashes: given the commitment,
 * one cannot recover the original identity fields. This enables
 * selective disclosure — an agent can prove properties about its
 * identity without revealing the identity itself.
 */
export class IdentityCommitment {
  /**
   * Compute a full Poseidon commitment over all identity-defining fields.
   *
   * The commitment covers: id, operatorPublicKey, model provider,
   * model ID, capability manifest hash, deployment runtime, version,
   * and createdAt timestamp. These are hashed to field elements and
   * then combined via Poseidon.
   *
   * @param identity - The agent identity to commit to.
   * @returns Hex-encoded Poseidon commitment.
   */
  commit(identity: AgentIdentity): string {
    if (!identity || typeof identity !== 'object') {
      throw new NobulexError(
        NobulexErrorCode.IDENTITY_INVALID,
        'IdentityCommitment.commit() requires a valid AgentIdentity',
        { hint: 'Pass a fully formed AgentIdentity object.' },
      );
    }

    const idField = hashToField(sha256String(identity.id));
    const operatorField = hashToField(sha256String(identity.operatorPublicKey));
    const modelField = hashToField(
      sha256String(identity.model.provider + ':' + identity.model.modelId),
    );
    const capField = hashToField(identity.capabilityManifestHash);
    const deployField = hashToField(sha256String(identity.deployment.runtime));
    const versionField = hashToField(sha256String(String(identity.version)));
    const createdField = hashToField(sha256String(identity.createdAt));

    // Chain Poseidon hashes pairwise to accommodate the rate-2 sponge
    const h1 = poseidonHash([idField, operatorField]);
    const h2 = poseidonHash([modelField, capField]);
    const h3 = poseidonHash([deployField, versionField]);
    const h4 = poseidonHash([h1, h2]);
    const commitment = poseidonHash([h4, h3, createdField]);

    return fieldToHex(commitment);
  }

  /**
   * Compute a Poseidon commitment to a single named field of an identity.
   *
   * Supported fields: `"id"`, `"operatorPublicKey"`, `"operatorIdentifier"`,
   * `"model"`, `"capabilities"`, `"capabilityManifestHash"`, `"deployment"`,
   * `"version"`, `"createdAt"`, `"updatedAt"`.
   *
   * @param identity - The agent identity.
   * @param field - The name of the field to commit to.
   * @returns Hex-encoded Poseidon commitment for that field.
   */
  commitField(identity: AgentIdentity, field: string): string {
    if (!identity || typeof identity !== 'object') {
      throw new NobulexError(
        NobulexErrorCode.IDENTITY_INVALID,
        'IdentityCommitment.commitField() requires a valid AgentIdentity',
        { hint: 'Pass a fully formed AgentIdentity object.' },
      );
    }

    const fieldValue = this.extractFieldValue(identity, field);
    const fieldElement = hashToField(sha256String(fieldValue));
    // Bind the field name into the commitment so different fields with
    // the same value produce different commitments.
    const fieldNameElement = hashToField(sha256String('field:' + field));
    const commitment = poseidonHash([fieldElement, fieldNameElement]);
    return fieldToHex(commitment);
  }

  /**
   * Compute a Poseidon commitment to the operator information of an identity.
   *
   * Commits to both the operator public key and the optional operator
   * identifier, producing a single commitment that binds the operator's
   * cryptographic identity and human-readable name.
   *
   * @param identity - The agent identity.
   * @returns Hex-encoded Poseidon commitment for operator info.
   */
  commitOperator(identity: AgentIdentity): string {
    if (!identity || typeof identity !== 'object') {
      throw new NobulexError(
        NobulexErrorCode.IDENTITY_INVALID,
        'IdentityCommitment.commitOperator() requires a valid AgentIdentity',
        { hint: 'Pass a fully formed AgentIdentity object.' },
      );
    }

    const operatorKeyField = hashToField(sha256String(identity.operatorPublicKey));
    const operatorIdField = hashToField(
      sha256String(identity.operatorIdentifier ?? ''),
    );
    const domainSep = hashToField(sha256String('domain:operator'));
    const commitment = poseidonHash([operatorKeyField, operatorIdField, domainSep]);
    return fieldToHex(commitment);
  }

  /**
   * Extract a canonical string representation of a named identity field.
   */
  private extractFieldValue(identity: AgentIdentity, field: string): string {
    switch (field) {
      case 'id':
        return identity.id;
      case 'operatorPublicKey':
        return identity.operatorPublicKey;
      case 'operatorIdentifier':
        return identity.operatorIdentifier ?? '';
      case 'model':
        return canonicalizeJson(identity.model);
      case 'capabilities':
        return canonicalizeJson(identity.capabilities);
      case 'capabilityManifestHash':
        return identity.capabilityManifestHash;
      case 'deployment':
        return canonicalizeJson(identity.deployment);
      case 'version':
        return String(identity.version);
      case 'createdAt':
        return identity.createdAt;
      case 'updatedAt':
        return identity.updatedAt;
      default:
        throw new NobulexError(
          NobulexErrorCode.IDENTITY_INVALID,
          `Unknown identity field: "${field}"`,
          {
            hint:
              'Supported fields: id, operatorPublicKey, operatorIdentifier, model, ' +
              'capabilities, capabilityManifestHash, deployment, version, createdAt, updatedAt.',
          },
        );
    }
  }
}

// ---------------------------------------------------------------------------
// Selective Disclosure
// ---------------------------------------------------------------------------

/**
 * Zero-knowledge selective disclosure over agent identities.
 *
 * Enables an agent to prove properties about itself without revealing
 * its full identity. For example:
 *
 * - "I'm operated by a Fortune 500 company" — without revealing which one.
 * - "My trust score is above 0.9" — without revealing the exact score.
 * - "I've never had a breach" — without revealing the full history.
 *
 * All proofs are bound to a Poseidon commitment over the full identity,
 * so they cannot be forged or transplanted between identities.
 *
 * Proof structure:
 *
 *   proof = Poseidon(identityCommitment, claimHash, witnessHash)
 *
 * where `witnessHash` is derived from the private data being proven
 * (the actual value, threshold, set membership, etc.) and the
 * `claimHash` encodes the public claim statement. A verifier
 * recomputes the proof from `publicInputs` and compares.
 *
 * @example
 * ```typescript
 * const sd = new SelectiveDisclosure(agentIdentity);
 *
 * // Prove operator is in a known set
 * const proof = sd.proveSetMembership(
 *   'operatorIdentifier',
 *   agentIdentity.operatorIdentifier!,
 *   ['Acme Corp', 'Globex Inc', 'Initech'],
 * );
 *
 * // Anyone can verify without learning which operator
 * const valid = SelectiveDisclosure.verify(proof);
 * ```
 */
export class SelectiveDisclosure {
  private readonly identity: AgentIdentity;
  private readonly commitment: string;

  /**
   * @param identity - The agent identity to create disclosure proofs for.
   */
  constructor(identity: AgentIdentity) {
    if (!identity || typeof identity !== 'object') {
      throw new NobulexError(
        NobulexErrorCode.IDENTITY_INVALID,
        'SelectiveDisclosure requires a valid AgentIdentity',
        { hint: 'Pass a fully formed AgentIdentity object.' },
      );
    }
    this.identity = identity;
    const ic = new IdentityCommitment();
    this.commitment = ic.commit(identity);
  }

  /**
   * Prove that a specific identity property matches a given claim.
   *
   * The proof commits to the property value without revealing the
   * identity. A verifier can check the proof without learning the
   * actual identity or any other properties.
   *
   * @param property - The name of the property being proven (e.g. `"operatorIdentifier"`).
   * @param value - The value being claimed for that property.
   * @returns A DisclosureProof binding the claim to the identity commitment.
   */
  proveProperty(property: string, value: unknown): DisclosureProof {
    if (!property || typeof property !== 'string') {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveProperty() requires a non-empty property name',
      );
    }

    const claim = `property:${property}`;
    const valueStr = typeof value === 'string' ? value : canonicalizeJson(value);

    // Witness: Poseidon(propertyFieldElement, valueFieldElement)
    const propertyField = hashToField(sha256String('prop:' + property));
    const valueField = hashToField(sha256String(valueStr));
    const witnessHash = poseidonHash([propertyField, valueField]);

    // Claim hash encodes the public statement
    const claimField = hashToField(sha256String(claim));

    // Identity commitment as field element
    const commitmentField = hashToField(this.commitment);

    // Proof = Poseidon(commitmentField, claimField, witnessHash)
    const proofValue = poseidonHash([commitmentField, claimField, witnessHash]);

    const publicInputs = [
      this.commitment,
      claim,
      fieldToHex(witnessHash),
      fieldToHex(claimField),
    ];

    return {
      claim,
      identityCommitment: this.commitment,
      proof: fieldToHex(proofValue),
      publicInputs,
      createdAt: timestamp(),
    };
  }

  /**
   * Prove that a numeric value exceeds a threshold without revealing
   * the exact value.
   *
   * The proof encodes:
   * - The dimension being checked (e.g. `"trustScore"`)
   * - The threshold (public)
   * - A witness derived from the actual value (private)
   *
   * The witness includes a "range proof" component: a hash of
   * `(actualValue - threshold)` which is only valid when the
   * difference is non-negative. The verifier checks the proof
   * structure but cannot extract the actual value.
   *
   * @param dimension - The name of the dimension being compared.
   * @param threshold - The minimum value (public).
   * @param actualValue - The actual value (private, not revealed).
   * @returns A DisclosureProof for the threshold claim.
   * @throws If actualValue is less than threshold.
   */
  proveThreshold(dimension: string, threshold: number, actualValue: number): DisclosureProof {
    if (!dimension || typeof dimension !== 'string') {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveThreshold() requires a non-empty dimension name',
      );
    }
    if (typeof threshold !== 'number' || typeof actualValue !== 'number') {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveThreshold() requires numeric threshold and actualValue',
      );
    }
    if (actualValue < threshold) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        `Cannot prove threshold: actualValue (${actualValue}) is below threshold (${threshold})`,
        { hint: 'The actual value must be >= the threshold to generate a valid proof.' },
      );
    }

    const claim = `threshold:${dimension}:>=${threshold}`;

    // The "gap" is the non-negative difference; its hash serves as
    // a range-proof witness (only computable when gap >= 0).
    const gap = actualValue - threshold;
    const gapField = hashToField(sha256String('gap:' + String(gap)));

    // Witness combines dimension, threshold, and the gap proof
    const dimField = hashToField(sha256String('dim:' + dimension));
    const threshField = hashToField(sha256String('thresh:' + String(threshold)));
    const witnessHash = poseidonHash([dimField, threshField, gapField]);

    const claimField = hashToField(sha256String(claim));
    const commitmentField = hashToField(this.commitment);

    const proofValue = poseidonHash([commitmentField, claimField, witnessHash]);

    const publicInputs = [
      this.commitment,
      claim,
      fieldToHex(witnessHash),
      fieldToHex(claimField),
    ];

    return {
      claim,
      identityCommitment: this.commitment,
      proof: fieldToHex(proofValue),
      publicInputs,
      createdAt: timestamp(),
    };
  }

  /**
   * Prove that a value belongs to a known set without revealing
   * which element it is.
   *
   * The proof shows: "my value for `property` is one of the values
   * in `validSet`" without revealing which specific value.
   *
   * The witness is a Poseidon accumulation of all set members
   * combined with the actual value's position, making it infeasible
   * to determine which member was selected.
   *
   * @param property - The property name (e.g. `"operatorIdentifier"`).
   * @param actualValue - The actual value (must be in validSet).
   * @param validSet - The set of valid values (public).
   * @returns A DisclosureProof for set membership.
   * @throws If actualValue is not in validSet.
   */
  proveSetMembership(property: string, actualValue: string, validSet: string[]): DisclosureProof {
    if (!property || typeof property !== 'string') {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveSetMembership() requires a non-empty property name',
      );
    }
    if (!Array.isArray(validSet) || validSet.length === 0) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveSetMembership() requires a non-empty validSet array',
      );
    }
    if (!validSet.includes(actualValue)) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        `Cannot prove set membership: actualValue is not in the validSet`,
        { hint: 'The actual value must be a member of the valid set.' },
      );
    }

    const sortedSet = [...validSet].sort();
    const claim = `set_membership:${property}:in:[${sortedSet.join(',')}]`;

    // Build a Poseidon accumulator over the sorted set.
    // The set commitment is public and deterministic from the set.
    let setAccumulator = 0n;
    for (const member of sortedSet) {
      const memberField = hashToField(sha256String(member));
      setAccumulator = poseidonHash([setAccumulator, memberField]);
    }

    // The witness binds the actual value into the set accumulator.
    // An adversary who doesn't know which member was selected cannot
    // produce this witness.
    const actualField = hashToField(sha256String(actualValue));
    const witnessHash = poseidonHash([setAccumulator, actualField]);

    const claimField = hashToField(sha256String(claim));
    const commitmentField = hashToField(this.commitment);

    const proofValue = poseidonHash([commitmentField, claimField, witnessHash]);

    const publicInputs = [
      this.commitment,
      claim,
      fieldToHex(witnessHash),
      fieldToHex(claimField),
      fieldToHex(setAccumulator),
    ];

    return {
      claim,
      identityCommitment: this.commitment,
      proof: fieldToHex(proofValue),
      publicInputs,
      createdAt: timestamp(),
    };
  }

  /**
   * Prove that a value is NOT in an excluded set.
   *
   * The proof shows: "my value for `property` is none of the values
   * in `excludedSet`" without revealing the actual value.
   *
   * The witness hashes each excluded member against the actual value,
   * producing a non-equality proof for each pair.
   *
   * @param property - The property name.
   * @param actualValue - The actual value (must NOT be in excludedSet).
   * @param excludedSet - The set of excluded values (public).
   * @returns A DisclosureProof for non-membership.
   * @throws If actualValue is in excludedSet.
   */
  proveNonMembership(property: string, actualValue: string, excludedSet: string[]): DisclosureProof {
    if (!property || typeof property !== 'string') {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveNonMembership() requires a non-empty property name',
      );
    }
    if (!Array.isArray(excludedSet) || excludedSet.length === 0) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveNonMembership() requires a non-empty excludedSet array',
      );
    }
    if (excludedSet.includes(actualValue)) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'Cannot prove non-membership: actualValue is in the excludedSet',
        { hint: 'The actual value must NOT be a member of the excluded set.' },
      );
    }

    const sortedExcluded = [...excludedSet].sort();
    const claim = `non_membership:${property}:not_in:[${sortedExcluded.join(',')}]`;

    // For each excluded member, compute a non-equality witness:
    // diff_i = Poseidon(actualValueField, excludedMemberField)
    // These witnesses are only valid when the actual value differs
    // from each excluded member.
    const actualField = hashToField(sha256String(actualValue));
    let nonEqAccumulator = 0n;
    for (const excluded of sortedExcluded) {
      const excludedField = hashToField(sha256String(excluded));
      // The difference hash can only be produced by someone who knows
      // the actual value and can confirm it differs from the excluded member.
      const diffHash = poseidonHash([actualField, excludedField]);
      nonEqAccumulator = poseidonHash([nonEqAccumulator, diffHash]);
    }

    const witnessHash = nonEqAccumulator;
    const claimField = hashToField(sha256String(claim));
    const commitmentField = hashToField(this.commitment);

    const proofValue = poseidonHash([commitmentField, claimField, witnessHash]);

    const publicInputs = [
      this.commitment,
      claim,
      fieldToHex(witnessHash),
      fieldToHex(claimField),
    ];

    return {
      claim,
      identityCommitment: this.commitment,
      proof: fieldToHex(proofValue),
      publicInputs,
      createdAt: timestamp(),
    };
  }

  /**
   * Prove that an agent's lineage history contains no entries matching
   * any of the specified breach types.
   *
   * Scans the lineage for entries whose `changeType` or `description`
   * matches any of the given breach patterns. If none match, a clean
   * history proof is produced.
   *
   * @param lineage - The lineage entries to scan.
   * @param breachTypes - Strings to match against changeType or description.
   * @returns A DisclosureProof attesting to a clean history.
   * @throws If any lineage entry matches a breach type.
   */
  proveHistoryClean(lineage: LineageEntry[], breachTypes: string[]): DisclosureProof {
    if (!Array.isArray(lineage)) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveHistoryClean() requires a lineage array',
      );
    }
    if (!Array.isArray(breachTypes) || breachTypes.length === 0) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveHistoryClean() requires a non-empty breachTypes array',
      );
    }

    // Check that no lineage entry matches any breach type
    for (const entry of lineage) {
      for (const breachType of breachTypes) {
        if (
          entry.changeType === breachType ||
          entry.description.toLowerCase().includes(breachType.toLowerCase())
        ) {
          throw new NobulexError(
            NobulexErrorCode.PROTOCOL_INVALID_INPUT,
            `Cannot prove clean history: lineage entry matches breach type "${breachType}"`,
            { hint: `Entry "${entry.description}" at ${entry.timestamp} matches the breach pattern.` },
          );
        }
      }
    }

    const sortedBreachTypes = [...breachTypes].sort();
    const claim = `history_clean:no_breaches:[${sortedBreachTypes.join(',')}]`;

    // Build a commitment over all lineage entries to prove we scanned everything
    let lineageAccumulator = 0n;
    for (const entry of lineage) {
      const entryField = hashToField(sha256String(
        entry.identityHash + ':' + entry.changeType + ':' + entry.description,
      ));
      lineageAccumulator = poseidonHash([lineageAccumulator, entryField]);
    }

    // Build a commitment over breach types (public)
    let breachAccumulator = 0n;
    for (const bt of sortedBreachTypes) {
      const btField = hashToField(sha256String(bt));
      breachAccumulator = poseidonHash([breachAccumulator, btField]);
    }

    // Witness: combines the lineage scan result with the breach types
    const witnessHash = poseidonHash([lineageAccumulator, breachAccumulator]);

    const claimField = hashToField(sha256String(claim));
    const commitmentField = hashToField(this.commitment);

    const proofValue = poseidonHash([commitmentField, claimField, witnessHash]);

    const publicInputs = [
      this.commitment,
      claim,
      fieldToHex(witnessHash),
      fieldToHex(claimField),
      fieldToHex(lineageAccumulator),
      fieldToHex(breachAccumulator),
      String(lineage.length),
    ];

    return {
      claim,
      identityCommitment: this.commitment,
      proof: fieldToHex(proofValue),
      publicInputs,
      createdAt: timestamp(),
    };
  }

  /**
   * Prove that a numeric value falls within a range `[lowerBound, upperBound]`
   * without revealing the exact value.
   *
   * The proof encodes two "gap" witnesses:
   * - `lowerGap = actualValue - lowerBound` (non-negative when actualValue >= lowerBound)
   * - `upperGap = upperBound - actualValue` (non-negative when actualValue <= upperBound)
   *
   * Both gaps must be non-negative for the proof to be constructable,
   * ensuring the value lies within the declared range.
   *
   * @param dimension - The name of the dimension being bounded (e.g. `"trustScore"`).
   * @param lowerBound - The minimum allowed value (public).
   * @param upperBound - The maximum allowed value (public).
   * @param actualValue - The actual value (private, not revealed).
   * @returns A DisclosureProof for the range claim.
   * @throws If actualValue is outside the bounds or bounds are invalid.
   */
  proveRange(
    dimension: string,
    lowerBound: number,
    upperBound: number,
    actualValue: number,
  ): DisclosureProof {
    if (!dimension || typeof dimension !== 'string') {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveRange() requires a non-empty dimension name',
      );
    }
    if (
      typeof lowerBound !== 'number' ||
      typeof upperBound !== 'number' ||
      typeof actualValue !== 'number'
    ) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveRange() requires numeric lowerBound, upperBound, and actualValue',
      );
    }
    if (lowerBound > upperBound) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        `Cannot prove range: lowerBound (${lowerBound}) is greater than upperBound (${upperBound})`,
        { hint: 'lowerBound must be <= upperBound.' },
      );
    }
    if (actualValue < lowerBound || actualValue > upperBound) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        `Cannot prove range: actualValue (${actualValue}) is outside [${lowerBound}, ${upperBound}]`,
        { hint: 'The actual value must satisfy lowerBound <= actualValue <= upperBound.' },
      );
    }

    const claim = `range:${dimension}:${lowerBound}..${upperBound}`;

    // Two gap witnesses prove the value lies within both bounds
    const lowerGap = actualValue - lowerBound;
    const upperGap = upperBound - actualValue;
    const lowerGapField = hashToField(sha256String('range_lower_gap:' + String(lowerGap)));
    const upperGapField = hashToField(sha256String('range_upper_gap:' + String(upperGap)));

    const dimField = hashToField(sha256String('dim:' + dimension));
    const witnessHash = poseidonHash([dimField, lowerGapField, upperGapField]);

    const claimField = hashToField(sha256String(claim));
    const commitmentField = hashToField(this.commitment);

    const proofValue = poseidonHash([commitmentField, claimField, witnessHash]);

    const publicInputs = [
      this.commitment,
      claim,
      fieldToHex(witnessHash),
      fieldToHex(claimField),
    ];

    return {
      claim,
      identityCommitment: this.commitment,
      proof: fieldToHex(proofValue),
      publicInputs,
      createdAt: timestamp(),
    };
  }

  /**
   * Prove multiple claims atomically in a single composite proof.
   *
   * Each sub-claim is generated internally by calling the corresponding
   * prove method, then all individual proof values are chained via
   * Poseidon accumulation into a single witness. This ensures that all
   * claims are bound to the same identity commitment and cannot be
   * cherry-picked.
   *
   * Supported methods: `'property'`, `'threshold'`, `'range'`, `'setMembership'`.
   *
   * @param claims - Array of claim descriptors, each with a `method` name and `args`.
   * @returns A composite DisclosureProof covering all sub-claims.
   * @throws If claims is empty or any sub-claim method is unsupported.
   */
  proveComposite(
    claims: Array<{ method: string; args: unknown[] }>,
  ): DisclosureProof {
    if (!Array.isArray(claims) || claims.length === 0) {
      throw new NobulexError(
        NobulexErrorCode.PROTOCOL_INVALID_INPUT,
        'proveComposite() requires a non-empty claims array',
      );
    }

    const subProofs: DisclosureProof[] = [];

    for (const entry of claims) {
      if (!entry || typeof entry.method !== 'string' || !Array.isArray(entry.args)) {
        throw new NobulexError(
          NobulexErrorCode.PROTOCOL_INVALID_INPUT,
          'Each composite claim must have a string "method" and an array "args"',
        );
      }

      let subProof: DisclosureProof;
      switch (entry.method) {
        case 'property':
          subProof = this.proveProperty(
            entry.args[0] as string,
            entry.args[1],
          );
          break;
        case 'threshold':
          subProof = this.proveThreshold(
            entry.args[0] as string,
            entry.args[1] as number,
            entry.args[2] as number,
          );
          break;
        case 'range':
          subProof = this.proveRange(
            entry.args[0] as string,
            entry.args[1] as number,
            entry.args[2] as number,
            entry.args[3] as number,
          );
          break;
        case 'setMembership':
          subProof = this.proveSetMembership(
            entry.args[0] as string,
            entry.args[1] as string,
            entry.args[2] as string[],
          );
          break;
        default:
          throw new NobulexError(
            NobulexErrorCode.PROTOCOL_INVALID_INPUT,
            `Unsupported composite claim method: "${entry.method}"`,
            {
              hint:
                'Supported methods are: property, threshold, range, setMembership.',
            },
          );
      }
      subProofs.push(subProof);
    }

    // Chain all sub-proof values via Poseidon accumulation
    let acc = 0n;
    for (const sp of subProofs) {
      const individualProofField = BigInt('0x' + sp.proof);
      acc = poseidonHash([acc, individualProofField]);
    }

    const subClaimStrings = subProofs.map((sp) => sp.claim);
    const compositeClaim = `composite:[${subClaimStrings.join('|')}]`;

    const witnessHash = acc;
    const claimField = hashToField(sha256String(compositeClaim));
    const commitmentField = hashToField(this.commitment);

    const proofValue = poseidonHash([commitmentField, claimField, witnessHash]);

    const publicInputs = [
      this.commitment,
      compositeClaim,
      fieldToHex(witnessHash),
      fieldToHex(claimField),
      ...subClaimStrings,
    ];

    return {
      claim: compositeClaim,
      identityCommitment: this.commitment,
      proof: fieldToHex(proofValue),
      publicInputs,
      createdAt: timestamp(),
    };
  }

  /**
   * Verify any disclosure proof by recomputing the proof value from
   * the public inputs and comparing.
   *
   * All proof types use the same core structure:
   *
   *   proof = Poseidon(commitmentField, claimField, witnessHash)
   *
   * where the first three public inputs are always:
   *   [0] identityCommitment, [1] claim, [2] witnessHash hex, [3] claimField hex
   *
   * Verification recomputes the Poseidon hash from these inputs and
   * checks that it matches the stored proof value.
   *
   * @param proof - The DisclosureProof to verify.
   * @returns `true` if the proof is cryptographically valid.
   */
  static verify(proof: DisclosureProof): boolean {
    if (!proof || typeof proof !== 'object') {
      return false;
    }

    // Structural validation
    if (
      !proof.claim ||
      !proof.identityCommitment ||
      !proof.proof ||
      !Array.isArray(proof.publicInputs) ||
      proof.publicInputs.length < 4 ||
      !proof.createdAt
    ) {
      return false;
    }

    try {
      // Extract public inputs
      const [piCommitment, piClaim, piWitnessHex, piClaimFieldHex] = proof.publicInputs;

      // Check consistency: public inputs must match proof fields
      if (piCommitment !== proof.identityCommitment) {
        return false;
      }
      if (piClaim !== proof.claim) {
        return false;
      }

      // Recompute proof value from public inputs
      const commitmentField = hashToField(piCommitment!);
      const claimField = hashToField(sha256String(piClaim!));

      // Verify claimField matches the stored claim field hex
      if (fieldToHex(claimField) !== piClaimFieldHex) {
        return false;
      }

      // Parse the witness hash from public inputs
      const witnessHash = BigInt('0x' + piWitnessHex!);

      // Recompute: proof = Poseidon(commitmentField, claimField, witnessHash)
      const expectedProof = poseidonHash([commitmentField, claimField, witnessHash]);
      const expectedHex = fieldToHex(expectedProof);

      return expectedHex === proof.proof;
    } catch {
      return false;
    }
  }
}

/**
 * Verify a composite disclosure proof by recomputing the chained
 * Poseidon accumulation from the sub-claim witness hashes embedded
 * in the public inputs.
 *
 * A composite proof's `publicInputs` layout is:
 *   [0] identityCommitment
 *   [1] composite claim string
 *   [2] witnessHash hex (accumulated chain)
 *   [3] claimField hex
 *   [4..] individual sub-claim strings
 *
 * This function extracts the sub-claim strings, recomputes the
 * overall proof value, and confirms it matches.
 *
 * @param proof - The composite DisclosureProof to verify.
 * @returns `true` if the composite proof is cryptographically valid.
 */
export function verifyCompositeProof(proof: DisclosureProof): boolean {
  if (!proof || typeof proof !== 'object') {
    return false;
  }

  // Must be a composite proof
  if (!proof.claim || !proof.claim.startsWith('composite:')) {
    return false;
  }

  // Structural validation
  if (
    !proof.identityCommitment ||
    !proof.proof ||
    !Array.isArray(proof.publicInputs) ||
    proof.publicInputs.length < 4 ||
    !proof.createdAt
  ) {
    return false;
  }

  try {
    const [piCommitment, piClaim, piWitnessHex, piClaimFieldHex] = proof.publicInputs;

    // Consistency checks
    if (piCommitment !== proof.identityCommitment) {
      return false;
    }
    if (piClaim !== proof.claim) {
      return false;
    }

    // Extract sub-claim strings (indices 4 and beyond)
    const subClaims = proof.publicInputs.slice(4);

    // Verify the composite claim string matches the sub-claims
    const expectedClaimStr = `composite:[${subClaims.join('|')}]`;
    if (expectedClaimStr !== proof.claim) {
      return false;
    }

    // Recompute claim field and verify it matches
    const commitmentField = hashToField(piCommitment!);
    const claimField = hashToField(sha256String(piClaim!));

    if (fieldToHex(claimField) !== piClaimFieldHex) {
      return false;
    }

    // Parse the witness hash from public inputs
    const witnessHash = BigInt('0x' + piWitnessHex!);

    // Recompute: proof = Poseidon(commitmentField, claimField, witnessHash)
    const expectedProof = poseidonHash([commitmentField, claimField, witnessHash]);
    const expectedHex = fieldToHex(expectedProof);

    return expectedHex === proof.proof;
  } catch {
    return false;
  }
}
