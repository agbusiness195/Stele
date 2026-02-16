/**
 * Advanced cross-package integration tests for the Stele monorepo.
 *
 * Tests complex multi-package pipelines that are NOT covered by existing
 * integration tests (cross-package.test.ts and full-flow.test.ts):
 *
 *   1. Reputation -> Enforcement -> Breach Pipeline
 *   2. Core -> Verifier -> Store Lifecycle
 *   3. Identity -> Reputation -> Evolution
 *   4. CCL -> Enforcement -> Audit Trail
 */

import { describe, it, expect, beforeEach } from 'vitest';

import { generateKeyPair, sha256String, sha256Object } from '@stele/crypto';
import type { KeyPair, HashHex } from '@stele/crypto';

import {
  buildCovenant,
  verifyCovenant,
  serializeCovenant,
  deserializeCovenant,
} from '@stele/core';
import type { CovenantDocument } from '@stele/core';

import { MemoryStore } from '@stele/store';

import { Verifier, verifyBatch } from '@stele/verifier';

import { parse, evaluate, serialize as serializeCCL } from '@stele/ccl';

import {
  createIdentity,
  evolveIdentity,
  verifyIdentity,
  serializeIdentity,
  deserializeIdentity,
} from '@stele/identity';
import type { AgentIdentity } from '@stele/identity';

import {
  Monitor,
  MonitorDeniedError,
  verifyMerkleProof,
} from '@stele/enforcement';
import type { AuditEntry } from '@stele/enforcement';

import {
  createBreachAttestation,
  verifyBreachAttestation,
  TrustGraph,
} from '@stele/breach';
import type { BreachAttestation, BreachEvent } from '@stele/breach';

import {
  createReceipt,
  verifyReceiptChain,
  computeReputationScore,
  createStake,
  burnStake,
} from '@stele/reputation';
import type { ExecutionReceipt } from '@stele/reputation';


// ---------------------------------------------------------------------------
// 1. Reputation -> Enforcement -> Breach Pipeline
//
// Creates an agent with a reputation track record, uses an enforcement
// monitor to evaluate actions (including a denied action), generates a
// breach attestation for the denial, processes it through a trust graph,
// and verifies that the breach outcome degrades the reputation score.
// ---------------------------------------------------------------------------

describe('Reputation -> Enforcement -> Breach Pipeline', () => {
  let agentKp: KeyPair;
  let reporterKp: KeyPair;
  let beneficiaryKp: KeyPair;
  let agentIdentityHash: HashHex;
  let covenantId: HashHex;
  let monitor: Monitor;
  let covenant: CovenantDocument;

  const CONSTRAINTS = [
    "permit file.read on '/data/**'",
    "permit api.call on '/analysis/**'",
    "deny db.write on '/prod/**' severity critical",
    "deny file.delete on '**' severity high",
  ].join('\n');

  beforeEach(async () => {
    [agentKp, reporterKp, beneficiaryKp] = await Promise.all([
      generateKeyPair(),
      generateKeyPair(),
      generateKeyPair(),
    ]);
    agentIdentityHash = sha256String('pipeline-agent') as HashHex;

    covenant = await buildCovenant({
      issuer: { id: agentIdentityHash, publicKey: agentKp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'pipeline-ben', publicKey: beneficiaryKp.publicKeyHex, role: 'beneficiary' },
      constraints: CONSTRAINTS,
      privateKey: agentKp.privateKey,
    });
    covenantId = covenant.id;

    monitor = new Monitor(covenantId, CONSTRAINTS, {
      mode: 'enforce',
      failureMode: 'fail_closed',
    });
  });

  it('should build a good reputation from permitted actions', async () => {
    // Execute several permitted actions through the monitor
    for (let i = 0; i < 5; i++) {
      const result = await monitor.evaluate('file.read', `/data/file-${i}.csv`);
      expect(result.permitted).toBe(true);
    }
    for (let i = 0; i < 3; i++) {
      const result = await monitor.evaluate('api.call', `/analysis/task-${i}`);
      expect(result.permitted).toBe(true);
    }

    // Build receipts for these successful executions
    const receipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 8; i++) {
      const receipt = await createReceipt(
        covenantId,
        agentIdentityHash,
        beneficiaryKp.publicKeyHex,
        'fulfilled',
        sha256String(`proof-${i}`),
        500 + i * 100,
        agentKp,
        prevHash,
      );
      receipts.push(receipt);
      prevHash = receipt.receiptHash;
    }

    // Verify receipt chain
    expect(verifyReceiptChain(receipts)).toBe(true);

    // Compute reputation -- should be positive
    const score = computeReputationScore(agentIdentityHash, receipts);
    expect(score.totalExecutions).toBe(8);
    expect(score.fulfilled).toBe(8);
    expect(score.breached).toBe(0);
    expect(score.successRate).toBe(1.0);
    expect(score.weightedScore).toBeGreaterThan(0);
  });

  it('should detect a denied action and create a breach attestation', async () => {
    // First some good actions
    await monitor.evaluate('file.read', '/data/report.csv');

    // Attempt a denied action
    let caughtError: MonitorDeniedError | undefined;
    try {
      await monitor.evaluate('db.write', '/prod/users');
    } catch (err) {
      if (err instanceof MonitorDeniedError) {
        caughtError = err;
      } else {
        throw err;
      }
    }
    expect(caughtError).toBeDefined();
    expect(caughtError!.severity).toBe('critical');

    // Verify audit log recorded both actions
    const auditLog = monitor.getAuditLog();
    expect(auditLog.count).toBe(2);
    expect(auditLog.entries[0]!.outcome).toBe('EXECUTED');
    expect(auditLog.entries[1]!.outcome).toBe('DENIED');

    // Create breach attestation from the denied action evidence
    const evidenceHash = sha256Object({
      auditEntry: auditLog.entries[1],
      merkleRoot: auditLog.merkleRoot,
    });

    const breach = await createBreachAttestation(
      covenantId,
      agentIdentityHash,
      "deny db.write on '/prod/**' severity critical",
      'critical',
      'db.write',
      '/prod/users',
      evidenceHash,
      [covenantId],
      reporterKp,
    );

    expect(breach.id).toMatch(/^[0-9a-f]{64}$/);
    expect(breach.severity).toBe('critical');
    expect(breach.recommendedAction).toBe('revoke');

    // Verify the attestation
    const valid = await verifyBreachAttestation(breach);
    expect(valid).toBe(true);
  });

  it('should show that a breach degrades reputation compared to a clean record', async () => {
    // Build a clean receipt chain
    const cleanReceipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 10; i++) {
      const receipt = await createReceipt(
        covenantId,
        agentIdentityHash,
        beneficiaryKp.publicKeyHex,
        'fulfilled',
        sha256String(`clean-proof-${i}`),
        1000,
        agentKp,
        prevHash,
      );
      cleanReceipts.push(receipt);
      prevHash = receipt.receiptHash;
    }

    const cleanScore = computeReputationScore(agentIdentityHash, cleanReceipts);

    // Build a receipt chain with a critical breach
    const breachedReceipts: ExecutionReceipt[] = [];
    prevHash = null;
    for (let i = 0; i < 9; i++) {
      const receipt = await createReceipt(
        covenantId,
        agentIdentityHash,
        beneficiaryKp.publicKeyHex,
        'fulfilled',
        sha256String(`breach-proof-${i}`),
        1000,
        agentKp,
        prevHash,
      );
      breachedReceipts.push(receipt);
      prevHash = receipt.receiptHash;
    }
    // Add one breached receipt
    const breachedReceipt = await createReceipt(
      covenantId,
      agentIdentityHash,
      beneficiaryKp.publicKeyHex,
      'breached',
      sha256String('breach-proof-final'),
      500,
      agentKp,
      prevHash,
      'critical',
    );
    breachedReceipts.push(breachedReceipt);

    const breachedScore = computeReputationScore(agentIdentityHash, breachedReceipts);

    // Clean record should have a higher weighted score
    expect(cleanScore.weightedScore).toBeGreaterThan(breachedScore.weightedScore);
    expect(cleanScore.successRate).toBe(1.0);
    expect(breachedScore.breached).toBe(1);
  });

  it('should propagate a breach through a trust graph and degrade dependents', async () => {
    const graph = new TrustGraph();
    const dependent1 = sha256String('dep-agent-1') as HashHex;
    const dependent2 = sha256String('dep-agent-2') as HashHex;

    graph.registerDependency(agentIdentityHash, dependent1);
    graph.registerDependency(dependent1, dependent2);

    // All start as trusted
    expect(graph.isTrusted(agentIdentityHash)).toBe(true);
    expect(graph.isTrusted(dependent1)).toBe(true);
    expect(graph.isTrusted(dependent2)).toBe(true);

    // Create and process a breach
    const evidenceHash = sha256String('pipeline-evidence');
    const breach = await createBreachAttestation(
      covenantId,
      agentIdentityHash,
      "deny db.write on '/prod/**' severity critical",
      'critical',
      'db.write',
      '/prod/users',
      evidenceHash,
      [covenantId],
      reporterKp,
    );

    const events = await graph.processBreach(breach);
    expect(events.length).toBeGreaterThanOrEqual(2);

    // Violator should be revoked
    expect(graph.getStatus(agentIdentityHash)).toBe('revoked');
    expect(graph.isTrusted(agentIdentityHash)).toBe(false);

    // Dependents should be degraded
    expect(graph.isTrusted(dependent1)).toBe(false);
    expect(graph.getStatus(dependent1)).toBe('restricted');
    expect(graph.getStatus(dependent2)).toBe('degraded');
  });

  it('should correlate breach with stake burning', async () => {
    // Create a stake for the agent
    const stake = await createStake(agentIdentityHash, covenantId, 0.8, agentKp);
    expect(stake.status).toBe('active');
    expect(stake.amount).toBe(0.8);

    // Agent breaches -- burn the stake
    const burned = burnStake(stake);
    expect(burned.status).toBe('burned');
    expect(burned.resolvedAt).toBeDefined();
    expect(burned.amount).toBe(0.8); // Full amount is lost
  });
});


// ---------------------------------------------------------------------------
// 2. Core -> Verifier -> Store Lifecycle
//
// Builds a covenant with core, verifies it with verifier, stores it,
// retrieves it, serializes/deserializes it, re-verifies it, and confirms
// that tampered documents fail verification at every stage.
// ---------------------------------------------------------------------------

describe('Core -> Verifier -> Store Lifecycle', () => {
  let kp: KeyPair;
  let verifier: Verifier;
  let store: MemoryStore;

  beforeEach(async () => {
    kp = await generateKeyPair();
    verifier = new Verifier({ verifierId: 'lifecycle-verifier' });
    store = new MemoryStore();
  });

  it('should build, verify, store, retrieve, and re-verify a covenant', async () => {
    // Step 1: Build
    const doc = await buildCovenant({
      issuer: { id: 'lifecycle-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'lifecycle-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '/data/**'\ndeny file.write on '/system/**' severity critical",
      privateKey: kp.privateKey,
    });
    expect(doc.id).toMatch(/^[0-9a-f]{64}$/);

    // Step 2: Verify via Verifier
    const report1 = await verifier.verify(doc);
    expect(report1.valid).toBe(true);
    expect(report1.verifierId).toBe('lifecycle-verifier');

    // Step 3: Store
    await store.put(doc);
    expect(store.size).toBe(1);

    // Step 4: Retrieve
    const retrieved = await store.get(doc.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(doc.id);
    expect(retrieved!.constraints).toBe(doc.constraints);

    // Step 5: Re-verify retrieved document
    const report2 = await verifier.verify(retrieved!);
    expect(report2.valid).toBe(true);
  });

  it('should survive serialization round-trip and still verify', async () => {
    const doc = await buildCovenant({
      issuer: { id: 'ser-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'ser-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit api.call on '**'",
      privateKey: kp.privateKey,
    });

    // Serialize and deserialize
    const json = serializeCovenant(doc);
    const restored = deserializeCovenant(json);

    // Verify the restored document
    const report = await verifier.verify(restored);
    expect(report.valid).toBe(true);

    // Store the restored document
    await store.put(restored);
    const fromStore = await store.get(restored.id);
    expect(fromStore).toBeDefined();

    // Re-verify from store
    const report2 = await verifier.verify(fromStore!);
    expect(report2.valid).toBe(true);
  });

  it('should detect tampering after store retrieval', async () => {
    const doc = await buildCovenant({
      issuer: { id: 'tamper-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'tamper-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '/data/**'",
      privateKey: kp.privateKey,
    });

    await store.put(doc);
    const retrieved = await store.get(doc.id);
    expect(retrieved).toBeDefined();

    // Tamper the constraints
    const tampered = { ...retrieved!, constraints: "permit file.write on '**'" };

    // Verifier should detect the tampering
    const report = await verifier.verify(tampered);
    expect(report.valid).toBe(false);
  });

  it('should batch verify documents from store with one tampered', async () => {
    const docs: CovenantDocument[] = [];
    for (let i = 0; i < 5; i++) {
      const doc = await buildCovenant({
        issuer: { id: `batch-issuer-${i}`, publicKey: kp.publicKeyHex, role: 'issuer' },
        beneficiary: { id: `batch-ben-${i}`, publicKey: kp.publicKeyHex, role: 'beneficiary' },
        constraints: `permit file.read on '/data/${i}/**'`,
        privateKey: kp.privateKey,
      });
      docs.push(doc);
    }

    await store.putBatch(docs);
    const all = await store.list();
    expect(all).toHaveLength(5);

    // Tamper one document
    const tamperedList = all.map((d, i) =>
      i === 2 ? { ...d, constraints: "permit file.delete on '**'" } : d,
    );

    const batchReport = await verifyBatch(tamperedList);
    expect(batchReport.summary.total).toBe(5);
    expect(batchReport.summary.passed).toBe(4);
    expect(batchReport.summary.failed).toBe(1);
  });

  it('should verify action correctness through the full lifecycle', async () => {
    const doc = await buildCovenant({
      issuer: { id: 'action-lifecycle', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'action-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '/data/**'\ndeny file.write on '/system/**' severity critical",
      privateKey: kp.privateKey,
    });

    // Store and retrieve
    await store.put(doc);
    const retrieved = await store.get(doc.id);
    expect(retrieved).toBeDefined();

    // Verify action on retrieved document
    const readReport = await verifier.verifyAction(retrieved!, 'file.read', '/data/test.csv');
    expect(readReport.permitted).toBe(true);
    expect(readReport.documentValid).toBe(true);

    const writeReport = await verifier.verifyAction(retrieved!, 'file.write', '/system/config.yaml');
    expect(writeReport.permitted).toBe(false);
    expect(writeReport.severity).toBe('critical');
    expect(writeReport.documentValid).toBe(true);

    // Verify history accumulates
    const history = verifier.getHistory();
    expect(history.length).toBeGreaterThanOrEqual(2);
  });

  it('should track verification history across multiple operations', async () => {
    const doc = await buildCovenant({
      issuer: { id: 'history-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'history-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '**'",
      privateKey: kp.privateKey,
    });

    // Verify the valid document
    await verifier.verify(doc);

    // Verify a tampered document
    const tampered = { ...doc, constraints: "deny file.read on '**'" };
    await verifier.verify(tampered);

    // Verify action
    await verifier.verifyAction(doc, 'file.read', '/test.txt');

    const history = verifier.getHistory();
    expect(history).toHaveLength(3);
    expect(history[0]!.valid).toBe(true);
    expect(history[1]!.valid).toBe(false);
  });
});


// ---------------------------------------------------------------------------
// 3. Identity -> Reputation -> Evolution
//
// Creates an identity, builds a reputation through execution receipts,
// evolves the identity (capability change, model update), and verifies
// that reputation data carries forward consistently with the new identity
// version.
// ---------------------------------------------------------------------------

describe('Identity -> Reputation -> Evolution', () => {
  let operatorKp: KeyPair;
  let beneficiaryKp: KeyPair;

  beforeEach(async () => {
    [operatorKp, beneficiaryKp] = await Promise.all([
      generateKeyPair(),
      generateKeyPair(),
    ]);
  });

  it('should create identity, build reputation, evolve, and verify carry-forward', async () => {
    // Step 1: Create initial identity
    let identity = await createIdentity({
      operatorKeyPair: operatorKp,
      operatorIdentifier: 'evolution-corp',
      model: { provider: 'anthropic', modelId: 'claude-opus-4', modelVersion: '1.0', attestationType: 'provider_signed' },
      capabilities: ['file.read', 'api.call'],
      deployment: { runtime: 'container' },
    });
    expect(identity.version).toBe(1);
    expect(identity.capabilities).toContain('file.read');
    expect(identity.capabilities).toContain('api.call');

    const idV1 = await verifyIdentity(identity);
    expect(idV1.valid).toBe(true);

    // Step 2: Build reputation with v1 identity
    const covenantId = sha256String('evolution-covenant') as HashHex;
    const receiptsV1: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;

    for (let i = 0; i < 6; i++) {
      const receipt = await createReceipt(
        covenantId,
        identity.id,
        beneficiaryKp.publicKeyHex,
        'fulfilled',
        sha256String(`v1-proof-${i}`),
        800,
        operatorKp,
        prevHash,
      );
      receiptsV1.push(receipt);
      prevHash = receipt.receiptHash;
    }

    const scoreV1 = computeReputationScore(identity.id, receiptsV1);
    expect(scoreV1.totalExecutions).toBe(6);
    expect(scoreV1.successRate).toBe(1.0);
    expect(scoreV1.weightedScore).toBeGreaterThan(0);
    const v1WeightedScore = scoreV1.weightedScore;

    // Step 3: Evolve identity (add file.write capability)
    identity = await evolveIdentity(identity, {
      operatorKeyPair: operatorKp,
      changeType: 'capability_change',
      description: 'Add file.write capability for expanded operations',
      updates: { capabilities: ['file.read', 'file.write', 'api.call'] },
    });
    expect(identity.version).toBe(2);
    expect(identity.capabilities).toContain('file.write');
    expect(identity.lineage).toHaveLength(2);

    // The identity ID changes after evolution
    const newId = identity.id;

    // Step 4: Verify evolved identity
    const idV2 = await verifyIdentity(identity);
    expect(idV2.valid).toBe(true);

    // Step 5: Continue building reputation with evolved identity
    const receiptsV2: ExecutionReceipt[] = [];
    prevHash = null;

    for (let i = 0; i < 6; i++) {
      const receipt = await createReceipt(
        covenantId,
        newId,
        beneficiaryKp.publicKeyHex,
        'fulfilled',
        sha256String(`v2-proof-${i}`),
        700,
        operatorKp,
        prevHash,
      );
      receiptsV2.push(receipt);
      prevHash = receipt.receiptHash;
    }

    const scoreV2 = computeReputationScore(newId, receiptsV2);
    expect(scoreV2.totalExecutions).toBe(6);
    expect(scoreV2.successRate).toBe(1.0);

    // Step 6: Combined reputation across both versions (aggregated by caller)
    // The old receipts are under the old identity hash, new under the new hash
    // Both should have equivalent quality
    expect(scoreV1.successRate).toBe(scoreV2.successRate);
  });

  it('should carry lineage through multiple evolutions and verify at each stage', async () => {
    let identity = await createIdentity({
      operatorKeyPair: operatorKp,
      operatorIdentifier: 'lineage-test',
      model: { provider: 'anthropic', modelId: 'claude-opus-4', modelVersion: '1.0' },
      capabilities: ['file.read'],
      deployment: { runtime: 'container' },
    });

    // Evolve 3 times
    identity = await evolveIdentity(identity, {
      operatorKeyPair: operatorKp,
      changeType: 'capability_change',
      description: 'Add api.call',
      updates: { capabilities: ['file.read', 'api.call'] },
    });

    identity = await evolveIdentity(identity, {
      operatorKeyPair: operatorKp,
      changeType: 'model_update',
      description: 'Update model version',
      updates: { model: { ...identity.model, modelVersion: '2.0' } },
    });

    identity = await evolveIdentity(identity, {
      operatorKeyPair: operatorKp,
      changeType: 'capability_change',
      description: 'Add file.write',
      updates: { capabilities: ['file.read', 'file.write', 'api.call'] },
    });

    expect(identity.version).toBe(4);
    expect(identity.lineage).toHaveLength(4);

    // Verify the whole lineage chain
    const result = await verifyIdentity(identity);
    expect(result.valid).toBe(true);

    // Serialize and deserialize, then verify again
    const json = serializeIdentity(identity);
    const restored = deserializeIdentity(json);
    const restoredResult = await verifyIdentity(restored);
    expect(restoredResult.valid).toBe(true);
    expect(restored.version).toBe(4);
    expect(restored.lineage).toHaveLength(4);
  });

  it('should bind evolved identity to a new covenant and build receipts', async () => {
    let identity = await createIdentity({
      operatorKeyPair: operatorKp,
      operatorIdentifier: 'binding-test',
      model: { provider: 'anthropic', modelId: 'claude-opus-4', modelVersion: '1.0' },
      capabilities: ['file.read'],
      deployment: { runtime: 'container' },
    });

    // Build an initial covenant
    const cov1 = await buildCovenant({
      issuer: { id: identity.id, publicKey: operatorKp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'cov-ben', publicKey: beneficiaryKp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '/data/**'",
      privateKey: operatorKp.privateKey,
    });
    expect((await verifyCovenant(cov1)).valid).toBe(true);

    // Evolve identity
    identity = await evolveIdentity(identity, {
      operatorKeyPair: operatorKp,
      changeType: 'capability_change',
      description: 'Expand capabilities',
      updates: { capabilities: ['file.read', 'file.write'] },
    });

    // Build a new covenant with the evolved identity
    const cov2 = await buildCovenant({
      issuer: { id: identity.id, publicKey: operatorKp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'cov-ben-v2', publicKey: beneficiaryKp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '/data/**'\npermit file.write on '/output/**'",
      privateKey: operatorKp.privateKey,
    });
    expect((await verifyCovenant(cov2)).valid).toBe(true);
    expect(cov2.issuer.id).toBe(identity.id);
    expect(cov2.issuer.id).not.toBe(cov1.issuer.id); // Different identity versions

    // Generate receipts for both covenants
    const receipt1 = await createReceipt(
      cov1.id,
      cov1.issuer.id as HashHex,
      beneficiaryKp.publicKeyHex,
      'fulfilled',
      sha256String('cov1-proof'),
      1000,
      operatorKp,
      null,
    );

    const receipt2 = await createReceipt(
      cov2.id,
      identity.id,
      beneficiaryKp.publicKeyHex,
      'fulfilled',
      sha256String('cov2-proof'),
      800,
      operatorKp,
      null,
    );

    expect(receipt1.covenantId).toBe(cov1.id);
    expect(receipt2.covenantId).toBe(cov2.id);
    expect(receipt1.agentIdentityHash).not.toBe(receipt2.agentIdentityHash);
  });

  it('should produce distinct reputation scores for agents with different histories', async () => {
    // Create two identities
    const kp2 = await generateKeyPair();

    const identity1 = await createIdentity({
      operatorKeyPair: operatorKp,
      operatorIdentifier: 'good-agent',
      model: { provider: 'anthropic', modelId: 'claude-opus-4', modelVersion: '1.0' },
      capabilities: ['file.read'],
      deployment: { runtime: 'container' },
    });

    const identity2 = await createIdentity({
      operatorKeyPair: kp2,
      operatorIdentifier: 'bad-agent',
      model: { provider: 'anthropic', modelId: 'claude-opus-4', modelVersion: '1.0' },
      capabilities: ['file.read'],
      deployment: { runtime: 'container' },
    });

    const covenantId = sha256String('dual-agent-covenant') as HashHex;

    // Good agent: all fulfilled
    const goodReceipts: ExecutionReceipt[] = [];
    let prevHash: HashHex | null = null;
    for (let i = 0; i < 12; i++) {
      const receipt = await createReceipt(
        covenantId,
        identity1.id,
        beneficiaryKp.publicKeyHex,
        'fulfilled',
        sha256String(`good-proof-${i}`),
        1000,
        operatorKp,
        prevHash,
      );
      goodReceipts.push(receipt);
      prevHash = receipt.receiptHash;
    }

    // Bad agent: mix of fulfilled and breached
    const badReceipts: ExecutionReceipt[] = [];
    prevHash = null;
    for (let i = 0; i < 12; i++) {
      const outcome = i >= 9 ? 'breached' as const : 'fulfilled' as const;
      const receipt = await createReceipt(
        covenantId,
        identity2.id,
        beneficiaryKp.publicKeyHex,
        outcome,
        sha256String(`bad-proof-${i}`),
        1000,
        kp2,
        prevHash,
        outcome === 'breached' ? 'high' : undefined,
      );
      badReceipts.push(receipt);
      prevHash = receipt.receiptHash;
    }

    const goodScore = computeReputationScore(identity1.id, goodReceipts);
    const badScore = computeReputationScore(identity2.id, badReceipts);

    expect(goodScore.weightedScore).toBeGreaterThan(badScore.weightedScore);
    expect(goodScore.breached).toBe(0);
    expect(badScore.breached).toBe(3);
    expect(goodScore.successRate).toBe(1.0);
    expect(badScore.successRate).toBe(0.75);
  });
});


// ---------------------------------------------------------------------------
// 4. CCL -> Enforcement -> Audit Trail
//
// Parses CCL rules, creates an enforcement monitor from those rules,
// exercises a variety of actions (permitted, denied, conditional),
// verifies audit trail integrity (hash chain and Merkle proofs), and
// confirms that the audit trail accurately reflects all enforcement
// decisions.
// ---------------------------------------------------------------------------

describe('CCL -> Enforcement -> Audit Trail', () => {
  let kp: KeyPair;

  const CCL_SOURCE = [
    "permit file.read on '/data/**'",
    "permit api.call on '/public/**'",
    "deny api.call on '/public/**' when user.role = guest severity medium",
    "deny file.write on '/system/**' severity critical",
    "deny file.delete on '**' severity high",
    "limit api.call 50 per 3600 seconds severity medium",
  ].join('\n');

  beforeEach(async () => {
    kp = await generateKeyPair();
  });

  it('should parse CCL, enforce through monitor, and verify audit trail integrity', async () => {
    // Step 1: Parse the CCL to confirm it is valid
    const cclDoc = parse(CCL_SOURCE);
    expect(cclDoc.statements.length).toBeGreaterThan(0);
    expect(cclDoc.permits.length).toBe(2);
    expect(cclDoc.denies.length).toBe(3);
    expect(cclDoc.limits.length).toBe(1);

    // Step 2: Build a covenant and monitor
    const covenant = await buildCovenant({
      issuer: { id: 'ccl-audit-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'ccl-audit-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: CCL_SOURCE,
      privateKey: kp.privateKey,
    });

    const monitor = new Monitor(covenant.id, CCL_SOURCE, {
      mode: 'enforce',
      failureMode: 'fail_closed',
    });

    // Step 3: Execute a variety of actions
    // -- Permitted read
    const readResult = await monitor.evaluate('file.read', '/data/report.csv');
    expect(readResult.permitted).toBe(true);

    // -- Permitted API call (no condition context)
    const apiResult = await monitor.evaluate('api.call', '/public/endpoint');
    expect(apiResult.permitted).toBe(true);

    // -- Denied API call with guest context
    try {
      await monitor.evaluate('api.call', '/public/endpoint', { user: { role: 'guest' } });
    } catch (err) {
      expect(err).toBeInstanceOf(MonitorDeniedError);
      expect((err as MonitorDeniedError).severity).toBe('medium');
    }

    // -- Denied file write
    try {
      await monitor.evaluate('file.write', '/system/config.yaml');
    } catch (err) {
      expect(err).toBeInstanceOf(MonitorDeniedError);
      expect((err as MonitorDeniedError).severity).toBe('critical');
    }

    // -- Denied file delete
    try {
      await monitor.evaluate('file.delete', '/data/important.csv');
    } catch (err) {
      expect(err).toBeInstanceOf(MonitorDeniedError);
      expect((err as MonitorDeniedError).severity).toBe('high');
    }

    // -- More permitted reads
    for (let i = 0; i < 3; i++) {
      await monitor.evaluate('file.read', `/data/batch-${i}.csv`);
    }

    // Step 4: Verify audit trail
    const auditLog = monitor.getAuditLog();
    expect(auditLog.count).toBe(8); // 2 permitted + 3 denied + 3 more reads
    expect(auditLog.covenantId).toBe(covenant.id);

    // Count outcomes
    const executed = auditLog.entries.filter((e) => e.outcome === 'EXECUTED');
    const denied = auditLog.entries.filter((e) => e.outcome === 'DENIED');
    expect(executed).toHaveLength(5);
    expect(denied).toHaveLength(3);

    // Step 5: Verify hash chain integrity
    expect(monitor.verifyAuditLogIntegrity()).toBe(true);

    // Step 6: Verify Merkle root consistency
    const merkleRoot = monitor.computeMerkleRoot();
    expect(merkleRoot).toMatch(/^[0-9a-f]{64}$/);
    expect(auditLog.merkleRoot).toBe(merkleRoot);
  });

  it('should generate and verify Merkle proofs for individual audit entries', async () => {
    const covenant = await buildCovenant({
      issuer: { id: 'merkle-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'merkle-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '**'\ndeny file.write on '**' severity critical",
      privateKey: kp.privateKey,
    });

    const monitor = new Monitor(covenant.id, covenant.constraints, { mode: 'enforce' });

    // Generate 10 permitted entries
    for (let i = 0; i < 10; i++) {
      await monitor.evaluate('file.read', `/data/file-${i}.csv`);
    }

    // Generate 3 denied entries
    for (let i = 0; i < 3; i++) {
      try {
        await monitor.evaluate('file.write', `/data/file-${i}.csv`);
      } catch {
        // Expected
      }
    }

    expect(monitor.getAuditLog().count).toBe(13);

    // Generate and verify Merkle proof for several entries
    for (const idx of [0, 5, 9, 12]) {
      const proof = monitor.generateMerkleProof(idx);
      expect(proof).toBeDefined();
      expect(verifyMerkleProof(proof)).toBe(true);

      // Tampered entry hash should fail
      const tampered = { ...proof, entryHash: sha256String('tampered') as HashHex };
      expect(verifyMerkleProof(tampered)).toBe(false);
    }
  });

  it('should preserve CCL semantics through parse -> serialize -> re-parse', async () => {
    const doc1 = parse(CCL_SOURCE);
    const serialized = serializeCCL(doc1);
    const doc2 = parse(serialized);

    // Both documents should evaluate identically for various actions
    const testCases = [
      { action: 'file.read', resource: '/data/test.csv' },
      { action: 'api.call', resource: '/public/endpoint' },
      { action: 'file.write', resource: '/system/config.yaml' },
      { action: 'file.delete', resource: '/data/important.csv' },
    ];

    for (const { action, resource } of testCases) {
      const r1 = evaluate(doc1, action, resource);
      const r2 = evaluate(doc2, action, resource);
      expect(r1.permitted).toBe(r2.permitted);
      if (r1.severity) {
        expect(r1.severity).toBe(r2.severity);
      }
    }
  });

  it('should record conditional denials with correct context in audit entries', async () => {
    const covenant = await buildCovenant({
      issuer: { id: 'cond-audit-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'cond-audit-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: [
        "permit api.call on '/public/**'",
        "deny api.call on '/public/**' when user.role = guest severity medium",
      ].join('\n'),
      privateKey: kp.privateKey,
    });

    const monitor = new Monitor(covenant.id, covenant.constraints, { mode: 'enforce' });

    // Permitted call (no matching deny condition)
    const r1 = await monitor.evaluate('api.call', '/public/data', { user: { role: 'admin' } });
    expect(r1.permitted).toBe(true);

    // Denied call (matching deny condition)
    try {
      await monitor.evaluate('api.call', '/public/data', { user: { role: 'guest' } });
    } catch (err) {
      expect(err).toBeInstanceOf(MonitorDeniedError);
    }

    const auditLog = monitor.getAuditLog();
    expect(auditLog.count).toBe(2);
    expect(auditLog.entries[0]!.outcome).toBe('EXECUTED');
    expect(auditLog.entries[1]!.outcome).toBe('DENIED');

    // Verify the context was captured in the audit entries
    expect(auditLog.entries[0]!.context).toEqual({ user: { role: 'admin' } });
    expect(auditLog.entries[1]!.context).toEqual({ user: { role: 'guest' } });

    // Verify audit integrity is maintained
    expect(monitor.verifyAuditLogIntegrity()).toBe(true);
  });

  it('should track violation callbacks alongside the audit trail', async () => {
    const violations: AuditEntry[] = [];
    const allActions: AuditEntry[] = [];

    const covenant = await buildCovenant({
      issuer: { id: 'callback-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'callback-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '/data/**'\ndeny file.write on '**' severity critical\ndeny file.delete on '**' severity high",
      privateKey: kp.privateKey,
    });

    const monitor = new Monitor(covenant.id, covenant.constraints, {
      mode: 'enforce',
      onViolation: (entry) => violations.push(entry),
      onAction: (entry) => allActions.push(entry),
    });

    // 3 permitted actions
    for (let i = 0; i < 3; i++) {
      await monitor.evaluate('file.read', `/data/file-${i}.csv`);
    }

    // 2 denied actions
    for (const action of ['file.write', 'file.delete']) {
      try {
        await monitor.evaluate(action, '/data/something');
      } catch {
        // Expected
      }
    }

    // Violations should only contain the 2 denied actions
    expect(violations).toHaveLength(2);
    expect(violations[0]!.action).toBe('file.write');
    expect(violations[1]!.action).toBe('file.delete');

    // All actions callback should have all 5
    expect(allActions).toHaveLength(5);

    // Audit log should match
    const auditLog = monitor.getAuditLog();
    expect(auditLog.count).toBe(5);

    // Integrity still holds
    expect(monitor.verifyAuditLogIntegrity()).toBe(true);
  });

  it('should maintain audit integrity with log_only mode (no throws)', async () => {
    const covenant = await buildCovenant({
      issuer: { id: 'logonly-issuer', publicKey: kp.publicKeyHex, role: 'issuer' },
      beneficiary: { id: 'logonly-ben', publicKey: kp.publicKeyHex, role: 'beneficiary' },
      constraints: "permit file.read on '/data/**'\ndeny file.write on '**' severity critical",
      privateKey: kp.privateKey,
    });

    const monitor = new Monitor(covenant.id, covenant.constraints, { mode: 'log_only' });

    // In log_only mode, denied actions do not throw
    const r1 = await monitor.evaluate('file.read', '/data/test.csv');
    expect(r1.permitted).toBe(true);

    const r2 = await monitor.evaluate('file.write', '/data/test.csv');
    expect(r2.permitted).toBe(false); // CCL still says denied

    // But audit log records both as EXECUTED in log_only mode
    const auditLog = monitor.getAuditLog();
    expect(auditLog.count).toBe(2);
    expect(auditLog.entries[0]!.outcome).toBe('EXECUTED');
    expect(auditLog.entries[1]!.outcome).toBe('EXECUTED');

    // Audit integrity still holds
    expect(monitor.verifyAuditLogIntegrity()).toBe(true);
  });
});
