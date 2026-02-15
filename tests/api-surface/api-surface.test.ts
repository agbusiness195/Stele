/**
 * API Surface Snapshot Tests
 *
 * These tests verify the public API surface of each foundation package
 * has not changed accidentally. For each package, we import everything
 * and verify the exported names match a known list. Only value exports
 * (functions, classes, constants) are checked since type-only exports
 * do not appear in runtime Object.keys().
 */
import { describe, it, expect } from 'vitest';

describe('API Surface Tests', () => {

  // ─── @stele/crypto ──────────────────────────────────────────────────────────

  it('@stele/crypto exports', async () => {
    const mod = await import('@stele/crypto');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'KeyManager',
      'base64urlDecode',
      'base64urlEncode',
      'canonicalizeJson',
      'constantTimeEqual',
      'fromHex',
      'generateId',
      'generateKeyPair',
      'generateNonce',
      'keyPairFromPrivateKey',
      'keyPairFromPrivateKeyHex',
      'sha256',
      'sha256Object',
      'sha256String',
      'sign',
      'signString',
      'timestamp',
      'toHex',
      'verify',
    ].sort());
  });

  // ─── @stele/ccl ─────────────────────────────────────────────────────────────

  it('@stele/ccl exports', async () => {
    const mod = await import('@stele/ccl');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'CCLSyntaxError',
      'CCLValidationError',
      'checkRateLimit',
      'evaluate',
      'evaluateCondition',
      'matchAction',
      'matchResource',
      'merge',
      'parse',
      'parseTokens',
      'serialize',
      'specificity',
      'tokenize',
      'validateNarrowing',
    ].sort());
  });

  // ─── @stele/core ────────────────────────────────────────────────────────────

  it('@stele/core exports', async () => {
    const mod = await import('@stele/core');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'CovenantBuildError',
      'CovenantVerificationError',
      'DocumentMigrator',
      'MAX_CHAIN_DEPTH',
      'MAX_CONSTRAINTS',
      'MAX_DOCUMENT_SIZE',
      'MemoryChainResolver',
      'PROTOCOL_VERSION',
      'buildCovenant',
      'canonicalForm',
      'computeEffectiveConstraints',
      'computeId',
      'countersignCovenant',
      'defaultMigrator',
      'deserializeCovenant',
      'resignCovenant',
      'resolveChain',
      'serializeCovenant',
      'validateChainNarrowing',
      'validateChainSchema',
      'validateConstraintsSchema',
      'validateDocumentSchema',
      'validatePartySchema',
      'verifyCovenant',
    ].sort());
  });

  // ─── @stele/store ───────────────────────────────────────────────────────────

  it('@stele/store exports', async () => {
    const mod = await import('@stele/store');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'FileStore',
      'IndexedStore',
      'MemoryStore',
      'QueryBuilder',
      'SqliteStore',
      'StoreIndex',
      'createQuery',
      'createTransaction',
    ].sort());
  });

  // ─── @stele/types ───────────────────────────────────────────────────────────

  it('@stele/types exports', async () => {
    const mod = await import('@stele/types');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'ActiveSpan',
      'CCLError',
      'ChainError',
      'CircuitBreaker',
      'Counter',
      'CryptoError',
      'DEFAULT_SEVERITY',
      'DocumentedErrorCode',
      'DocumentedSteleError',
      'Gauge',
      'HealthChecker',
      'Histogram',
      'InMemoryCollector',
      'LogLevel',
      'Logger',
      'MetricsRegistry',
      'STELE_VERSION',
      'SUPPORTED_HASH_ALGORITHMS',
      'SUPPORTED_SIGNATURE_SCHEMES',
      'SteleError',
      'SteleErrorCode',
      'StorageError',
      'Tracer',
      'ValidationError',
      'assertNever',
      'createDebugLogger',
      'createLogger',
      'createMetricsRegistry',
      'createTracer',
      'debug',
      'defaultLogger',
      'defaultMetrics',
      'deprecated',
      'err',
      'errorDocsUrl',
      'formatError',
      'freezeDeep',
      'getEmittedWarnings',
      'isDebugEnabled',
      'isNonEmptyString',
      'isPlainObject',
      'isValidHex',
      'isValidISODate',
      'isValidId',
      'isValidPublicKey',
      'isValidSignature',
      'isValidVersion',
      'ok',
      'resetDeprecationWarnings',
      'sanitizeJsonInput',
      'sanitizeString',
      'validateHex',
      'validateNonEmpty',
      'validateProbability',
      'validateRange',
      'withRetry',
      'wrapDeprecated',
    ].sort());
  });

  // ─── @stele/identity ────────────────────────────────────────────────────────

  it('@stele/identity exports', async () => {
    const mod = await import('@stele/identity');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'AdaptiveCarryForward',
      'DEFAULT_EVOLUTION_POLICY',
      'IdentitySimilarity',
      'LineageCompactor',
      'SemanticVersion',
      'computeCapabilityManifestHash',
      'computeCarryForward',
      'computeIdentityHash',
      'createIdentity',
      'deserializeIdentity',
      'evolveIdentity',
      'getLineage',
      'serializeIdentity',
      'shareAncestor',
      'verifyIdentity',
    ].sort());
  });

  // ─── @stele/verifier ────────────────────────────────────────────────────────

  it('@stele/verifier exports', async () => {
    const mod = await import('@stele/verifier');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'Verifier',
      'verifyBatch',
    ].sort());
  });

  // ─── @stele/enforcement ─────────────────────────────────────────────────────

  it('@stele/enforcement exports', async () => {
    const mod = await import('@stele/enforcement');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'AuditChain',
      'CapabilityError',
      'CapabilityGate',
      'Monitor',
      'MonitorDeniedError',
      'verifyMerkleProof',
    ].sort());
  });

  // ─── @stele/sdk ─────────────────────────────────────────────────────────────

  it('@stele/sdk exports', async () => {
    const mod = await import('@stele/sdk');
    const exports = Object.keys(mod).sort();
    expect(exports).toEqual([
      'AGENT_KEY_SCHEMA',
      'CCL_EVALUATION_CONTEXT_SCHEMA',
      'CCLSyntaxError',
      'CCLValidationError',
      'CONFIGURATION_PATH',
      'COVENANT_SCHEMA',
      'CovenantBuildError',
      'CovenantVerificationError',
      'DEFAULT_EVOLUTION_POLICY',
      'DEFAULT_SCORING_CONFIG',
      'DISCOVERY_DOCUMENT_SCHEMA',
      'DiscoveryClient',
      'DiscoveryServer',
      'FIELD_PRIME',
      'FileStore',
      'IndexedStore',
      'KeyManager',
      'MAX_CHAIN_DEPTH',
      'MAX_CONSTRAINTS',
      'MAX_DOCUMENT_AGE_MS',
      'MAX_DOCUMENT_SIZE',
      'MemoryChainResolver',
      'MemoryStore',
      'MiddlewarePipeline',
      'NoopCounter',
      'NoopHistogram',
      'NoopMeter',
      'NoopSpan',
      'NoopTracer',
      'PROTOCOL_VERSION',
      'QueryBuilder',
      'QuickCovenant',
      'STELE_MEDIA_TYPE',
      'SpanStatusCode',
      'SqliteStore',
      'SteleAccessDeniedError',
      'SteleCallbackHandler',
      'SteleClient',
      'SteleMetrics',
      'StoreIndex',
      'TrustGraph',
      'Verifier',
      'WELL_KNOWN_PATH',
      'attestationChainVerify',
      'authMiddleware',
      'base64urlDecode',
      'base64urlEncode',
      'buildCovenant',
      'buildDiscoveryDocument',
      'buildKeyEntry',
      'buildKeySet',
      'burnDelegation',
      'burnStake',
      'cachingMiddleware',
      'canonicalForm',
      'canonicalizeJson',
      'cclConformance',
      'checkRateLimit',
      'coBurnDelegation',
      'computeAttestationCoverage',
      'computeAuditCommitment',
      'computeCapabilityManifestHash',
      'computeCarryForward',
      'computeConstraintCommitment',
      'computeEffectiveConstraints',
      'computeId',
      'computeIdentityHash',
      'computeReceiptsMerkleRoot',
      'computeReputationScore',
      'constantTimeEqual',
      'countersignCovenant',
      'countersignReceipt',
      'covenantConformance',
      'createAttestation',
      'createBreachAttestation',
      'createChainGuard',
      'createCovenantRouter',
      'createDelegation',
      'createEndorsement',
      'createIdentity_core',
      'createQuery',
      'createReceipt',
      'createStake',
      'createTelemetry',
      'createToolGuard',
      'createTransaction',
      'cryptoConformance',
      'deserializeCovenant',
      'deserializeIdentity',
      'evaluateCCL',
      'evaluateCondition',
      'evolveIdentity_core',
      'executeWithRetry',
      'fieldToHex',
      'fromHex',
      'generateComplianceProof',
      'generateId',
      'generateKeyPair',
      'generateNonce',
      'getAllSchemas',
      'getDiscrepancies',
      'getLineage',
      'hashToField',
      'interopConformance',
      'isSigned',
      'keyPairFromPrivateKey',
      'keyPairFromPrivateKeyHex',
      'loggingMiddleware',
      'matchAction',
      'matchResource',
      'mergeCCL',
      'metricsMiddleware',
      'parseCCL',
      'parseTokens',
      'poseidonHash',
      'rateLimitMiddleware',
      'reconcile',
      'releaseStake',
      'resignCovenant',
      'resolveChain_core',
      'retryMiddleware',
      'runConformanceSuite',
      'securityConformance',
      'serializeCCL',
      'serializeCovenant',
      'serializeIdentity',
      'sha256',
      'sha256Object',
      'sha256String',
      'shareAncestor',
      'sign',
      'signAttestation',
      'signString',
      'specificity',
      'steleGuardHandler',
      'steleMiddleware',
      'telemetryMiddleware',
      'timestamp',
      'timingMiddleware',
      'toHex',
      'tokenize',
      'validateAgentKeySchema',
      'validateChainNarrowing',
      'validateCovenantSchema',
      'validateDiscoveryDocument',
      'validateDiscoverySchema',
      'validateNarrowing',
      'validationMiddleware',
      'verify',
      'verifyAttestation',
      'verifyBatch',
      'verifyBreachAttestation',
      'verifyComplianceProof',
      'verifyCovenant_core',
      'verifyEndorsement',
      'verifyIdentity',
      'verifyReceipt',
      'verifyReceiptChain',
      'withStele',
      'withSteleTool',
      'withSteleTools',
    ].sort());
  });

  // ─── Cross-package consistency checks ───────────────────────────────────────

  describe('Cross-package consistency', () => {

    it('PROTOCOL_VERSION is consistent across core and sdk', async () => {
      const core = await import('@stele/core');
      const sdk = await import('@stele/sdk');
      expect(core.PROTOCOL_VERSION).toBe(sdk.PROTOCOL_VERSION);
    });

    it('MAX_CHAIN_DEPTH is consistent across core and sdk', async () => {
      const core = await import('@stele/core');
      const sdk = await import('@stele/sdk');
      expect(core.MAX_CHAIN_DEPTH).toBe(sdk.MAX_CHAIN_DEPTH);
    });

    it('buildCovenant is the same function in core and sdk', async () => {
      const core = await import('@stele/core');
      const sdk = await import('@stele/sdk');
      expect(core.buildCovenant).toBe(sdk.buildCovenant);
    });

    it('generateKeyPair is the same function in crypto and sdk', async () => {
      const crypto = await import('@stele/crypto');
      const sdk = await import('@stele/sdk');
      expect(crypto.generateKeyPair).toBe(sdk.generateKeyPair);
    });

    it('parse from ccl is the same function as parseCCL from sdk', async () => {
      const ccl = await import('@stele/ccl');
      const sdk = await import('@stele/sdk');
      expect(ccl.parse).toBe(sdk.parseCCL);
    });
  });
});
