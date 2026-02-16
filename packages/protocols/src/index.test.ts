import { describe, it, expect } from 'vitest';

describe('@stele/protocols', () => {
  it('re-exports breach detection', async () => {
    const mod = await import('./index');
    expect(mod.createBreachAttestation).toBeTypeOf('function');
    expect(mod.TrustGraph).toBeTypeOf('function');
  });

  it('re-exports reputation', async () => {
    const mod = await import('./index');
    expect(mod.computeReputationScore).toBeTypeOf('function');
    expect(mod.createReceipt).toBeTypeOf('function');
  });

  it('re-exports proof', async () => {
    const mod = await import('./index');
    expect(mod.generateComplianceProof).toBeTypeOf('function');
    expect(mod.FIELD_PRIME).toBeTypeOf('bigint');
  });

  it('re-exports game theory', async () => {
    const mod = await import('./index');
    expect(mod.proveHonesty).toBeTypeOf('function');
    expect(mod.validateGameTheoryParameters).toBeTypeOf('function');
  });

  it('re-exports consensus', async () => {
    const mod = await import('./index');
    expect(mod.byzantineFaultTolerance).toBeTypeOf('function');
    expect(mod.StreamlinedBFT).toBeTypeOf('function');
  });

  it('re-exports discovery', async () => {
    const mod = await import('./index');
    expect(mod.DiscoveryClient).toBeTypeOf('function');
    expect(mod.WELL_KNOWN_PATH).toBeTypeOf('string');
  });

  it('re-exports schema', async () => {
    const mod = await import('./index');
    expect(mod.validateCovenantSchema).toBeTypeOf('function');
    expect(mod.COVENANT_SCHEMA).toBeDefined();
  });

  it('re-exports temporal', async () => {
    const mod = await import('./index');
    expect(mod.defineEvolution).toBeTypeOf('function');
    expect(mod.DecayModel).toBeTypeOf('function');
  });

  it('aliases conflicting names correctly', async () => {
    const mod = await import('./index');
    // canary.isExpired → isCanaryExpired
    expect(mod.isCanaryExpired).toBeTypeOf('function');
    // negotiation.isExpired → isNegotiationExpired
    expect(mod.isNegotiationExpired).toBeTypeOf('function');
    // negotiation.initiate → initiateNegotiation
    expect(mod.initiateNegotiation).toBeTypeOf('function');
    // negotiation.evaluate → evaluateNegotiation
    expect(mod.evaluateNegotiation).toBeTypeOf('function');
  });
});
