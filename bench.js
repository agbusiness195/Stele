const { buildCovenant, verifyCovenant } = require('@usekova/core');
const { generateKeyPair } = require('@usekova/crypto');

(async () => {
  const issuer = await generateKeyPair();
  const beneficiary = await generateKeyPair();

  let start = Date.now();
  const covenants = [];
  for (let i = 0; i < 100; i++) {
    covenants.push(await buildCovenant({
      issuer: { id: 'agent-' + i, publicKey: Buffer.from(issuer.publicKey).toString('hex'), role: 'issuer' },
      beneficiary: { id: 'user-' + i, publicKey: Buffer.from(beneficiary.publicKey).toString('hex'), role: 'beneficiary' },
      constraints: "permit read on '/data/**'",
      privateKey: issuer.privateKey
    }));
  }
  let elapsed = Date.now() - start;
  console.log('BUILD 100 covenants: ' + elapsed + 'ms (' + (elapsed/100).toFixed(2) + 'ms each)');

  start = Date.now();
  let validCount = 0;
  for (const c of covenants) {
    const v = await verifyCovenant(c);
    if (v === true || (v && v.valid === true)) validCount++;
  }
  elapsed = Date.now() - start;
  console.log('VERIFY 100 covenants: ' + elapsed + 'ms (' + (elapsed/100).toFixed(2) + 'ms each) valid: ' + validCount + '/100');

  // Check what verifyCovenant actually returns
  const sample = await verifyCovenant(covenants[0]);
  console.log('Verify return type:', typeof sample, JSON.stringify(sample).substring(0, 200));

  start = Date.now();
  for (let i = 0; i < 1000; i++) {
    const c = await buildCovenant({
      issuer: { id: 'a-' + i, publicKey: Buffer.from(issuer.publicKey).toString('hex'), role: 'issuer' },
      beneficiary: { id: 'b-' + i, publicKey: Buffer.from(beneficiary.publicKey).toString('hex'), role: 'beneficiary' },
      constraints: "deny transfer on '/bank/**'",
      privateKey: issuer.privateKey
    });
    await verifyCovenant(c);
  }
  elapsed = Date.now() - start;
  console.log('BUILD+VERIFY 1000 covenants: ' + elapsed + 'ms (' + (elapsed/1000).toFixed(2) + 'ms each)');
  console.log('Target: sub-50ms per operation. Result: ' + ((elapsed/1000) < 50 ? 'PASSED' : 'FAILED'));
})().catch(e => console.error('FAILED:', e));
