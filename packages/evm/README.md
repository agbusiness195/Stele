# @grith/evm

EVM anchoring utilities for on-chain covenant verification with ABI encoding and Keccak-256 hashing.

## Installation

```bash
npm install @grith/evm
```

## Key APIs

- **EVMClient**: Client for anchoring and verifying covenants on-chain via a user-supplied JSON-RPC provider. No ethers.js dependency.
- **encodeUint256() / decodeUint256()**: ABI encode/decode uint256 values.
- **encodeBytes32() / decodeBytes32()**: ABI encode/decode bytes32 values.
- **encodeAddress() / decodeAddress()**: ABI encode/decode EVM addresses with EIP-55 checksumming.
- **encodeString()**: ABI encode dynamic strings.
- **encodeFunctionCall()**: Concatenate a 4-byte selector with ABI-encoded parameters.
- **computeFunctionSelector()**: Compute the 4-byte Keccak-256 selector for a Solidity function signature.
- **buildAnchorCalldata() / parseAnchorFromCalldata()**: Encode/decode covenant anchor calldata.
- **computeAnchorHash()**: Deterministic Keccak-256 hash of a CovenantAnchor.
- **checksumAddress()**: EIP-55 mixed-case checksum encoding.
- **isValidAddress()**: Validate EVM addresses.
- **keccak256()**: Keccak-256 hashing for EVM-compatible use cases.
- **GRITH_REGISTRY_ABI**: JSON ABI for the on-chain Grith registry contract.

## Usage

```typescript
import { EVMClient, buildAnchorCalldata, computeAnchorHash } from '@grith/evm';

// Plug in any JSON-RPC provider (ethers, viem, raw fetch, etc.)
const client = new EVMClient(myProvider, '0xRegistryAddress');

const anchor = {
  covenantId: '00'.repeat(32),
  constraintsHash: 'ab'.repeat(32),
  issuerAddress: '0x' + '11'.repeat(20),
  beneficiaryAddress: '0x' + '22'.repeat(20),
  timestamp: BigInt(Date.now()),
  chainId: 1,
};

const txHash = await client.anchorCovenant(anchor, fromAddress);
const receipt = await client.waitForTransaction(txHash);
const isAnchored = await client.verifyCovenant(anchor.covenantId);
```

## Docs

See the [Grith SDK root documentation](../../README.md) for the full API reference.
