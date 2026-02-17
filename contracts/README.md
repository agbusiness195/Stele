# SteleRegistry Smart Contract

On-chain registry for anchoring and verifying Stele protocol covenant constraints on EVM-compatible blockchains.

## Overview

`SteleRegistry` is a minimal, ownerless, non-upgradeable smart contract that stores covenant anchors on-chain. Each anchor binds a unique `covenantId` to a constraints hash, issuer address, beneficiary address, and timestamp. Any party can verify whether a covenant has been anchored; only the original issuer can revoke it.

The contract implements the interface consumed by the `@stele/evm` TypeScript package (see `STELE_REGISTRY_ABI` and `SteleRegistryInterface` in `packages/evm/src/index.ts`).

## Contract Interface

### Structs

```solidity
struct Anchor {
    bytes32 constraintsHash;
    address issuer;
    address beneficiary;
    uint256 timestamp;
    bool exists;
}
```

### Functions

| Function | Mutability | Description |
|---|---|---|
| `anchor(bytes32,bytes32,address,address,uint256)` | nonpayable | Anchor a new covenant |
| `verify(bytes32)` | view | Check if a covenant is anchored |
| `getAnchor(bytes32)` | view | Retrieve full anchor data |
| `revoke(bytes32)` | nonpayable | Revoke an anchored covenant |
| `anchorBatch(bytes32[],bytes32[],address[],address[],uint256[])` | nonpayable | Batch anchor multiple covenants |
| `verifyBatch(bytes32[])` | view | Batch verify multiple covenants |
| `computeAnchorHash(bytes32,bytes32,address,address,uint256)` | pure | Compute deterministic hash of anchor data |
| `anchorCount()` | view | Return total number of live anchors |

### Events

```solidity
event CovenantAnchored(
    bytes32 indexed covenantId,
    bytes32 constraintsHash,
    address indexed issuer,
    address indexed beneficiary,
    uint256 timestamp
);

event CovenantRevoked(
    bytes32 indexed covenantId,
    address indexed revoker,
    uint256 timestamp
);
```

### Custom Errors

```solidity
error AnchorAlreadyExists(bytes32 covenantId);
error CallerNotIssuer(address caller, address expectedIssuer);
error TimestampInFuture(uint256 supplied, uint256 blockTimestamp);
error AnchorNotFound(bytes32 covenantId);
error ArrayLengthMismatch();
```

## ABI Compatibility with @stele/evm

The core three functions (`anchor`, `verify`, `getAnchor`) match the `STELE_REGISTRY_ABI` exported by `@stele/evm`:

```typescript
export const STELE_REGISTRY_ABI = [
  {
    name: 'anchor',
    type: 'function',
    inputs: [
      { name: 'covenantId', type: 'bytes32' },
      { name: 'constraintsHash', type: 'bytes32' },
      { name: 'issuer', type: 'address' },
      { name: 'beneficiary', type: 'address' },
      { name: 'timestamp', type: 'uint256' },
    ],
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    name: 'verify',
    type: 'function',
    inputs: [{ name: 'covenantId', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    name: 'getAnchor',
    type: 'function',
    inputs: [{ name: 'covenantId', type: 'bytes32' }],
    outputs: [
      { name: 'constraintsHash', type: 'bytes32' },
      { name: 'issuer', type: 'address' },
      { name: 'beneficiary', type: 'address' },
      { name: 'timestamp', type: 'uint256' },
    ],
    stateMutability: 'view',
  },
] as const;
```

The `EVMClient` class in `@stele/evm` uses `buildAnchorCalldata()` to construct the `anchor()` calldata and `computeFunctionSelector('verify(bytes32)')` / `computeFunctionSelector('getAnchor(bytes32)')` for read calls. These selectors match the deployed contract's function signatures exactly.

## Deployment

### Prerequisites

- Solidity compiler ^0.8.24
- [Foundry](https://book.getfoundry.sh/) (recommended) or [Hardhat](https://hardhat.org/)
- An RPC endpoint for the target chain
- A funded deployer account

### Using Foundry (Forge)

1. **Install Foundry** (if not already installed):

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

2. **Initialize a Foundry project** (from the repository root):

```bash
cd contracts
forge init --no-git --no-commit .
```

3. **Copy the contract** into `src/`:

```bash
cp SteleRegistry.sol src/SteleRegistry.sol
```

4. **Compile**:

```bash
forge build
```

5. **Run tests** (write tests in `test/`):

```bash
forge test
```

6. **Deploy to a live network**:

```bash
# Set your private key and RPC URL
export PRIVATE_KEY=0x...
export RPC_URL=https://...

# Deploy
forge create src/SteleRegistry.sol:SteleRegistry \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast
```

7. **Deploy to a local Anvil instance** (for development):

```bash
# Terminal 1: start Anvil
anvil

# Terminal 2: deploy
forge create src/SteleRegistry.sol:SteleRegistry \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### Using Hardhat

1. **Install dependencies**:

```bash
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
```

2. **Initialize Hardhat** (if not already configured):

```bash
npx hardhat init
```

3. **Copy the contract** into `contracts/`:

```bash
# If using Hardhat from the repo root, SteleRegistry.sol is already here.
```

4. **Compile**:

```bash
npx hardhat compile
```

5. **Create a deployment script** (`scripts/deploy.js`):

```javascript
const { ethers } = require("hardhat");

async function main() {
  const SteleRegistry = await ethers.getContractFactory("SteleRegistry");
  const registry = await SteleRegistry.deploy();
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log("SteleRegistry deployed to:", address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

6. **Deploy**:

```bash
# Local (Hardhat network)
npx hardhat run scripts/deploy.js

# Live network
npx hardhat run scripts/deploy.js --network <network-name>
```

## Example Interactions

### Using cast (Foundry)

```bash
REGISTRY=0x... # deployed contract address
ISSUER=0x...   # your address (must match --private-key signer)

# Anchor a covenant
cast send $REGISTRY \
  "anchor(bytes32,bytes32,address,address,uint256)" \
  0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  $ISSUER \
  0x0000000000000000000000000000000000000001 \
  $(date +%s) \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY

# Verify a covenant
cast call $REGISTRY \
  "verify(bytes32)(bool)" \
  0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --rpc-url $RPC_URL

# Get anchor data
cast call $REGISTRY \
  "getAnchor(bytes32)(bytes32,address,address,uint256)" \
  0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --rpc-url $RPC_URL

# Get anchor count
cast call $REGISTRY "anchorCount()(uint256)" --rpc-url $RPC_URL

# Revoke a covenant
cast send $REGISTRY \
  "revoke(bytes32)" \
  0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY
```

### Using @stele/evm (TypeScript)

```typescript
import { EVMClient } from '@stele/evm';
import type { CovenantAnchor, EVMProvider } from '@stele/evm';

// Wrap your JSON-RPC transport (fetch, ethers, viem, etc.)
const provider: EVMProvider = {
  request: async ({ method, params }) => {
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    const json = await res.json();
    return json.result;
  },
};

const client = new EVMClient(provider, REGISTRY_ADDRESS);

// Anchor
const anchor: CovenantAnchor = {
  covenantId: 'aa'.repeat(32),
  constraintsHash: 'bb'.repeat(32),
  issuerAddress: '0x1234567890123456789012345678901234567890',
  beneficiaryAddress: '0x0000000000000000000000000000000000000001',
  timestamp: BigInt(Math.floor(Date.now() / 1000)),
  chainId: 1,
};

const txHash = await client.anchorCovenant(anchor, anchor.issuerAddress);
const receipt = await client.waitForTransaction(txHash);

// Verify
const isAnchored = await client.verifyCovenant(anchor.covenantId);
console.log('Anchored:', isAnchored); // true

// Read back
const data = await client.getAnchor(anchor.covenantId);
console.log('Anchor data:', data);
```

## Security Considerations

### Access Control

- **No owner / admin**: The contract has no privileged roles. There is no pause, upgrade, or emergency mechanism. This is intentional -- the registry is a neutral public good.
- **Issuer-only anchoring**: The `anchor()` function requires `msg.sender == issuer`. This prevents impersonation; only the issuer can anchor a covenant on their own behalf.
- **Issuer-only revocation**: The `revoke()` function requires `msg.sender == anchors[covenantId].issuer`. No other party can revoke an anchor.

### Data Integrity

- **No overwrites**: Once a covenant is anchored, calling `anchor()` again with the same `covenantId` reverts with `AnchorAlreadyExists`. This guarantees immutability of the anchor data (unless revoked and re-anchored).
- **Timestamp validation**: The supplied `timestamp` must be `<= block.timestamp`. This prevents anchoring covenants with future dates.
- **Deletion on revoke**: `revoke()` uses Solidity's `delete` to zero out all storage slots for the anchor, including the `exists` flag.

### Gas and Denial of Service

- **No loops over unbounded storage**: The contract does not iterate over stored anchors. All lookups are O(1) by `covenantId`.
- **Batch size**: `anchorBatch()` and `verifyBatch()` iterate over caller-supplied arrays. Extremely large batches may hit the block gas limit. Callers should keep batch sizes reasonable (typically under 50-100 items depending on gas limits).
- **Unchecked arithmetic**: Counter increments/decrements use `unchecked` blocks. The `_anchorCount` counter cannot realistically overflow a `uint256`. The loop counters `i` cannot overflow within the array bounds.

### Reentrancy

- The contract does not make any external calls, so reentrancy is not a concern.

### Front-Running

- An adversary could observe a pending `anchor()` transaction and attempt to front-run it with a different anchor for the same `covenantId`. However, the `msg.sender == issuer` check means the attacker would need to be the same issuer address, which limits this to self-front-running (not a meaningful attack).

### Upgradability

- The contract is **not upgradeable**. If a new version is needed, deploy a new contract and update the registry address in client configurations. Historical anchors on the old contract remain verifiable.

## Gas Estimates

Approximate gas costs (may vary by compiler version, optimizer settings, and EVM version):

| Operation | Estimated Gas |
|---|---|
| `anchor()` (new covenant) | ~70,000 - 80,000 |
| `verify()` | ~5,000 - 8,000 |
| `getAnchor()` | ~5,000 - 10,000 |
| `revoke()` | ~15,000 - 25,000 |
| `anchorBatch()` (N items) | ~70,000 + N * 65,000 |
| `verifyBatch()` (N items) | ~5,000 + N * 3,000 |
| `computeAnchorHash()` | ~1,000 - 2,000 |
| `anchorCount()` | ~2,500 - 3,500 |

To get precise estimates, compile with the optimizer enabled and run gas benchmarks:

```bash
# Foundry
forge test --gas-report

# Hardhat
REPORT_GAS=true npx hardhat test
```

## Compiler Settings

Recommended `foundry.toml` for production:

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.24"
optimizer = true
optimizer_runs = 10000
evm_version = "cancun"
```

Recommended Hardhat config (`hardhat.config.js`):

```javascript
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 10000,
      },
      evmVersion: "cancun",
    },
  },
};
```

## License

MIT
