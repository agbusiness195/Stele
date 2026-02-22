# Decentralized Key Discovery and Attestation

**Version 1.0.0 — 2026-02-17**

---

## 1. Overview

This document specifies the decentralized key discovery and attestation mechanism
for the Nobulex protocol. It extends the existing `.well-known/nobulex/` discovery
protocol with peer-to-peer key resolution, distributed hash table (DHT) backed
key registries, and cross-domain attestation chains.

### Design Goals

1. **No single point of failure.** Key discovery must not depend on any single
   server, registry, or certificate authority.
2. **Cryptographic binding.** Every key-to-identity mapping must be signed by
   the identity's current key, forming a self-certifying namespace.
3. **Offline verification.** A verifier with a cached key set can verify
   covenants without network access.
4. **Incremental adoption.** The mechanism must be backward-compatible with
   the existing `.well-known/nobulex/` protocol.

---

## 2. Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Agent A        │     │   DHT Network   │     │  Agent B        │
│                 │     │                 │     │                 │
│  ┌───────────┐  │     │  ┌───────────┐  │     │  ┌───────────┐  │
│  │ Key Store │──┼─────┼─▶│ Key Index │◀─┼─────┼──│ Key Store │  │
│  └───────────┘  │     │  └───────────┘  │     │  └───────────┘  │
│                 │     │                 │     │                 │
│  ┌───────────┐  │     │  ┌───────────┐  │     │  ┌───────────┐  │
│  │ Resolver  │──┼─────┼─▶│ Attestation│◀─┼─────┼──│ Resolver  │  │
│  └───────────┘  │     │  │   Store   │  │     │  └───────────┘  │
│                 │     │  └───────────┘  │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Components

- **Key Store**: Local storage of an agent's own keys and known peer keys.
- **DHT Network**: A Kademlia-style distributed hash table for key publication.
- **Key Index**: DHT-stored mappings from agent identity to public key records.
- **Attestation Store**: DHT-stored cross-domain attestation records.
- **Resolver**: Client-side logic for multi-source key resolution.

---

## 3. Key Record Format

A **Key Record** is a signed, self-certifying document published by an agent:

```json
{
  "nobulex": "1.0",
  "kind": "key-record",
  "agentId": "<agent-identity-hash>",
  "publicKey": "<Ed25519 public key, hex>",
  "previousKey": "<previous public key, hex | null>",
  "endpoints": [
    "https://agent-a.example.com/.well-known/nobulex/",
    "ipfs://Qm.../nobulex/"
  ],
  "capabilities": ["covenant.issue", "covenant.verify"],
  "published": "<ISO 8601 UTC>",
  "expires": "<ISO 8601 UTC>",
  "sequence": 1,
  "signature": "<Ed25519 signature, hex>"
}
```

### Field Semantics

| Field | Type | Description |
|-------|------|-------------|
| `agentId` | string | SHA-256 hash of the agent's identity document. |
| `publicKey` | string | Current Ed25519 public key (64 hex chars). |
| `previousKey` | string \| null | Previous public key for key rotation verification. |
| `endpoints` | string[] | Discovery endpoints where the agent can be reached. |
| `capabilities` | string[] | Protocol capabilities this agent supports. |
| `published` | string | ISO 8601 UTC timestamp of publication. |
| `expires` | string | ISO 8601 UTC timestamp after which the record is stale. |
| `sequence` | integer | Monotonically increasing counter for key rotation. |
| `signature` | string | Ed25519 signature over the canonical form. |

### Canonical Form

The canonical form strips `signature` and applies JCS (RFC 8785) canonicalization,
identical to the covenant canonical form algorithm.

### Self-Certification

A key record is self-certifying: the `publicKey` field contains the key that
signs the record. Verification requires only the record itself — no external
authority is needed.

For key rotations (sequence > 1), the `previousKey` field enables chain
verification: the new record must be signed by the new key, and the transition
from `previousKey` to `publicKey` must be attested by the previous key
(via a **Key Rotation Attestation**).

---

## 4. DHT Key Index

### Publication

When an agent publishes a key record:

1. Compute the DHT key: `DHT_KEY = SHA-256(agentId)`.
2. Sign the key record with the agent's current private key.
3. Store the record at `DHT_KEY` in the DHT network.
4. Replicate to the `k` closest nodes (Kademlia `k` parameter, default 20).

### Resolution

To resolve an agent's public key:

```
function resolve_key(agent_id):
    dht_key = SHA-256(agent_id)

    // 1. Check local cache
    cached = local_cache.get(dht_key)
    if cached and not expired(cached):
        return cached

    // 2. Query DHT
    records = dht.find_value(dht_key)
    if records is empty:
        // 3. Fall back to .well-known
        return well_known_resolve(agent_id)

    // 4. Select the record with the highest sequence number
    best = max(records, key=r.sequence)

    // 5. Verify self-certification
    if not verify_key_record(best):
        return ERROR("invalid key record")

    // 6. Cache and return
    local_cache.put(dht_key, best, ttl=best.expires)
    return best
```

### Conflict Resolution

When multiple records exist for the same `agentId`:

1. **Highest sequence wins.** The record with the highest `sequence` value is
   canonical, provided it can be verified.
2. **Key rotation chain.** For a record with sequence `n > 1`, the DHT must
   also contain a valid record with sequence `n - 1` whose `publicKey` matches
   the current record's `previousKey`.
3. **Expiration.** Expired records are evicted during DHT maintenance.

---

## 5. Cross-Domain Attestation

A **Cross-Domain Attestation** is a signed statement by one agent vouching for
another agent's key binding:

```json
{
  "nobulex": "1.0",
  "kind": "key-attestation",
  "subject": {
    "agentId": "<subject agent ID>",
    "publicKey": "<subject's public key, hex>",
    "sequence": 5
  },
  "attester": {
    "agentId": "<attester agent ID>",
    "publicKey": "<attester's public key, hex>"
  },
  "confidence": 0.95,
  "evidence": ["<covenant-receipt-id>", "<covenant-receipt-id>"],
  "published": "<ISO 8601 UTC>",
  "expires": "<ISO 8601 UTC>",
  "signature": "<attester's Ed25519 signature, hex>"
}
```

### Attestation Semantics

- An attestation binds a specific `(agentId, publicKey, sequence)` triple.
- `confidence` is a value in [0, 1] indicating the attester's confidence.
- `evidence` references execution receipts that substantiate the attestation.
- Attestations expire and must be refreshed periodically.

### Attestation Graph

Attestations form a directed graph that can be traversed for trust computation:

```
Agent A ──attests──▶ Agent B ──attests──▶ Agent C
   │                                         ▲
   └─────────────attests─────────────────────┘
```

The weight of an attestation path is the product of confidence values along
the path, with a maximum path length of 5 hops (matching the protocol's
`MAX_PROPAGATION_DEPTH`).

---

## 6. Key Rotation Attestation

When an agent rotates its key, it produces a **Key Rotation Attestation**
signed by the **previous** key:

```json
{
  "nobulex": "1.0",
  "kind": "key-rotation",
  "agentId": "<agent ID>",
  "previousKey": "<old public key, hex>",
  "newKey": "<new public key, hex>",
  "previousSequence": 4,
  "newSequence": 5,
  "reason": "scheduled-rotation",
  "published": "<ISO 8601 UTC>",
  "signature": "<signature by PREVIOUS key, hex>"
}
```

Verification:
1. Verify the signature using `previousKey`.
2. Verify that `previousSequence + 1 == newSequence`.
3. Verify that a key record exists for `(agentId, previousKey, previousSequence)`.

---

## 7. Multi-Source Resolution Strategy

The resolver uses a cascading strategy to maximize availability:

```
Priority 1: Local cache (fastest, may be stale)
Priority 2: DHT network (decentralized, eventual consistency)
Priority 3: .well-known endpoint (centralized, authoritative)
Priority 4: Cross-domain attestations (social proof)
```

For high-security contexts, the resolver can require **quorum verification**:
a key is considered valid only if it is confirmed by at least `q` independent
sources (default `q = 2`).

### Quorum Verification Algorithm

```
function quorum_resolve(agent_id, q=2):
    sources = []

    // Collect from all sources in parallel
    dht_record = dht.find_value(SHA-256(agent_id))
    wk_record = well_known_resolve(agent_id)
    attestations = dht.find_attestations(agent_id)

    if dht_record: sources.append(dht_record.publicKey)
    if wk_record: sources.append(wk_record.publicKey)
    for att in attestations:
        if verify_attestation(att):
            sources.append(att.subject.publicKey)

    // Count agreement
    key_counts = count_occurrences(sources)
    best_key = max(key_counts, key=count)

    if key_counts[best_key] >= q:
        return best_key
    else:
        return ERROR("quorum not reached")
```

---

## 8. Revocation

Key revocation is handled through the existing key rotation mechanism:

1. The agent publishes a new key record with an incremented sequence.
2. The agent publishes a key rotation attestation signed by the old key.
3. Verifiers checking covenants signed by the old key after the rotation
   timestamp reject them as invalid.

For emergency revocation (compromised key), the agent publishes a
**Revocation Record**:

```json
{
  "nobulex": "1.0",
  "kind": "key-revocation",
  "agentId": "<agent ID>",
  "revokedKey": "<compromised public key, hex>",
  "revokedSequence": 5,
  "reason": "key-compromise",
  "published": "<ISO 8601 UTC>",
  "signature": "<signature by NEW key OR by a designated recovery key, hex>"
}
```

Emergency revocations must be signed by either:
- A newer key in the rotation chain, or
- A pre-designated recovery key specified in the agent's identity document.

---

## 9. Protocol Constants

| Parameter | Value | Description |
|-----------|-------|-------------|
| `DHT_REPLICATION_FACTOR` | 20 | Number of nodes storing each key record |
| `KEY_RECORD_TTL` | 30 days | Default time-to-live for key records |
| `ATTESTATION_TTL` | 90 days | Default time-to-live for attestations |
| `MAX_ATTESTATION_DEPTH` | 5 | Maximum attestation chain depth |
| `QUORUM_DEFAULT` | 2 | Default quorum for high-security resolution |
| `CACHE_TTL` | 1 hour | Default local cache time-to-live |
| `MAX_SEQUENCE_GAP` | 1 | Maximum allowed gap in sequence numbers |

---

## 10. Security Considerations

### Eclipse Attacks

An attacker controlling nodes around a DHT key could serve false key records.
Mitigations:
- Self-certification ensures records are verifiable without trusting DHT nodes.
- Quorum verification across multiple sources detects inconsistencies.
- .well-known fallback provides an authoritative source.

### Key Compromise

If an agent's key is compromised before rotation:
- The attacker can publish valid key records and sign covenants.
- Emergency revocation via a recovery key limits the window of vulnerability.
- Cross-domain attestations provide social evidence of the legitimate key.

### Sybil Attacks on Attestations

An attacker creating many identities to attest a false key:
- Attestation weight depends on attester reputation (§7.2 of PROTOCOL.md).
- Low-reputation attesters contribute negligible weight.
- Quorum verification with diverse sources mitigates coordinated attestation fraud.

---

## 11. Compatibility

This mechanism is fully backward-compatible with the existing discovery protocol:

- Agents that only support `.well-known/nobulex/` continue to work unchanged.
- DHT publication is optional; resolution falls back to `.well-known`.
- Cross-domain attestations are supplementary, not required.
- The key record format extends (does not replace) the existing `AgentKeyEntry`.
