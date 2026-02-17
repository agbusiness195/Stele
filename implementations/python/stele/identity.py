"""
Stele Agent Identity creation, evolution, and verification.

Implements the full agent identity lifecycle: creation, evolution with lineage
tracking, cryptographic verification, and serialization.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Optional

from . import crypto


# ---------------------------------------------------------------------------
# Default evolution policy
# ---------------------------------------------------------------------------

DEFAULT_EVOLUTION_POLICY: dict[str, float] = {
    "minorUpdate": 0.95,
    "modelVersionChange": 0.80,
    "modelFamilyChange": 0.20,
    "operatorTransfer": 0.50,
    "capabilityExpansion": 0.90,
    "capabilityReduction": 1.00,
    "fullRebuild": 0.00,
}


# ---------------------------------------------------------------------------
# Hash utilities
# ---------------------------------------------------------------------------

def compute_capability_manifest_hash(capabilities: list[str]) -> str:
    """Compute a canonical hash of a sorted capabilities list.

    Capabilities are sorted lexicographically before hashing to ensure
    determinism regardless of input order.

    Args:
        capabilities: Array of capability strings.

    Returns:
        A hex-encoded SHA-256 hash of the canonical capability list.
    """
    sorted_caps = sorted(capabilities)
    return crypto.sha256_string(crypto.canonicalize_json(sorted_caps))


def compute_identity_hash(body: dict) -> str:
    """Compute the composite identity hash from all identity-defining fields.

    The hash covers operator key, model attestation, capability manifest,
    deployment context, and the full lineage chain.

    Args:
        body: The identity fields (excluding 'id' and 'signature').

    Returns:
        A hex-encoded SHA-256 composite hash.
    """
    composite = {
        "operatorPublicKey": body["operatorPublicKey"],
        "model": body["model"],
        "capabilityManifestHash": body["capabilityManifestHash"],
        "deployment": body["deployment"],
        "lineage": body["lineage"],
    }
    return crypto.sha256_object(composite)


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------

def _identity_signing_payload(identity: dict) -> str:
    """Build the canonical string representation of an identity for signing.

    Excludes 'signature' since that is what we are producing.
    """
    body = {k: v for k, v in identity.items() if k != "signature"}
    return crypto.canonicalize_json(body)


def _lineage_signing_payload(entry: dict) -> str:
    """Build the canonical string for a lineage entry before its signature is set."""
    return crypto.canonicalize_json(entry)


# ---------------------------------------------------------------------------
# Create identity
# ---------------------------------------------------------------------------

def create_identity(options: dict) -> dict:
    """Create a brand-new agent identity.

    Computes the capability manifest hash and composite identity hash,
    initialises a single lineage entry of type 'created', and signs
    the whole identity with the provided operator key pair.

    Args:
        options: Creation options dict with keys:
          - operatorKeyPair: dict with private_key (bytes), public_key (bytes),
            public_key_hex (str)
          - model: dict with provider, modelId, and optional fields
          - capabilities: list[str]
          - deployment: dict with runtime and optional fields
          - operatorIdentifier: optional str

    Returns:
        A fully signed AgentIdentity dict with version 1 and one lineage entry.

    Raises:
        ValueError: When required fields are missing.
    """
    if not options or not isinstance(options, dict):
        raise ValueError("createIdentity() requires a valid options dict")

    operator_key_pair = options.get("operatorKeyPair")
    if (
        not operator_key_pair
        or not operator_key_pair.get("private_key")
        or not operator_key_pair.get("public_key")
        or not operator_key_pair.get("public_key_hex")
    ):
        raise ValueError(
            "createIdentity() requires a valid operatorKeyPair with "
            "private_key, public_key, and public_key_hex"
        )

    model = options.get("model")
    if not model or not isinstance(model, dict):
        raise ValueError("createIdentity() requires a valid model attestation dict")

    capabilities = options.get("capabilities")
    if not isinstance(capabilities, list):
        raise ValueError("createIdentity() requires a capabilities list")

    deployment = options.get("deployment")
    if not deployment or not isinstance(deployment, dict):
        raise ValueError("createIdentity() requires a valid deployment context dict")

    operator_identifier = options.get("operatorIdentifier")
    now = crypto.timestamp()
    capability_manifest_hash = compute_capability_manifest_hash(capabilities)

    # Build a partial identity (no id/signature yet)
    partial_for_lineage: dict[str, Any] = {
        "operatorPublicKey": operator_key_pair["public_key_hex"],
        "model": model,
        "capabilities": sorted(capabilities),
        "capabilityManifestHash": capability_manifest_hash,
        "deployment": deployment,
        "lineage": [],
        "version": 1,
        "createdAt": now,
        "updatedAt": now,
    }
    if operator_identifier is not None:
        partial_for_lineage["operatorIdentifier"] = operator_identifier

    # Compute a preliminary identity hash (lineage empty) for the first lineage entry
    preliminary_hash = compute_identity_hash(partial_for_lineage)

    # Build the lineage entry (unsigned first, then signed)
    lineage_entry_unsigned: dict[str, Any] = {
        "identityHash": preliminary_hash,
        "changeType": "created",
        "description": "Identity created",
        "timestamp": now,
        "parentHash": None,
        "reputationCarryForward": 1.0,
    }

    lineage_payload = _lineage_signing_payload(lineage_entry_unsigned)
    lineage_sig = crypto.sign_string(lineage_payload, operator_key_pair["private_key"])
    lineage_entry = {
        **lineage_entry_unsigned,
        "signature": crypto.to_hex(lineage_sig),
    }

    # Rebuild identity with the final lineage chain
    identity_no_id_sig = {**partial_for_lineage, "lineage": [lineage_entry]}

    # Compute the final composite identity hash
    identity_id = compute_identity_hash(identity_no_id_sig)

    # Sign the full identity (including id)
    identity_for_signing = {**identity_no_id_sig, "id": identity_id}
    identity_sig = crypto.sign_string(
        _identity_signing_payload(identity_for_signing),
        operator_key_pair["private_key"],
    )

    identity: dict[str, Any] = {
        **identity_for_signing,
        "signature": crypto.to_hex(identity_sig),
    }

    return identity


# ---------------------------------------------------------------------------
# Evolve identity
# ---------------------------------------------------------------------------

def _compute_carry_forward(
    change_type: str,
    current: dict,
    updates: dict,
    policy: Optional[dict[str, float]] = None,
) -> float:
    """Compute the reputation carry-forward rate for an identity evolution."""
    pol = policy or DEFAULT_EVOLUTION_POLICY

    if change_type == "created":
        return 1.0

    if change_type == "model_update":
        new_model = updates.get("model")
        if new_model:
            same_family = (
                new_model.get("provider") == current["model"].get("provider")
                and new_model.get("modelId") == current["model"].get("modelId")
            )
            return pol["modelVersionChange"] if same_family else pol["modelFamilyChange"]
        return pol["minorUpdate"]

    if change_type == "capability_change":
        new_caps = updates.get("capabilities")
        if new_caps:
            current_set = set(current["capabilities"])
            new_set = set(new_caps)
            added = [c for c in new_caps if c not in current_set]
            removed = [c for c in current["capabilities"] if c not in new_set]

            if added and not removed:
                return pol["capabilityExpansion"]
            if removed and not added:
                return pol["capabilityReduction"]
            return min(pol["capabilityExpansion"], pol["capabilityReduction"])
        return pol["minorUpdate"]

    if change_type == "operator_transfer":
        return pol["operatorTransfer"]

    if change_type == "fork":
        return pol["operatorTransfer"]

    if change_type == "merge":
        return min(pol["capabilityExpansion"], pol["modelVersionChange"])

    return pol["fullRebuild"]


def evolve_identity(identity: dict, options: dict) -> dict:
    """Evolve an existing identity by applying updates.

    Returns a new AgentIdentity dict (the original is never mutated).

    Args:
        identity: The existing identity dict.
        options: Evolution options dict with keys:
          - operatorKeyPair: dict with private_key, public_key, public_key_hex
          - changeType: str
          - description: str
          - updates: dict with optional model, capabilities, deployment,
            operatorPublicKey, operatorIdentifier
          - reputationCarryForward: optional float

    Returns:
        A new AgentIdentity dict with incremented version and extended lineage.
    """
    operator_key_pair = options["operatorKeyPair"]
    change_type = options["changeType"]
    description = options["description"]
    updates = options.get("updates", {})

    now = crypto.timestamp()

    new_model = updates.get("model", identity["model"])
    new_capabilities = sorted(updates["capabilities"]) if updates.get("capabilities") else sorted(identity["capabilities"])
    new_deployment = updates.get("deployment", identity["deployment"])
    new_operator_public_key = updates.get("operatorPublicKey", operator_key_pair["public_key_hex"])
    new_operator_identifier = updates.get("operatorIdentifier", identity.get("operatorIdentifier"))

    capability_manifest_hash = compute_capability_manifest_hash(new_capabilities)

    reputation_carry_forward = options.get(
        "reputationCarryForward",
        _compute_carry_forward(change_type, identity, updates),
    )

    new_version = identity["version"] + 1

    partial_for_lineage: dict[str, Any] = {
        "operatorPublicKey": new_operator_public_key,
        "model": new_model,
        "capabilities": new_capabilities,
        "capabilityManifestHash": capability_manifest_hash,
        "deployment": new_deployment,
        "lineage": identity["lineage"],  # carried forward; extended below
        "version": new_version,
        "createdAt": identity["createdAt"],
        "updatedAt": now,
    }
    if new_operator_identifier is not None:
        partial_for_lineage["operatorIdentifier"] = new_operator_identifier

    preliminary_hash = compute_identity_hash(partial_for_lineage)

    # Previous lineage tail hash
    parent_hash = (
        identity["lineage"][-1]["identityHash"]
        if identity["lineage"]
        else None
    )

    # Build and sign the new lineage entry
    lineage_entry_unsigned: dict[str, Any] = {
        "identityHash": preliminary_hash,
        "changeType": change_type,
        "description": description,
        "timestamp": now,
        "parentHash": parent_hash,
        "reputationCarryForward": reputation_carry_forward,
    }

    lineage_payload = _lineage_signing_payload(lineage_entry_unsigned)
    lineage_sig = crypto.sign_string(lineage_payload, operator_key_pair["private_key"])
    lineage_entry = {
        **lineage_entry_unsigned,
        "signature": crypto.to_hex(lineage_sig),
    }

    # Final lineage chain
    new_lineage = list(identity["lineage"]) + [lineage_entry]

    # Rebuild identity with final lineage
    identity_no_id_sig = {**partial_for_lineage, "lineage": new_lineage}

    identity_id = compute_identity_hash(identity_no_id_sig)

    identity_for_signing = {**identity_no_id_sig, "id": identity_id}
    identity_sig = crypto.sign_string(
        _identity_signing_payload(identity_for_signing),
        operator_key_pair["private_key"],
    )

    new_identity: dict[str, Any] = {
        **identity_for_signing,
        "signature": crypto.to_hex(identity_sig),
    }

    return new_identity


# ---------------------------------------------------------------------------
# Verify identity
# ---------------------------------------------------------------------------

def verify_identity(identity: dict) -> dict:
    """Verify all cryptographic and structural invariants of an agent identity.

    Checks performed:
     1. Capability manifest hash matches sorted capabilities.
     2. Composite identity hash matches the 'id' field.
     3. Operator signature over the identity payload is valid.
     4. Lineage chain is consistent (parent hash links, ordered timestamps).
     5. All lineage entry signatures are valid.
     6. Version number matches the lineage length.

    Args:
        identity: The agent identity dict.

    Returns:
        A dict with 'valid' (bool) and 'checks' (list of dicts with
        name, passed, message).
    """
    checks: list[dict] = []

    # 1. Capability manifest hash
    expected_cap_hash = compute_capability_manifest_hash(identity["capabilities"])
    cap_hash_ok = expected_cap_hash == identity.get("capabilityManifestHash")
    checks.append({
        "name": "capability_manifest_hash",
        "passed": cap_hash_ok,
        "message": (
            "Capability manifest hash is valid"
            if cap_hash_ok
            else f"Capability manifest hash mismatch: expected {expected_cap_hash}, "
                 f"got {identity.get('capabilityManifestHash')}"
        ),
    })

    # 2. Composite identity hash
    rest = {k: v for k, v in identity.items() if k not in ("id", "signature")}
    expected_id = compute_identity_hash(rest)
    id_ok = expected_id == identity.get("id")
    checks.append({
        "name": "composite_identity_hash",
        "passed": id_ok,
        "message": (
            "Composite identity hash is valid"
            if id_ok
            else f"Composite identity hash mismatch: expected {expected_id}, "
                 f"got {identity.get('id')}"
        ),
    })

    # 3. Operator signature
    identity_for_signing: dict[str, Any] = {
        "id": identity["id"],
        "operatorPublicKey": identity["operatorPublicKey"],
    }
    if "operatorIdentifier" in identity:
        identity_for_signing["operatorIdentifier"] = identity["operatorIdentifier"]
    identity_for_signing.update({
        "model": identity["model"],
        "capabilities": identity["capabilities"],
        "capabilityManifestHash": identity["capabilityManifestHash"],
        "deployment": identity["deployment"],
        "lineage": identity["lineage"],
        "version": identity["version"],
        "createdAt": identity["createdAt"],
        "updatedAt": identity["updatedAt"],
    })

    sig_payload = _identity_signing_payload(identity_for_signing)
    sig_message = sig_payload.encode("utf-8")

    sig_ok = False
    try:
        sig_bytes = crypto.from_hex(identity["signature"])
        pub_key_bytes = crypto.from_hex(identity["operatorPublicKey"])
        sig_ok = crypto.verify(sig_message, sig_bytes, pub_key_bytes)
    except Exception:
        sig_ok = False
    checks.append({
        "name": "operator_signature",
        "passed": sig_ok,
        "message": (
            "Operator signature is valid"
            if sig_ok
            else "Operator signature verification failed"
        ),
    })

    # 4. Lineage chain consistency
    lineage_ok = True
    lineage_message = "Lineage chain is consistent"

    lineage = identity.get("lineage", [])
    for i, entry in enumerate(lineage):
        if i == 0:
            if entry.get("parentHash") is not None:
                lineage_ok = False
                lineage_message = (
                    f"Lineage entry 0: expected null parentHash, "
                    f"got {entry.get('parentHash')}"
                )
                break
        else:
            prev = lineage[i - 1]
            if entry.get("parentHash") != prev.get("identityHash"):
                lineage_ok = False
                lineage_message = (
                    f"Lineage entry {i}: parentHash {entry.get('parentHash')} "
                    f"does not match previous identityHash {prev.get('identityHash')}"
                )
                break

        # Check timestamp ordering
        if i > 0:
            prev = lineage[i - 1]
            if entry.get("timestamp", "") < prev.get("timestamp", ""):
                lineage_ok = False
                lineage_message = (
                    f"Lineage entry {i}: timestamp {entry.get('timestamp')} "
                    f"is before previous {prev.get('timestamp')}"
                )
                break

    checks.append({
        "name": "lineage_chain",
        "passed": lineage_ok,
        "message": lineage_message,
    })

    # 5. Lineage entry signatures
    lineage_sigs_ok = True
    lineage_sigs_message = "All lineage entry signatures are valid"

    for i, entry in enumerate(lineage):
        try:
            entry_unsigned: dict[str, Any] = {
                "identityHash": entry["identityHash"],
                "changeType": entry["changeType"],
                "description": entry["description"],
                "timestamp": entry["timestamp"],
                "parentHash": entry["parentHash"],
                "reputationCarryForward": entry["reputationCarryForward"],
            }
            payload = crypto.canonicalize_json(entry_unsigned)
            msg_bytes = payload.encode("utf-8")
            entry_sig_bytes = crypto.from_hex(entry["signature"])
            pub_bytes = crypto.from_hex(identity["operatorPublicKey"])
            entry_valid = crypto.verify(msg_bytes, entry_sig_bytes, pub_bytes)
            if not entry_valid:
                lineage_sigs_ok = False
                lineage_sigs_message = (
                    f"Lineage entry {i}: signature verification failed"
                )
                break
        except Exception:
            lineage_sigs_ok = False
            lineage_sigs_message = (
                f"Lineage entry {i}: signature verification error"
            )
            break

    checks.append({
        "name": "lineage_signatures",
        "passed": lineage_sigs_ok,
        "message": lineage_sigs_message,
    })

    # 6. Version matches lineage length
    version_ok = identity.get("version") == len(lineage)
    checks.append({
        "name": "version_lineage_match",
        "passed": version_ok,
        "message": (
            "Version matches lineage length"
            if version_ok
            else f"Version {identity.get('version')} does not match "
                 f"lineage length {len(lineage)}"
        ),
    })

    valid = all(c["passed"] for c in checks)
    return {"valid": valid, "checks": checks}


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def serialize_identity(identity: dict) -> str:
    """Serialize an AgentIdentity to a canonical (deterministic) JSON string.

    Args:
        identity: The identity dict.

    Returns:
        A canonical JSON string.
    """
    return crypto.canonicalize_json(identity)


def deserialize_identity(json_str: str) -> dict:
    """Deserialize a JSON string back into an AgentIdentity dict.

    Performs structural validation to ensure all required fields are present.

    Args:
        json_str: A JSON string representing an agent identity.

    Returns:
        The parsed AgentIdentity dict.

    Raises:
        ValueError: When the JSON is malformed or missing required fields.
    """
    if not isinstance(json_str, str) or json_str.strip() == "":
        raise ValueError("deserializeIdentity() requires a non-empty JSON string")

    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError as err:
        raise ValueError(f"Invalid identity JSON: {err}") from err

    if not isinstance(parsed, dict):
        raise ValueError("Invalid identity JSON: expected an object")

    required_fields = [
        "id",
        "operatorPublicKey",
        "model",
        "capabilities",
        "capabilityManifestHash",
        "deployment",
        "lineage",
        "version",
        "createdAt",
        "updatedAt",
        "signature",
    ]

    for field_name in required_fields:
        if field_name not in parsed:
            raise ValueError(
                f'Invalid identity JSON: missing required field "{field_name}"'
            )

    if not isinstance(parsed["lineage"], list):
        raise ValueError("Invalid identity JSON: lineage must be an array")

    if not isinstance(parsed["capabilities"], list):
        raise ValueError("Invalid identity JSON: capabilities must be an array")

    if not isinstance(parsed["version"], (int, float)):
        raise ValueError("Invalid identity JSON: version must be a number")

    return parsed
