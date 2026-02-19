"""
Kova Covenant document builder, verifier, and serializer.

Implements the full covenant lifecycle: build, sign, verify, countersign,
chain, serialize, and deserialize.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any, Optional

from . import ccl as ccl_module
from . import crypto

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = "1.0"
MAX_CONSTRAINTS = 256
MAX_CHAIN_DEPTH = 16
MAX_DOCUMENT_SIZE = 1_048_576  # 1 MiB

VALID_ENFORCEMENT_TYPES = frozenset(
    ["capability", "monitor", "audit", "bond", "composite"]
)
VALID_PROOF_TYPES = frozenset(
    ["tee", "capability_manifest", "audit_log", "bond_reference", "zkp", "composite"]
)


# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------

class CovenantBuildError(Exception):
    """Raised when building a covenant document fails validation."""

    def __init__(self, message: str, field: str = ""):
        self.field = field
        super().__init__(message)


class CovenantVerificationError(Exception):
    """Raised when covenant verification encounters critical failures."""

    def __init__(self, message: str, checks: Optional[list[dict]] = None):
        self.checks = checks or []
        super().__init__(message)


# ---------------------------------------------------------------------------
# Canonical form & ID computation
# ---------------------------------------------------------------------------

def canonical_form(doc: dict) -> str:
    """Compute the canonical form of a covenant document.

    Strips the 'id', 'signature', and 'countersignatures' fields, then
    produces deterministic JSON via JCS (RFC 8785) canonicalization.

    Args:
        doc: The covenant document dict.

    Returns:
        A deterministic JSON string suitable for signing or hashing.
    """
    body = {k: v for k, v in doc.items() if k not in ("id", "signature", "countersignatures")}
    return crypto.canonicalize_json(body)


def compute_id(doc: dict) -> str:
    """Compute the SHA-256 document ID from its canonical form.

    Args:
        doc: The covenant document dict.

    Returns:
        A 64-character hex SHA-256 hash serving as the document ID.
    """
    return crypto.sha256_string(canonical_form(doc))


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_covenant(options: dict) -> dict:
    """Build a new, signed CovenantDocument from the provided options.

    Validates all required inputs, parses CCL constraints to verify syntax,
    generates a cryptographic nonce, signs the canonical form with the
    issuer's private key, and computes the document ID.

    Args:
        options: Builder options dict with keys:
          - issuer: dict with id, publicKey, role="issuer"
          - beneficiary: dict with id, publicKey, role="beneficiary"
          - constraints: str (CCL text)
          - privateKey: bytes (32-byte Ed25519 private key)
          - Optional: obligations, chain, enforcement, proof, revocation,
            metadata, expiresAt, activatesAt

    Returns:
        A complete, signed covenant document dict.

    Raises:
        CovenantBuildError: When any required input is missing or invalid.
    """
    # Validate issuer
    issuer = options.get("issuer")
    if not issuer:
        raise CovenantBuildError("issuer is required", "issuer")
    if not issuer.get("id"):
        raise CovenantBuildError("issuer.id is required", "issuer.id")
    if not issuer.get("publicKey"):
        raise CovenantBuildError(
            "buildCovenant: issuer.publicKey is required (hex-encoded Ed25519 public key)",
            "issuer.publicKey",
        )
    if issuer.get("role") != "issuer":
        raise CovenantBuildError('issuer.role must be "issuer"', "issuer.role")

    # Validate beneficiary
    beneficiary = options.get("beneficiary")
    if not beneficiary:
        raise CovenantBuildError("beneficiary is required", "beneficiary")
    if not beneficiary.get("id"):
        raise CovenantBuildError("beneficiary.id is required", "beneficiary.id")
    if not beneficiary.get("publicKey"):
        raise CovenantBuildError(
            "beneficiary.publicKey is required", "beneficiary.publicKey"
        )
    if beneficiary.get("role") != "beneficiary":
        raise CovenantBuildError(
            'beneficiary.role must be "beneficiary"', "beneficiary.role"
        )

    # Validate constraints
    constraints = options.get("constraints")
    if not constraints or (isinstance(constraints, str) and constraints.strip() == ""):
        raise CovenantBuildError(
            "buildCovenant: constraints is required. "
            "Provide a CCL string, e.g.: permit read on '/data/**'",
            "constraints",
        )

    # Validate private key
    private_key = options.get("privateKey")
    if not private_key or len(private_key) == 0:
        raise CovenantBuildError("buildCovenant: privateKey is required", "privateKey")
    if len(private_key) not in (32, 64):
        raise CovenantBuildError(
            f"buildCovenant: privateKey must be 32 or 64 bytes (Ed25519), "
            f"got {len(private_key)} bytes",
            "privateKey",
        )

    # Parse CCL to verify syntax
    try:
        parsed_ccl = ccl_module.parse(constraints)
    except Exception as err:
        raise CovenantBuildError(
            f"Invalid CCL constraints: {err}", "constraints"
        ) from err

    if len(parsed_ccl.statements) > MAX_CONSTRAINTS:
        raise CovenantBuildError(
            f"Constraints exceed maximum of {MAX_CONSTRAINTS} statements "
            f"(got {len(parsed_ccl.statements)})",
            "constraints",
        )

    # Validate chain reference if present
    chain = options.get("chain")
    if chain:
        if not chain.get("parentId"):
            raise CovenantBuildError(
                "chain.parentId is required", "chain.parentId"
            )
        if not chain.get("relation"):
            raise CovenantBuildError(
                "chain.relation is required", "chain.relation"
            )
        depth = chain.get("depth")
        if not isinstance(depth, int) or depth < 1:
            raise CovenantBuildError(
                "chain.depth must be a positive integer", "chain.depth"
            )
        if depth > MAX_CHAIN_DEPTH:
            raise CovenantBuildError(
                f"chain.depth exceeds maximum of {MAX_CHAIN_DEPTH} (got {depth})",
                "chain.depth",
            )

    # Validate enforcement config if present
    enforcement = options.get("enforcement")
    if enforcement:
        if enforcement.get("type") not in VALID_ENFORCEMENT_TYPES:
            raise CovenantBuildError(
                f"Invalid enforcement type: {enforcement.get('type')}",
                "enforcement.type",
            )

    # Validate proof config if present
    proof = options.get("proof")
    if proof:
        if proof.get("type") not in VALID_PROOF_TYPES:
            raise CovenantBuildError(
                f"Invalid proof type: {proof.get('type')}", "proof.type"
            )

    # Generate nonce and timestamp
    nonce = crypto.to_hex(crypto.generate_nonce())
    created_at = crypto.timestamp()

    # Construct the document
    doc: dict[str, Any] = {
        "id": "",
        "version": PROTOCOL_VERSION,
        "issuer": issuer,
        "beneficiary": beneficiary,
        "constraints": constraints,
        "nonce": nonce,
        "createdAt": created_at,
        "signature": "",
    }

    # Add optional fields
    if options.get("obligations"):
        doc["obligations"] = options["obligations"]
    if chain:
        doc["chain"] = chain
    if enforcement:
        doc["enforcement"] = enforcement
    if proof:
        doc["proof"] = proof
    if options.get("revocation"):
        doc["revocation"] = options["revocation"]
    if options.get("metadata"):
        doc["metadata"] = options["metadata"]
    if options.get("expiresAt"):
        doc["expiresAt"] = options["expiresAt"]
    if options.get("activatesAt"):
        doc["activatesAt"] = options["activatesAt"]

    # Compute canonical form, sign, and derive ID
    canonical = canonical_form(doc)
    signature_bytes = crypto.sign_string(canonical, private_key)
    doc["signature"] = crypto.to_hex(signature_bytes)
    doc["id"] = crypto.sha256_string(canonical)

    # Validate serialized size
    serialized = json.dumps(doc)
    if len(serialized.encode("utf-8")) > MAX_DOCUMENT_SIZE:
        raise CovenantBuildError(
            f"Serialized document exceeds maximum size of {MAX_DOCUMENT_SIZE} bytes",
            "document",
        )

    return doc


# ---------------------------------------------------------------------------
# Countersign
# ---------------------------------------------------------------------------

def countersign_covenant(
    doc: dict, signer_key_pair: dict, signer_role: str
) -> dict:
    """Add a countersignature to a covenant document.

    The countersigner signs the canonical form (which excludes existing
    countersignatures), so each countersignature is independent.

    Returns a new document; the original is not mutated.

    Args:
        doc: The covenant document dict.
        signer_key_pair: The countersigner's key pair dict with
            privateKey (bytes) and publicKeyHex (str).
        signer_role: The role of the countersigner.

    Returns:
        A new covenant document dict with the countersignature appended.
    """
    canonical = canonical_form(doc)
    signature_bytes = crypto.sign_string(canonical, signer_key_pair["private_key"])

    countersig = {
        "signerPublicKey": signer_key_pair["public_key_hex"],
        "signerRole": signer_role,
        "signature": crypto.to_hex(signature_bytes),
        "timestamp": crypto.timestamp(),
    }

    new_doc = copy.deepcopy(doc)
    existing = new_doc.get("countersignatures", [])
    new_doc["countersignatures"] = existing + [countersig]

    return new_doc


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_covenant(doc: dict) -> dict:
    """Verify a covenant document by running all 11 specification checks.

    Checks:
     1. id_match         - Document ID matches SHA-256 of canonical form
     2. signature_valid  - Issuer's Ed25519 signature is valid
     3. not_expired      - Current time is before expiresAt (if set)
     4. active           - Current time is after activatesAt (if set)
     5. ccl_parses       - Constraints parse as valid CCL
     6. enforcement_valid - Enforcement config type is recognized (if set)
     7. proof_valid       - Proof config type is recognized (if set)
     8. chain_depth      - Chain depth within MAX_CHAIN_DEPTH
     9. document_size    - Serialized size within MAX_DOCUMENT_SIZE
    10. countersignatures - All countersignatures valid
    11. nonce_present    - Nonce is 64-char hex

    Args:
        doc: The covenant document dict.

    Returns:
        A dict with 'valid' (bool) and 'checks' (list of dicts with
        name, passed, message).
    """
    checks: list[dict] = []

    # 1. ID match
    expected_id = compute_id(doc)
    id_match = doc.get("id") == expected_id
    checks.append({
        "name": "id_match",
        "passed": id_match,
        "message": (
            "Document ID matches canonical hash"
            if id_match
            else f"ID mismatch: expected {expected_id}, got {doc.get('id')}"
        ),
    })

    # 2. Signature valid
    sig_valid = False
    try:
        canonical = canonical_form(doc)
        message_bytes = canonical.encode("utf-8")
        sig_bytes = crypto.from_hex(doc["signature"])
        pub_key_bytes = crypto.from_hex(doc["issuer"]["publicKey"])
        sig_valid = crypto.verify(message_bytes, sig_bytes, pub_key_bytes)
    except Exception:
        sig_valid = False
    checks.append({
        "name": "signature_valid",
        "passed": sig_valid,
        "message": (
            "Issuer signature is valid"
            if sig_valid
            else "Issuer signature verification failed"
        ),
    })

    # 3. Not expired
    now = datetime.now(timezone.utc)
    expires_at = doc.get("expiresAt")
    if expires_at:
        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            not_expired = now < expires
        except Exception:
            not_expired = False
        checks.append({
            "name": "not_expired",
            "passed": not_expired,
            "message": (
                "Document has not expired"
                if not_expired
                else f"Document expired at {expires_at}"
            ),
        })
    else:
        checks.append({
            "name": "not_expired",
            "passed": True,
            "message": "No expiry set",
        })

    # 4. Active
    activates_at = doc.get("activatesAt")
    if activates_at:
        try:
            activates = datetime.fromisoformat(activates_at.replace("Z", "+00:00"))
            is_active = now >= activates
        except Exception:
            is_active = False
        checks.append({
            "name": "active",
            "passed": is_active,
            "message": (
                "Document is active"
                if is_active
                else f"Document activates at {activates_at}"
            ),
        })
    else:
        checks.append({
            "name": "active",
            "passed": True,
            "message": "No activation time set",
        })

    # 5. CCL parses
    ccl_parses = False
    ccl_msg = ""
    try:
        parsed = ccl_module.parse(doc.get("constraints", ""))
        if len(parsed.statements) > MAX_CONSTRAINTS:
            ccl_msg = f"Constraints exceed maximum of {MAX_CONSTRAINTS} statements"
        else:
            ccl_parses = True
            ccl_msg = f"CCL parsed successfully ({len(parsed.statements)} statement(s))"
    except Exception as err:
        ccl_msg = f"CCL parse error: {err}"
    checks.append({
        "name": "ccl_parses",
        "passed": ccl_parses,
        "message": ccl_msg,
    })

    # 6. Enforcement valid
    enforcement = doc.get("enforcement")
    if enforcement:
        enf_valid = enforcement.get("type") in VALID_ENFORCEMENT_TYPES
        checks.append({
            "name": "enforcement_valid",
            "passed": enf_valid,
            "message": (
                f"Enforcement type '{enforcement.get('type')}' is valid"
                if enf_valid
                else f"Unknown enforcement type '{enforcement.get('type')}'"
            ),
        })
    else:
        checks.append({
            "name": "enforcement_valid",
            "passed": True,
            "message": "No enforcement config present",
        })

    # 7. Proof valid
    proof = doc.get("proof")
    if proof:
        proof_valid = proof.get("type") in VALID_PROOF_TYPES
        checks.append({
            "name": "proof_valid",
            "passed": proof_valid,
            "message": (
                f"Proof type '{proof.get('type')}' is valid"
                if proof_valid
                else f"Unknown proof type '{proof.get('type')}'"
            ),
        })
    else:
        checks.append({
            "name": "proof_valid",
            "passed": True,
            "message": "No proof config present",
        })

    # 8. Chain depth
    chain = doc.get("chain")
    if chain:
        depth = chain.get("depth", 0)
        depth_ok = isinstance(depth, int) and 1 <= depth <= MAX_CHAIN_DEPTH
        checks.append({
            "name": "chain_depth",
            "passed": depth_ok,
            "message": (
                f"Chain depth {depth} is within limit"
                if depth_ok
                else f"Chain depth {depth} exceeds maximum of {MAX_CHAIN_DEPTH}"
            ),
        })
    else:
        checks.append({
            "name": "chain_depth",
            "passed": True,
            "message": "No chain reference present",
        })

    # 9. Document size
    serialized_bytes = len(json.dumps(doc).encode("utf-8"))
    size_ok = serialized_bytes <= MAX_DOCUMENT_SIZE
    checks.append({
        "name": "document_size",
        "passed": size_ok,
        "message": (
            f"Document size {serialized_bytes} bytes is within limit"
            if size_ok
            else f"Document size {serialized_bytes} bytes exceeds maximum of {MAX_DOCUMENT_SIZE}"
        ),
    })

    # 10. Countersignatures
    countersignatures = doc.get("countersignatures", [])
    if countersignatures:
        all_cs_valid = True
        failed_signers: list[str] = []

        for cs in countersignatures:
            try:
                canonical = canonical_form(doc)
                message_bytes = canonical.encode("utf-8")
                cs_sig_bytes = crypto.from_hex(cs["signature"])
                cs_pub_key_bytes = crypto.from_hex(cs["signerPublicKey"])
                cs_valid = crypto.verify(
                    message_bytes, cs_sig_bytes, cs_pub_key_bytes
                )
                if not cs_valid:
                    all_cs_valid = False
                    failed_signers.append(cs["signerPublicKey"][:16] + "...")
            except Exception:
                all_cs_valid = False
                failed_signers.append(cs.get("signerPublicKey", "unknown")[:16] + "...")

        checks.append({
            "name": "countersignatures",
            "passed": all_cs_valid,
            "message": (
                f"All {len(countersignatures)} countersignature(s) are valid"
                if all_cs_valid
                else f"Invalid countersignature(s) from: {', '.join(failed_signers)}"
            ),
        })
    else:
        checks.append({
            "name": "countersignatures",
            "passed": True,
            "message": "No countersignatures present",
        })

    # 11. Nonce present
    nonce = doc.get("nonce", "")
    import re as _re
    nonce_ok = isinstance(nonce, str) and bool(_re.fullmatch(r"[0-9a-fA-F]{64}", nonce))
    checks.append({
        "name": "nonce_present",
        "passed": nonce_ok,
        "message": (
            "Nonce is present and valid (64-char hex)"
            if nonce_ok
            else (
                "Nonce is missing or empty"
                if not isinstance(nonce, str) or len(nonce) == 0
                else f"Nonce is malformed: expected 64-char hex string, got {len(nonce)} chars"
            )
        ),
    })

    # Aggregate
    valid = all(c["passed"] for c in checks)

    return {
        "valid": valid,
        "checks": checks,
        "document": doc,
    }


# ---------------------------------------------------------------------------
# Chain narrowing validation
# ---------------------------------------------------------------------------

def validate_chain_narrowing(child: dict, parent: dict) -> dict:
    """Validate that a child covenant only narrows (never broadens) the parent.

    Args:
        child: The child covenant document dict.
        parent: The parent covenant document dict.

    Returns:
        A dict with 'valid' (bool) and 'violations' (list of dicts).
    """
    parent_ccl = ccl_module.parse(parent["constraints"])
    child_ccl = ccl_module.parse(child["constraints"])
    result = ccl_module.validate_narrowing(parent_ccl, child_ccl)

    violations = []
    for v in result.violations:
        violations.append({
            "childRule": {
                "type": v.child_rule.type,
                "action": v.child_rule.action,
                "resource": v.child_rule.resource,
            },
            "parentRule": {
                "type": v.parent_rule.type,
                "action": v.parent_rule.action,
                "resource": v.parent_rule.resource,
            },
            "reason": v.reason,
        })

    return {
        "valid": result.valid,
        "violations": violations,
    }


# ---------------------------------------------------------------------------
# Serialization / Deserialization
# ---------------------------------------------------------------------------

def serialize_covenant(doc: dict) -> str:
    """Serialize a covenant document to a JSON string.

    Args:
        doc: The covenant document dict.

    Returns:
        A JSON string representation.
    """
    return json.dumps(doc)


def deserialize_covenant(json_str: str) -> dict:
    """Deserialize a JSON string into a covenant document dict.

    Performs structural validation to ensure the result contains all
    required fields.

    Args:
        json_str: A JSON string to parse.

    Returns:
        The parsed covenant document dict.

    Raises:
        ValueError: When the JSON is malformed, missing required fields,
            or exceeds the maximum document size.
    """
    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError as err:
        raise ValueError(f"Invalid JSON: {err}") from err

    if not isinstance(parsed, dict):
        raise ValueError("Covenant document must be a JSON object")

    # Validate required string fields
    required_strings = ["id", "version", "constraints", "nonce", "createdAt", "signature"]
    for field_name in required_strings:
        if not isinstance(parsed.get(field_name), str):
            raise ValueError(f"Missing or invalid required field: {field_name}")

    # Validate issuer
    issuer = parsed.get("issuer")
    if not isinstance(issuer, dict):
        raise ValueError("Missing or invalid required field: issuer")
    if (
        not isinstance(issuer.get("id"), str)
        or not isinstance(issuer.get("publicKey"), str)
        or issuer.get("role") != "issuer"
    ):
        raise ValueError(
            'Invalid issuer: must have id, publicKey, and role="issuer"'
        )

    # Validate beneficiary
    beneficiary = parsed.get("beneficiary")
    if not isinstance(beneficiary, dict):
        raise ValueError("Missing or invalid required field: beneficiary")
    if (
        not isinstance(beneficiary.get("id"), str)
        or not isinstance(beneficiary.get("publicKey"), str)
        or beneficiary.get("role") != "beneficiary"
    ):
        raise ValueError(
            'Invalid beneficiary: must have id, publicKey, and role="beneficiary"'
        )

    # Validate version
    if parsed.get("version") != PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported protocol version: {parsed.get('version')} "
            f"(expected {PROTOCOL_VERSION})"
        )

    # Validate chain if present
    if "chain" in parsed:
        chain = parsed["chain"]
        if not isinstance(chain, dict):
            raise ValueError("Invalid chain: must be an object")
        if not isinstance(chain.get("parentId"), str):
            raise ValueError("Invalid chain.parentId: must be a string")
        if not isinstance(chain.get("relation"), str):
            raise ValueError("Invalid chain.relation: must be a string")
        if not isinstance(chain.get("depth"), (int, float)):
            raise ValueError("Invalid chain.depth: must be a number")

    # Validate document size
    byte_size = len(json_str.encode("utf-8"))
    if byte_size > MAX_DOCUMENT_SIZE:
        raise ValueError(
            f"Document size {byte_size} bytes exceeds maximum of {MAX_DOCUMENT_SIZE} bytes"
        )

    return parsed
