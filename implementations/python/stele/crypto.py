"""
Stele protocol cryptographic primitives.

Provides Ed25519 signing/verification, SHA-256 hashing, JCS canonicalization
(RFC 8785), and related utility functions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------------------------------------------------------------------------
# Key pair generation
# ---------------------------------------------------------------------------

def generate_key_pair() -> dict:
    """Generate a new Ed25519 key pair from cryptographically secure randomness.

    Returns:
        A dict with keys:
          - private_key: bytes (32 bytes)
          - public_key: bytes (32 bytes)
          - public_key_hex: str (64-char hex string)
    """
    private_key_obj = Ed25519PrivateKey.generate()
    private_key_bytes = private_key_obj.private_bytes_raw()
    public_key_bytes = private_key_obj.public_key().public_bytes_raw()
    return {
        "private_key": private_key_bytes,
        "public_key": public_key_bytes,
        "public_key_hex": to_hex(public_key_bytes),
    }


def key_pair_from_private_key(private_key: bytes) -> dict:
    """Reconstruct a KeyPair from an existing 32-byte Ed25519 private key.

    Args:
        private_key: A 32-byte Ed25519 private key seed.

    Returns:
        A dict with private_key, public_key, and public_key_hex.

    Raises:
        ValueError: When the private key is not exactly 32 bytes.
    """
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
        raise ValueError(
            f"Private key must be 32 bytes, got "
            f"{len(private_key) if isinstance(private_key, (bytes, bytearray)) else type(private_key).__name__}"
        )
    private_key_obj = Ed25519PrivateKey.from_private_bytes(private_key)
    public_key_bytes = private_key_obj.public_key().public_bytes_raw()
    return {
        "private_key": bytes(private_key),
        "public_key": public_key_bytes,
        "public_key_hex": to_hex(public_key_bytes),
    }


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

def sign(message: bytes, private_key: bytes) -> bytes:
    """Sign arbitrary bytes with an Ed25519 private key.

    Args:
        message: The message bytes to sign.
        private_key: A 32-byte Ed25519 private key seed.

    Returns:
        A 64-byte Ed25519 signature.

    Raises:
        TypeError: When message is not bytes or private_key is not bytes.
        ValueError: When private_key is not 32 bytes.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(
            f"sign() expects message to be bytes, got {type(message).__name__}"
        )
    if not isinstance(private_key, (bytes, bytearray)) or len(private_key) != 32:
        raise ValueError(
            "sign() expects private_key to be 32 bytes"
        )
    private_key_obj = Ed25519PrivateKey.from_private_bytes(private_key)
    return private_key_obj.sign(bytes(message))


def sign_string(message: str, private_key: bytes) -> bytes:
    """Sign a UTF-8 string with an Ed25519 private key.

    Convenience wrapper around :func:`sign`.

    Args:
        message: The UTF-8 string to sign.
        private_key: A 32-byte Ed25519 private key seed.

    Returns:
        A 64-byte Ed25519 signature.
    """
    if not isinstance(message, str):
        raise TypeError(
            f"sign_string() expects message to be str, got {type(message).__name__}"
        )
    return sign(message.encode("utf-8"), private_key)


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature against a message and public key.

    This function never raises on untrusted inputs -- any internal error
    returns False.

    Args:
        message: The original message bytes.
        signature: The 64-byte signature to verify.
        public_key: The signer's 32-byte public key.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_key_obj = Ed25519PublicKey.from_public_bytes(public_key)
        public_key_obj.verify(signature, message)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> str:
    """SHA-256 hash of arbitrary bytes, returned as a lowercase hex string.

    Args:
        data: The bytes to hash.

    Returns:
        A 64-character hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_string(data: str) -> str:
    """SHA-256 hash of a UTF-8 string, returned as a lowercase hex string.

    Args:
        data: The UTF-8 string to hash.

    Returns:
        A 64-character hex-encoded SHA-256 digest.
    """
    return sha256(data.encode("utf-8"))


def sha256_object(obj: Any) -> str:
    """SHA-256 hash of a Python object in canonical (deterministic) JSON form.

    The object is first serialized via :func:`canonicalize_json` (sorted keys,
    RFC 8785), then hashed.  Two structurally equal objects always produce
    the same hash regardless of key insertion order.

    Args:
        obj: The value to canonicalize and hash.

    Returns:
        A 64-character hex-encoded SHA-256 digest.
    """
    return sha256_string(canonicalize_json(obj))


# ---------------------------------------------------------------------------
# JSON canonicalization (JCS / RFC 8785)
# ---------------------------------------------------------------------------

def canonicalize_json(obj: Any) -> str:
    """Deterministic JSON serialization following JCS (RFC 8785).

    Recursively sorts all object keys alphabetically before serializing.
    Produces identical output regardless of key insertion order, making
    it safe for hashing and signature computation.

    Args:
        obj: The value to serialize.

    Returns:
        A canonical JSON string with no extra whitespace.
    """
    return json.dumps(_sort_keys(obj), ensure_ascii=False, separators=(",", ":"))


def _sort_keys(value: Any) -> Any:
    """Recursively sort dictionary keys for canonical output."""
    if value is None:
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_sort_keys(item) for item in value]
    if isinstance(value, dict):
        sorted_dict: dict[str, Any] = {}
        for key in sorted(value.keys()):
            v = value[key]
            if v is not None:
                sorted_dict[key] = _sort_keys(v)
        return sorted_dict
    return value


# ---------------------------------------------------------------------------
# Hex encoding / decoding
# ---------------------------------------------------------------------------

def to_hex(data: bytes) -> str:
    """Encode a byte sequence to a lowercase hex string.

    Args:
        data: The bytes to encode.

    Returns:
        A hex string with length ``len(data) * 2``.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(
            f"to_hex() expects bytes, got {type(data).__name__}"
        )
    return data.hex()


def from_hex(hex_str: str) -> bytes:
    """Decode a hex string to bytes.

    Args:
        hex_str: An even-length hexadecimal string.

    Returns:
        The decoded bytes.

    Raises:
        ValueError: When the hex string has odd length or invalid characters.
    """
    if not isinstance(hex_str, str):
        raise TypeError(
            f"from_hex() expects a string, got {type(hex_str).__name__}"
        )
    if len(hex_str) % 2 != 0:
        raise ValueError(
            f"Invalid hex string: odd length ({len(hex_str)})"
        )
    return bytes.fromhex(hex_str)


# ---------------------------------------------------------------------------
# Nonce and randomness
# ---------------------------------------------------------------------------

def generate_nonce() -> bytes:
    """Generate a cryptographically secure 32-byte nonce.

    Returns:
        A 32-byte random nonce from the platform CSPRNG.
    """
    return secrets.token_bytes(32)


# ---------------------------------------------------------------------------
# Constant-time comparison
# ---------------------------------------------------------------------------

def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte sequences.

    Prevents timing side-channel attacks when comparing signatures,
    hashes, or other secret-derived values.

    Args:
        a: First byte sequence.
        b: Second byte sequence.

    Returns:
        True if the sequences are identical in length and content.
    """
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

def timestamp() -> str:
    """Create a timestamp string in ISO 8601 format (UTC).

    Returns:
        An ISO 8601 timestamp string like ``"2025-01-15T12:00:00.000Z"``.
    """
    now = datetime.now(timezone.utc)
    # Format to match JavaScript's toISOString() output: always 3 fractional digits + Z
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
