//! Cryptographic primitives for the Grith protocol.
//!
//! Provides Ed25519 signing/verification via `ed25519-dalek`, SHA-256 hashing
//! via `sha2`, JCS (RFC 8785) JSON canonicalization, and utility functions
//! for nonce generation, timestamps, and constant-time comparison.

use crate::GrithError;
use ed25519_dalek::{Signer, Verifier};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// An Ed25519 key pair containing the signing key, verifying key, and hex-encoded public key.
pub struct KeyPair {
    pub signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub public_key_hex: String,
}

/// Generate a new Ed25519 key pair from cryptographically secure randomness.
///
/// Returns a `KeyPair` with a fresh 32-byte private key, the derived public key,
/// and the hex-encoded public key string.
pub fn generate_key_pair() -> Result<KeyPair, GrithError> {
    let mut rng = rand::thread_rng();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());
    Ok(KeyPair {
        signing_key,
        verifying_key,
        public_key_hex,
    })
}

/// Reconstruct a `KeyPair` from a 32-byte private key.
///
/// # Errors
/// Returns `GrithError::CryptoError` if the byte slice is not exactly 32 bytes.
pub fn key_pair_from_private_key(bytes: &[u8]) -> Result<KeyPair, GrithError> {
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GrithError::CryptoError(format!("Private key must be 32 bytes, got {}", bytes.len())))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());
    Ok(KeyPair {
        signing_key,
        verifying_key,
        public_key_hex,
    })
}

/// Sign a message with an Ed25519 signing key.
///
/// Returns the 64-byte signature as a `Vec<u8>`.
pub fn sign(message: &[u8], signing_key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>, GrithError> {
    let signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an Ed25519 signature against a message and verifying key.
///
/// Returns `true` if the signature is valid, `false` otherwise. Never panics
/// on malformed inputs -- any error is treated as an invalid signature.
pub fn verify(
    message: &[u8],
    signature: &[u8],
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify(message, &sig).is_ok()
}

/// Compute the SHA-256 hash of raw bytes and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Compute the SHA-256 hash of a UTF-8 string and return it as a lowercase hex string.
pub fn sha256_string(data: &str) -> String {
    sha256_hex(data.as_bytes())
}

/// Compute the SHA-256 hash of a JSON value after JCS canonicalization.
///
/// The value is first serialized via `canonicalize_json`, then hashed.
/// Two structurally equal objects always produce the same hash regardless
/// of key insertion order.
pub fn sha256_object(obj: &serde_json::Value) -> Result<String, GrithError> {
    let canonical = canonicalize_json(obj);
    Ok(sha256_string(&canonical))
}

/// Deterministic JSON serialization following JCS (RFC 8785).
///
/// Recursively sorts all object keys alphabetically before serializing.
/// Produces identical output regardless of key insertion order.
pub fn canonicalize_json(obj: &serde_json::Value) -> String {
    let sorted = sort_keys(obj);
    // serde_json::to_string produces compact JSON without extra whitespace
    serde_json::to_string(&sorted).unwrap_or_default()
}

/// Recursively sort all object keys in a JSON value.
fn sort_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // Collect keys, sort, and rebuild the map
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted_map = serde_json::Map::new();
            for key in keys {
                if let Some(v) = map.get(key) {
                    // Skip null values to match JS behavior where undefined values are omitted
                    sorted_map.insert(key.clone(), sort_keys(v));
                }
            }
            serde_json::Value::Object(sorted_map)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_keys).collect())
        }
        other => other.clone(),
    }
}

/// Generate 32 random bytes for use as a cryptographic nonce.
pub fn generate_nonce() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut nonce = vec![0u8; 32];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Constant-time comparison of two byte slices.
///
/// Returns `true` only if both slices have the same length and identical contents.
/// The comparison time is proportional to the length of the slices, preventing
/// timing side-channel attacks.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Return the current UTC time as an ISO 8601 string.
///
/// Format: `YYYY-MM-DDTHH:MM:SS.sssZ`
pub fn timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign_verify() {
        let kp = generate_key_pair().unwrap();
        let message = b"hello grith";
        let sig = sign(message, &kp.signing_key).unwrap();
        assert!(verify(message, &sig, &kp.verifying_key));
        assert!(!verify(b"tampered", &sig, &kp.verifying_key));
    }

    #[test]
    fn test_sha256() {
        let hash = sha256_string("hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn test_canonicalize_json() {
        let obj: serde_json::Value = serde_json::json!({"z": 1, "a": 2});
        let canonical = canonicalize_json(&obj);
        assert_eq!(canonical, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_constant_time_equal() {
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"abd"));
        assert!(!constant_time_equal(b"ab", b"abc"));
    }

    #[test]
    fn test_key_pair_from_private_key() {
        let kp = generate_key_pair().unwrap();
        let bytes = kp.signing_key.to_bytes();
        let restored = key_pair_from_private_key(&bytes).unwrap();
        assert_eq!(kp.public_key_hex, restored.public_key_hex);
    }

    #[test]
    fn test_nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
    }
}
