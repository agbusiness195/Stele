//! Stele: The accountability primitive for AI agents - Rust implementation.
//!
//! This crate provides the core protocol primitives for building, signing,
//! verifying, and chaining Covenant documents. It includes:
//!
//! - **crypto**: Ed25519 signing/verification, SHA-256 hashing, JCS canonicalization
//! - **ccl**: Covenant Constraint Language parser and evaluator
//! - **covenant**: Covenant document building, verification, and chaining
//! - **identity**: Agent identity creation, evolution, and verification
//! - **store**: In-memory covenant storage

pub mod ccl;
pub mod covenant;
pub mod crypto;
pub mod identity;
pub mod store;

/// Errors that can occur throughout the Stele protocol.
#[derive(Debug, thiserror::Error)]
pub enum SteleError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("CCL parse error: {0}")]
    CCLParseError(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}
