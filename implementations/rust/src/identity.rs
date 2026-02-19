//! Agent identity creation, evolution, and verification.
//!
//! An agent identity is a content-addressed, signed document describing an AI
//! agent's operator, model, capabilities, and deployment context. Identities
//! evolve through a hash-linked lineage chain, where each evolution is signed
//! and records the type of change made.

use crate::crypto;
use crate::SteleError;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Attestation about the AI model powering an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub provider: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
}

/// Describes where and how an agent is deployed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentInfo {
    pub runtime: String,
}

/// A single entry in an agent's lineage chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEntry {
    #[serde(rename = "identityHash")]
    pub identity_hash: String,
    #[serde(rename = "parentHash")]
    pub parent_hash: Option<String>,
    #[serde(rename = "changeType")]
    pub change_type: String,
    pub description: String,
    pub timestamp: String,
}

/// A complete, signed AI agent identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: String,
    #[serde(rename = "operatorPublicKey")]
    pub operator_public_key: String,
    pub model: ModelInfo,
    pub capabilities: Vec<String>,
    pub deployment: DeploymentInfo,
    pub version: u32,
    pub lineage: Vec<LineageEntry>,
    pub signature: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Options for creating a new agent identity.
pub struct CreateIdentityOptions {
    pub signing_key: ed25519_dalek::SigningKey,
    pub public_key_hex: String,
    pub model: ModelInfo,
    pub capabilities: Vec<String>,
    pub deployment: DeploymentInfo,
}

/// Options for evolving an existing identity.
pub struct EvolveIdentityOptions {
    pub signing_key: ed25519_dalek::SigningKey,
    pub change_type: String,
    pub description: String,
    pub model: Option<ModelInfo>,
    pub capabilities: Option<Vec<String>>,
    pub deployment: Option<DeploymentInfo>,
}

/// Result of verifying an agent identity.
#[derive(Debug)]
pub struct IdentityVerificationResult {
    pub valid: bool,
    pub checks: Vec<IdentityCheck>,
}

/// A single verification check for identity verification.
#[derive(Debug)]
pub struct IdentityCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Hash computation
// ---------------------------------------------------------------------------

/// Compute the composite identity hash from all identity-defining fields.
///
/// The hash covers operator key, model, capabilities, deployment,
/// and the full lineage chain. This produces the `id` field.
pub fn compute_identity_hash(body: &serde_json::Value) -> String {
    crypto::sha256_string(&crypto::canonicalize_json(body))
}

/// Build the JSON body used for hashing/signing (excludes `id` and `signature`).
fn identity_body(identity: &AgentIdentity) -> Result<serde_json::Value, SteleError> {
    let val = serde_json::to_value(identity)
        .map_err(|e| SteleError::SerializationError(format!("Failed to serialize identity: {}", e)))?;

    let mut obj = match val {
        serde_json::Value::Object(m) => m,
        _ => return Err(SteleError::SerializationError("Expected object".to_string())),
    };

    obj.remove("id");
    obj.remove("signature");

    Ok(serde_json::Value::Object(obj))
}

// ---------------------------------------------------------------------------
// Create identity
// ---------------------------------------------------------------------------

/// Create a brand-new agent identity.
///
/// Computes the composite identity hash, initializes a single lineage entry
/// of type `created`, and signs the whole identity with the operator key.
///
/// # Errors
/// Returns `SteleError::InvalidInput` for missing fields or
/// `SteleError::CryptoError` for signing failures.
pub fn create_identity(opts: CreateIdentityOptions) -> Result<AgentIdentity, SteleError> {
    if opts.public_key_hex.is_empty() {
        return Err(SteleError::InvalidInput(
            "operatorPublicKey is required".to_string(),
        ));
    }
    if opts.model.provider.is_empty() || opts.model.model_id.is_empty() {
        return Err(SteleError::InvalidInput(
            "model.provider and model.modelId are required".to_string(),
        ));
    }
    if opts.capabilities.is_empty() {
        return Err(SteleError::InvalidInput(
            "capabilities array must not be empty".to_string(),
        ));
    }
    if opts.deployment.runtime.is_empty() {
        return Err(SteleError::InvalidInput(
            "deployment.runtime is required".to_string(),
        ));
    }

    let now = crypto::timestamp();
    let mut capabilities = opts.capabilities.clone();
    capabilities.sort();

    // Build partial identity without id/signature to compute hash
    let mut identity = AgentIdentity {
        id: String::new(),
        operator_public_key: opts.public_key_hex.clone(),
        model: opts.model,
        capabilities,
        deployment: opts.deployment,
        version: 1,
        lineage: Vec::new(),
        signature: String::new(),
        created_at: now.clone(),
    };

    // Compute identity hash for the first lineage entry
    let body = identity_body(&identity)?;
    let identity_hash = compute_identity_hash(&body);

    // Create the initial lineage entry
    let lineage_entry = LineageEntry {
        identity_hash: identity_hash.clone(),
        parent_hash: None,
        change_type: "created".to_string(),
        description: "Identity created".to_string(),
        timestamp: now,
    };

    identity.lineage = vec![lineage_entry];

    // Recompute hash with lineage included
    let body_with_lineage = identity_body(&identity)?;
    let final_hash = compute_identity_hash(&body_with_lineage);
    identity.id = final_hash;

    // Sign the identity
    let signing_payload = crypto::canonicalize_json(&identity_body(&identity)?);
    let sig_bytes = crypto::sign(signing_payload.as_bytes(), &opts.signing_key)?;
    identity.signature = hex::encode(&sig_bytes);

    Ok(identity)
}

// ---------------------------------------------------------------------------
// Evolve identity
// ---------------------------------------------------------------------------

/// Evolve an existing agent identity by applying updates.
///
/// Creates a new version of the identity with the specified changes,
/// appends a lineage entry describing the change, and re-signs everything.
///
/// # Errors
/// Returns `SteleError::InvalidInput` for invalid change types or
/// `SteleError::CryptoError` for signing failures.
pub fn evolve_identity(
    identity: &AgentIdentity,
    opts: EvolveIdentityOptions,
) -> Result<AgentIdentity, SteleError> {
    if opts.change_type.is_empty() {
        return Err(SteleError::InvalidInput(
            "changeType is required for evolution".to_string(),
        ));
    }
    if opts.description.is_empty() {
        return Err(SteleError::InvalidInput(
            "description is required for evolution".to_string(),
        ));
    }

    let now = crypto::timestamp();

    // Apply updates
    let model = opts.model.unwrap_or_else(|| identity.model.clone());
    let mut capabilities = opts
        .capabilities
        .unwrap_or_else(|| identity.capabilities.clone());
    capabilities.sort();
    let deployment = opts
        .deployment
        .unwrap_or_else(|| identity.deployment.clone());

    // Build the evolved identity
    let mut evolved = AgentIdentity {
        id: String::new(),
        operator_public_key: identity.operator_public_key.clone(),
        model,
        capabilities,
        deployment,
        version: identity.version + 1,
        lineage: identity.lineage.clone(),
        signature: String::new(),
        created_at: identity.created_at.clone(),
    };

    // Compute the new identity hash
    let body = identity_body(&evolved)?;
    let new_hash = compute_identity_hash(&body);

    // Get the parent hash (last lineage entry's identity_hash)
    let parent_hash = identity.lineage.last().map(|e| e.identity_hash.clone());

    // Append new lineage entry
    let lineage_entry = LineageEntry {
        identity_hash: new_hash,
        parent_hash,
        change_type: opts.change_type,
        description: opts.description,
        timestamp: now,
    };

    evolved.lineage.push(lineage_entry);

    // Recompute hash with new lineage
    let body_with_lineage = identity_body(&evolved)?;
    let final_hash = compute_identity_hash(&body_with_lineage);
    evolved.id = final_hash;

    // Sign
    let signing_payload = crypto::canonicalize_json(&identity_body(&evolved)?);
    let sig_bytes = crypto::sign(signing_payload.as_bytes(), &opts.signing_key)?;
    evolved.signature = hex::encode(&sig_bytes);

    Ok(evolved)
}

// ---------------------------------------------------------------------------
// Verify identity
// ---------------------------------------------------------------------------

/// Verify an agent identity's integrity and signature.
///
/// Checks:
/// 1. `id_match` -- ID matches the hash of the identity body
/// 2. `signature_valid` -- Operator signature is valid
/// 3. `lineage_chain` -- Lineage entries form a valid hash chain
/// 4. `version_match` -- Version matches lineage length
pub fn verify_identity(
    identity: &AgentIdentity,
) -> Result<IdentityVerificationResult, SteleError> {
    let mut checks: Vec<IdentityCheck> = Vec::new();

    // 1. ID match
    let body = identity_body(identity)?;
    let expected_id = compute_identity_hash(&body);
    checks.push(IdentityCheck {
        name: "id_match".to_string(),
        passed: identity.id == expected_id,
        message: if identity.id == expected_id {
            "Identity ID matches hash".to_string()
        } else {
            format!(
                "ID mismatch: expected {}, got {}",
                expected_id, identity.id
            )
        },
    });

    // 2. Signature valid
    let signing_payload = crypto::canonicalize_json(&body);
    let sig_bytes = hex::decode(&identity.signature).unwrap_or_default();
    let pub_key_bytes = hex::decode(&identity.operator_public_key).unwrap_or_default();
    let pub_array: [u8; 32] = pub_key_bytes
        .as_slice()
        .try_into()
        .unwrap_or([0u8; 32]);
    let sig_valid = if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pub_array) {
        crypto::verify(signing_payload.as_bytes(), &sig_bytes, &vk)
    } else {
        false
    };
    checks.push(IdentityCheck {
        name: "signature_valid".to_string(),
        passed: sig_valid,
        message: if sig_valid {
            "Operator signature is valid".to_string()
        } else {
            "Operator signature verification failed".to_string()
        },
    });

    // 3. Lineage chain
    let mut lineage_valid = true;
    let mut lineage_msg = "Lineage chain is valid".to_string();
    for i in 1..identity.lineage.len() {
        let expected_parent = &identity.lineage[i - 1].identity_hash;
        match &identity.lineage[i].parent_hash {
            Some(parent) if parent == expected_parent => {}
            Some(parent) => {
                lineage_valid = false;
                lineage_msg = format!(
                    "Lineage break at entry {}: expected parent {}, got {}",
                    i, expected_parent, parent
                );
                break;
            }
            None => {
                lineage_valid = false;
                lineage_msg = format!("Lineage entry {} has no parent hash", i);
                break;
            }
        }
    }
    checks.push(IdentityCheck {
        name: "lineage_chain".to_string(),
        passed: lineage_valid,
        message: lineage_msg,
    });

    // 4. Version match
    let version_match = identity.version as usize == identity.lineage.len();
    checks.push(IdentityCheck {
        name: "version_match".to_string(),
        passed: version_match,
        message: if version_match {
            format!("Version {} matches lineage length", identity.version)
        } else {
            format!(
                "Version {} does not match lineage length {}",
                identity.version,
                identity.lineage.len()
            )
        },
    });

    let valid = checks.iter().all(|c| c.passed);

    Ok(IdentityVerificationResult { valid, checks })
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize an AgentIdentity to a JSON string.
pub fn serialize_identity(identity: &AgentIdentity) -> Result<String, SteleError> {
    serde_json::to_string_pretty(identity)
        .map_err(|e| SteleError::SerializationError(format!("Failed to serialize identity: {}", e)))
}

/// Deserialize a JSON string into an AgentIdentity.
pub fn deserialize_identity(json: &str) -> Result<AgentIdentity, SteleError> {
    serde_json::from_str(json)
        .map_err(|e| SteleError::SerializationError(format!("Failed to deserialize identity: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_identity() {
        let kp = crypto::generate_key_pair().unwrap();
        let identity = create_identity(CreateIdentityOptions {
            signing_key: kp.signing_key,
            public_key_hex: kp.public_key_hex,
            model: ModelInfo {
                provider: "anthropic".to_string(),
                model_id: "claude-3".to_string(),
            },
            capabilities: vec!["read".to_string(), "write".to_string()],
            deployment: DeploymentInfo {
                runtime: "container".to_string(),
            },
        })
        .unwrap();

        assert!(!identity.id.is_empty());
        assert_eq!(identity.version, 1);
        assert_eq!(identity.lineage.len(), 1);
        assert_eq!(identity.lineage[0].change_type, "created");
    }

    #[test]
    fn test_evolve_identity() {
        let kp = crypto::generate_key_pair().unwrap();
        let identity = create_identity(CreateIdentityOptions {
            signing_key: kp.signing_key.clone(),
            public_key_hex: kp.public_key_hex.clone(),
            model: ModelInfo {
                provider: "anthropic".to_string(),
                model_id: "claude-3".to_string(),
            },
            capabilities: vec!["read".to_string()],
            deployment: DeploymentInfo {
                runtime: "container".to_string(),
            },
        })
        .unwrap();

        let evolved = evolve_identity(
            &identity,
            EvolveIdentityOptions {
                signing_key: kp.signing_key,
                change_type: "capability_change".to_string(),
                description: "Added write capability".to_string(),
                model: None,
                capabilities: Some(vec!["read".to_string(), "write".to_string()]),
                deployment: None,
            },
        )
        .unwrap();

        assert_eq!(evolved.version, 2);
        assert_eq!(evolved.lineage.len(), 2);
        assert_ne!(identity.id, evolved.id);
    }

    #[test]
    fn test_serialize_deserialize_identity() {
        let kp = crypto::generate_key_pair().unwrap();
        let identity = create_identity(CreateIdentityOptions {
            signing_key: kp.signing_key,
            public_key_hex: kp.public_key_hex,
            model: ModelInfo {
                provider: "anthropic".to_string(),
                model_id: "claude-3".to_string(),
            },
            capabilities: vec!["read".to_string()],
            deployment: DeploymentInfo {
                runtime: "container".to_string(),
            },
        })
        .unwrap();

        let json = serialize_identity(&identity).unwrap();
        let restored = deserialize_identity(&json).unwrap();
        assert_eq!(identity.id, restored.id);
        assert_eq!(identity.signature, restored.signature);
    }
}
