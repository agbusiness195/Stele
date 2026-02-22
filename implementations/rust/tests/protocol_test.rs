//! Integration tests for the Nobulex protocol Rust implementation.
//!
//! These tests exercise all core operations: key generation, signing,
//! CCL parsing/evaluation, covenant building/verification/chaining,
//! identity creation/evolution, and the MemoryStore.

use std::collections::HashMap;

use nobulex::ccl;
use nobulex::covenant::{
    self, ChainReference, CovenantBuilderOptions, CovenantDocument, Party,
    PROTOCOL_VERSION, MAX_CHAIN_DEPTH,
};
use nobulex::crypto;
use nobulex::identity::{
    self, CreateIdentityOptions, DeploymentInfo, EvolveIdentityOptions, ModelInfo,
};
use nobulex::store::{MemoryStore, Store};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_issuer(kp: &crypto::KeyPair) -> Party {
    Party {
        id: "issuer-1".to_string(),
        public_key: kp.public_key_hex.clone(),
        role: "issuer".to_string(),
    }
}

fn make_beneficiary(kp: &crypto::KeyPair) -> Party {
    Party {
        id: "beneficiary-1".to_string(),
        public_key: kp.public_key_hex.clone(),
        role: "beneficiary".to_string(),
    }
}

fn build_test_covenant(constraints: &str) -> (CovenantDocument, crypto::KeyPair) {
    let issuer_kp = crypto::generate_key_pair().unwrap();
    let beneficiary_kp = crypto::generate_key_pair().unwrap();
    let doc = covenant::build_covenant(CovenantBuilderOptions {
        issuer: make_issuer(&issuer_kp),
        beneficiary: make_beneficiary(&beneficiary_kp),
        constraints: constraints.to_string(),
        signing_key: issuer_kp.signing_key.clone(),
        chain: None,
        expires_at: None,
        activates_at: None,
        metadata: None,
    })
    .unwrap();
    (doc, issuer_kp)
}

// ===========================================================================
// Crypto tests
// ===========================================================================

#[test]
fn test_key_pair_generation() {
    let kp = crypto::generate_key_pair().unwrap();
    assert_eq!(kp.public_key_hex.len(), 64); // 32 bytes = 64 hex chars
    assert_eq!(kp.signing_key.to_bytes().len(), 32);
}

#[test]
fn test_key_pair_from_private_key_roundtrip() {
    let kp = crypto::generate_key_pair().unwrap();
    let bytes = kp.signing_key.to_bytes();
    let restored = crypto::key_pair_from_private_key(&bytes).unwrap();
    assert_eq!(kp.public_key_hex, restored.public_key_hex);
}

#[test]
fn test_key_pair_from_invalid_bytes() {
    let result = crypto::key_pair_from_private_key(&[0u8; 16]);
    assert!(result.is_err());
}

#[test]
fn test_sign_and_verify() {
    let kp = crypto::generate_key_pair().unwrap();
    let message = b"The accountability primitive for AI agents";
    let signature = crypto::sign(message, &kp.signing_key).unwrap();

    assert_eq!(signature.len(), 64);
    assert!(crypto::verify(message, &signature, &kp.verifying_key));
}

#[test]
fn test_verify_tampered_message() {
    let kp = crypto::generate_key_pair().unwrap();
    let message = b"original message";
    let signature = crypto::sign(message, &kp.signing_key).unwrap();

    assert!(!crypto::verify(b"tampered message", &signature, &kp.verifying_key));
}

#[test]
fn test_verify_wrong_key() {
    let kp1 = crypto::generate_key_pair().unwrap();
    let kp2 = crypto::generate_key_pair().unwrap();
    let message = b"test message";
    let signature = crypto::sign(message, &kp1.signing_key).unwrap();

    assert!(!crypto::verify(message, &signature, &kp2.verifying_key));
}

#[test]
fn test_verify_invalid_signature_length() {
    let kp = crypto::generate_key_pair().unwrap();
    assert!(!crypto::verify(b"msg", &[0u8; 32], &kp.verifying_key));
}

#[test]
fn test_sha256_known_value() {
    let hash = crypto::sha256_string("hello");
    assert_eq!(
        hash,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn test_sha256_object_determinism() {
    let obj1 = serde_json::json!({"z": 1, "a": 2, "m": 3});
    let obj2 = serde_json::json!({"a": 2, "m": 3, "z": 1});
    let hash1 = crypto::sha256_object(&obj1).unwrap();
    let hash2 = crypto::sha256_object(&obj2).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn test_canonicalize_json_sorts_keys() {
    let obj = serde_json::json!({"zebra": 1, "apple": 2, "mango": 3});
    let canonical = crypto::canonicalize_json(&obj);
    assert_eq!(canonical, r#"{"apple":2,"mango":3,"zebra":1}"#);
}

#[test]
fn test_canonicalize_json_nested() {
    let obj = serde_json::json!({"b": {"d": 1, "c": 2}, "a": 3});
    let canonical = crypto::canonicalize_json(&obj);
    assert_eq!(canonical, r#"{"a":3,"b":{"c":2,"d":1}}"#);
}

#[test]
fn test_generate_nonce() {
    let nonce1 = crypto::generate_nonce();
    let nonce2 = crypto::generate_nonce();
    assert_eq!(nonce1.len(), 32);
    assert_eq!(nonce2.len(), 32);
    assert_ne!(nonce1, nonce2);
}

#[test]
fn test_constant_time_equal() {
    assert!(crypto::constant_time_equal(b"hello", b"hello"));
    assert!(!crypto::constant_time_equal(b"hello", b"world"));
    assert!(!crypto::constant_time_equal(b"short", b"longer string"));
    assert!(crypto::constant_time_equal(b"", b""));
}

#[test]
fn test_timestamp_format() {
    let ts = crypto::timestamp();
    assert!(ts.contains('T'));
    assert!(ts.ends_with('Z'));
    // Verify it contains year, month, day, etc.
    assert!(ts.len() >= 20);
}

// ===========================================================================
// CCL tests
// ===========================================================================

#[test]
fn test_ccl_parse_permit() {
    let doc = ccl::parse("permit read on '/data/**'").unwrap();
    assert_eq!(doc.statements.len(), 1);
    assert_eq!(doc.permits.len(), 1);
    assert_eq!(doc.permits[0].action, "read");
    assert_eq!(doc.permits[0].resource, "/data/**");
}

#[test]
fn test_ccl_parse_deny() {
    let doc = ccl::parse("deny write on '/secrets/**'").unwrap();
    assert_eq!(doc.denies.len(), 1);
    assert_eq!(doc.denies[0].action, "write");
    assert_eq!(doc.denies[0].resource, "/secrets/**");
}

#[test]
fn test_ccl_parse_require() {
    let doc = ccl::parse("require audit.log on '/transactions/**'").unwrap();
    assert_eq!(doc.obligations.len(), 1);
    assert_eq!(doc.obligations[0].action, "audit.log");
}

#[test]
fn test_ccl_parse_limit() {
    let doc = ccl::parse("limit api.call 100 per 1 hours").unwrap();
    assert_eq!(doc.limits.len(), 1);
    assert_eq!(doc.limits[0].limit, Some(100.0));
    assert_eq!(doc.limits[0].period, Some(3600.0));
    assert_eq!(doc.limits[0].action, "api.call");
}

#[test]
fn test_ccl_parse_multiple_statements() {
    let source = "permit read on '/data/**'\ndeny write on '/data/secret'\nlimit api.call 50 per 60 seconds";
    let doc = ccl::parse(source).unwrap();
    assert_eq!(doc.statements.len(), 3);
    assert_eq!(doc.permits.len(), 1);
    assert_eq!(doc.denies.len(), 1);
    assert_eq!(doc.limits.len(), 1);
}

#[test]
fn test_ccl_parse_with_condition() {
    let doc = ccl::parse("permit read on '/data/**' when user.role = 'admin'").unwrap();
    assert_eq!(doc.permits.len(), 1);
    let cond = doc.permits[0].condition.as_ref().unwrap();
    assert_eq!(cond.field, "user.role");
    assert_eq!(cond.operator, "=");
    assert_eq!(cond.value, "admin");
}

#[test]
fn test_ccl_parse_wildcard_action() {
    let doc = ccl::parse("permit ** on '/public/**'").unwrap();
    assert_eq!(doc.permits[0].action, "**");
}

#[test]
fn test_ccl_parse_dotted_action() {
    let doc = ccl::parse("permit file.read on '/docs/**'").unwrap();
    assert_eq!(doc.permits[0].action, "file.read");
}

#[test]
fn test_ccl_parse_with_comments() {
    let source = "# This is a comment\npermit read on '/data/**'\n# Another comment";
    let doc = ccl::parse(source).unwrap();
    assert_eq!(doc.permits.len(), 1);
}

#[test]
fn test_ccl_parse_empty_input() {
    let doc = ccl::parse("").unwrap();
    assert_eq!(doc.statements.len(), 0);
}

#[test]
fn test_ccl_parse_invalid_syntax() {
    let result = ccl::parse("invalid syntax here");
    assert!(result.is_err());
}

#[test]
fn test_ccl_match_action_exact() {
    assert!(ccl::match_action("read", "read"));
    assert!(!ccl::match_action("read", "write"));
}

#[test]
fn test_ccl_match_action_single_wildcard() {
    assert!(ccl::match_action("file.*", "file.read"));
    assert!(ccl::match_action("file.*", "file.write"));
    assert!(!ccl::match_action("file.*", "file.read.all"));
    assert!(!ccl::match_action("file.*", "net.read"));
}

#[test]
fn test_ccl_match_action_double_wildcard() {
    assert!(ccl::match_action("**", "anything"));
    assert!(ccl::match_action("**", "anything.here.deep"));
    assert!(ccl::match_action("file.**", "file.read"));
    assert!(ccl::match_action("file.**", "file.read.all"));
}

#[test]
fn test_ccl_match_resource_exact() {
    assert!(ccl::match_resource("/data", "/data"));
    assert!(!ccl::match_resource("/data", "/other"));
}

#[test]
fn test_ccl_match_resource_single_wildcard() {
    assert!(ccl::match_resource("/data/*", "/data/users"));
    assert!(!ccl::match_resource("/data/*", "/data/users/123"));
}

#[test]
fn test_ccl_match_resource_double_wildcard() {
    assert!(ccl::match_resource("/data/**", "/data/users"));
    assert!(ccl::match_resource("/data/**", "/data/users/123"));
    assert!(ccl::match_resource("**", "/anything/here"));
}

#[test]
fn test_ccl_evaluate_permit() {
    let doc = ccl::parse("permit read on '/data/**'").unwrap();
    let ctx = HashMap::new();
    let result = ccl::evaluate(&doc, "read", "/data/users", &ctx);
    assert!(result.permitted);
}

#[test]
fn test_ccl_evaluate_default_deny() {
    let doc = ccl::parse("permit read on '/data/**'").unwrap();
    let ctx = HashMap::new();
    let result = ccl::evaluate(&doc, "write", "/data/users", &ctx);
    assert!(!result.permitted);
}

#[test]
fn test_ccl_evaluate_deny_wins_at_equal_specificity() {
    let doc = ccl::parse("permit read on '/data/**'\ndeny read on '/data/**'").unwrap();
    let ctx = HashMap::new();
    let result = ccl::evaluate(&doc, "read", "/data/users", &ctx);
    assert!(!result.permitted);
}

#[test]
fn test_ccl_evaluate_specific_deny_overrides_general_permit() {
    let doc = ccl::parse("permit read on '/data/**'\ndeny read on '/data/secret'").unwrap();
    let ctx = HashMap::new();

    let result_public = ccl::evaluate(&doc, "read", "/data/public", &ctx);
    assert!(result_public.permitted);

    let result_secret = ccl::evaluate(&doc, "read", "/data/secret", &ctx);
    assert!(!result_secret.permitted);
}

#[test]
fn test_ccl_evaluate_with_condition_pass() {
    let doc = ccl::parse("permit read on '/admin/**' when user.role = 'admin'").unwrap();
    let mut ctx = HashMap::new();
    ctx.insert("user.role".to_string(), "admin".to_string());
    let result = ccl::evaluate(&doc, "read", "/admin/dashboard", &ctx);
    assert!(result.permitted);
}

#[test]
fn test_ccl_evaluate_with_condition_fail() {
    let doc = ccl::parse("permit read on '/admin/**' when user.role = 'admin'").unwrap();
    let mut ctx = HashMap::new();
    ctx.insert("user.role".to_string(), "user".to_string());
    let result = ccl::evaluate(&doc, "read", "/admin/dashboard", &ctx);
    assert!(!result.permitted);
}

#[test]
fn test_ccl_evaluate_no_matching_resource() {
    let doc = ccl::parse("permit read on '/data/**'").unwrap();
    let ctx = HashMap::new();
    let result = ccl::evaluate(&doc, "read", "/other/path", &ctx);
    assert!(!result.permitted);
}

#[test]
fn test_ccl_check_rate_limit_within_limit() {
    let doc = ccl::parse("limit api.call 100 per 1 hours").unwrap();
    let now_ms = 1000000i64;
    let window_start = now_ms - 500; // well within the hour
    let result = ccl::check_rate_limit(&doc, "api.call", 50, window_start, now_ms);
    assert!(!result.exceeded);
    assert_eq!(result.remaining, 50);
    assert_eq!(result.limit, 100);
}

#[test]
fn test_ccl_check_rate_limit_exceeded() {
    let doc = ccl::parse("limit api.call 100 per 1 hours").unwrap();
    let now_ms = 1000000i64;
    let window_start = now_ms - 500;
    let result = ccl::check_rate_limit(&doc, "api.call", 100, window_start, now_ms);
    assert!(result.exceeded);
    assert_eq!(result.remaining, 0);
}

#[test]
fn test_ccl_check_rate_limit_expired_window() {
    let doc = ccl::parse("limit api.call 100 per 1 hours").unwrap();
    let now_ms = 100_000_000i64;
    let window_start = now_ms - 4_000_000; // more than 1 hour ago
    let result = ccl::check_rate_limit(&doc, "api.call", 200, window_start, now_ms);
    assert!(!result.exceeded);
    assert_eq!(result.remaining, 100); // reset
}

#[test]
fn test_ccl_check_rate_limit_no_matching_limit() {
    let doc = ccl::parse("permit read on '/data/**'").unwrap();
    let result = ccl::check_rate_limit(&doc, "api.call", 1000, 0, 1000);
    assert!(!result.exceeded);
}

#[test]
fn test_ccl_validate_narrowing_valid() {
    let parent = ccl::parse("permit read on '/data/**'").unwrap();
    let child = ccl::parse("permit read on '/data/subset'").unwrap();
    let result = ccl::validate_narrowing(&parent, &child);
    assert!(result.valid);
}

#[test]
fn test_ccl_validate_narrowing_violation_broader_permit() {
    let parent = ccl::parse("permit read on '/data/**'").unwrap();
    let child = ccl::parse("permit write on '/data/**'").unwrap();
    let result = ccl::validate_narrowing(&parent, &child);
    assert!(!result.valid);
    assert!(!result.violations.is_empty());
}

#[test]
fn test_ccl_validate_narrowing_child_permits_parent_denies() {
    let parent = ccl::parse("deny write on '/data/**'").unwrap();
    let child = ccl::parse("permit write on '/data/foo'").unwrap();
    let result = ccl::validate_narrowing(&parent, &child);
    assert!(!result.valid);
}

#[test]
fn test_ccl_merge() {
    let parent = ccl::parse("permit read on '/data/**'").unwrap();
    let child = ccl::parse("deny read on '/data/secret'").unwrap();
    let merged = ccl::merge(&parent, &child);

    assert_eq!(merged.permits.len(), 1);
    assert_eq!(merged.denies.len(), 1);

    // Deny should win for the secret path
    let ctx = HashMap::new();
    let result = ccl::evaluate(&merged, "read", "/data/secret", &ctx);
    assert!(!result.permitted);

    // Permit should still work for non-secret paths
    let result2 = ccl::evaluate(&merged, "read", "/data/public", &ctx);
    assert!(result2.permitted);
}

#[test]
fn test_ccl_merge_limits_more_restrictive_wins() {
    let parent = ccl::parse("limit api.call 100 per 1 hours").unwrap();
    let child = ccl::parse("limit api.call 50 per 1 hours").unwrap();
    let merged = ccl::merge(&parent, &child);
    assert_eq!(merged.limits.len(), 1);
    assert_eq!(merged.limits[0].limit, Some(50.0));
}

#[test]
fn test_ccl_serialize() {
    let doc = ccl::parse("permit read on '/data/**'\ndeny write on '/secrets/**'").unwrap();
    let serialized = ccl::serialize(&doc);
    assert!(serialized.contains("permit"));
    assert!(serialized.contains("deny"));
    assert!(serialized.contains("read"));
    assert!(serialized.contains("write"));
}

#[test]
fn test_ccl_limit_time_units() {
    let doc_sec = ccl::parse("limit api.call 10 per 30 seconds").unwrap();
    assert_eq!(doc_sec.limits[0].period, Some(30.0));

    let doc_min = ccl::parse("limit api.call 10 per 5 minutes").unwrap();
    assert_eq!(doc_min.limits[0].period, Some(300.0));

    let doc_hr = ccl::parse("limit api.call 10 per 2 hours").unwrap();
    assert_eq!(doc_hr.limits[0].period, Some(7200.0));

    let doc_day = ccl::parse("limit api.call 10 per 1 days").unwrap();
    assert_eq!(doc_day.limits[0].period, Some(86400.0));
}

// ===========================================================================
// Covenant tests
// ===========================================================================

#[test]
fn test_covenant_build_and_verify() {
    let (doc, _) = build_test_covenant("permit read on '/data/**'");

    assert!(!doc.id.is_empty());
    assert_eq!(doc.version, PROTOCOL_VERSION);
    assert!(!doc.signature.is_empty());
    assert!(!doc.nonce.is_empty());
    assert_eq!(doc.nonce.len(), 64);

    let result = covenant::verify_covenant(&doc).unwrap();
    assert!(result.valid, "Verification failed: {:?}", result.checks);

    // Verify each check passed
    for check in &result.checks {
        assert!(check.passed, "Check '{}' failed: {}", check.name, check.message);
    }
}

#[test]
fn test_covenant_id_is_deterministic() {
    let (doc, _) = build_test_covenant("permit read on '/data/**'");
    let computed_id = covenant::compute_id(&doc).unwrap();
    assert_eq!(doc.id, computed_id);
}

#[test]
fn test_covenant_canonical_form_excludes_mutable_fields() {
    let (doc, _) = build_test_covenant("permit read on '/data/**'");
    let canonical = covenant::canonical_form(&doc).unwrap();

    // Canonical form should not contain id or signature as top-level keys
    let parsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
    let obj = parsed.as_object().unwrap();
    assert!(!obj.contains_key("id"));
    assert!(!obj.contains_key("signature"));
    assert!(!obj.contains_key("countersignatures"));

    // But should contain the core fields
    assert!(obj.contains_key("version"));
    assert!(obj.contains_key("issuer"));
    assert!(obj.contains_key("beneficiary"));
    assert!(obj.contains_key("constraints"));
    assert!(obj.contains_key("nonce"));
}

#[test]
fn test_covenant_tampered_signature_fails_verification() {
    let (mut doc, _) = build_test_covenant("permit read on '/data/**'");
    // Tamper with the signature
    doc.signature = "0".repeat(128);

    let result = covenant::verify_covenant(&doc).unwrap();
    assert!(!result.valid);

    let sig_check = result.checks.iter().find(|c| c.name == "signature_valid").unwrap();
    assert!(!sig_check.passed);
}

#[test]
fn test_covenant_tampered_id_fails_verification() {
    let (mut doc, _) = build_test_covenant("permit read on '/data/**'");
    doc.id = "0".repeat(64);

    let result = covenant::verify_covenant(&doc).unwrap();
    assert!(!result.valid);

    let id_check = result.checks.iter().find(|c| c.name == "id_match").unwrap();
    assert!(!id_check.passed);
}

#[test]
fn test_covenant_serialize_and_deserialize() {
    let (doc, _) = build_test_covenant("permit read on '/data/**'");

    let json = covenant::serialize_covenant(&doc).unwrap();
    assert!(!json.is_empty());

    let restored = covenant::deserialize_covenant(&json).unwrap();
    assert_eq!(doc.id, restored.id);
    assert_eq!(doc.signature, restored.signature);
    assert_eq!(doc.version, restored.version);
    assert_eq!(doc.constraints, restored.constraints);
    assert_eq!(doc.nonce, restored.nonce);

    // The restored document should also verify
    let result = covenant::verify_covenant(&restored).unwrap();
    assert!(result.valid, "Restored document verification failed: {:?}", result.checks);
}

#[test]
fn test_covenant_countersign() {
    let (doc, _) = build_test_covenant("permit read on '/data/**'");

    let auditor_kp = crypto::generate_key_pair().unwrap();
    let signed = covenant::countersign_covenant(&doc, &auditor_kp, "auditor").unwrap();

    assert!(signed.countersignatures.is_some());
    let countersigs = signed.countersignatures.as_ref().unwrap();
    assert_eq!(countersigs.len(), 1);
    assert_eq!(countersigs[0].signer_public_key, auditor_kp.public_key_hex);
    assert_eq!(countersigs[0].signer_role, "auditor");

    // Verify the countersigned document
    let result = covenant::verify_covenant(&signed).unwrap();
    assert!(result.valid, "Countersigned verification failed: {:?}", result.checks);
}

#[test]
fn test_covenant_multiple_countersignatures() {
    let (doc, _) = build_test_covenant("permit read on '/data/**'");

    let auditor_kp = crypto::generate_key_pair().unwrap();
    let regulator_kp = crypto::generate_key_pair().unwrap();

    let with_auditor = covenant::countersign_covenant(&doc, &auditor_kp, "auditor").unwrap();
    let with_both =
        covenant::countersign_covenant(&with_auditor, &regulator_kp, "regulator").unwrap();

    let countersigs = with_both.countersignatures.as_ref().unwrap();
    assert_eq!(countersigs.len(), 2);

    let result = covenant::verify_covenant(&with_both).unwrap();
    assert!(result.valid, "Multi-countersign verification failed: {:?}", result.checks);
}

#[test]
fn test_covenant_with_chain_reference() {
    let (parent_doc, _) = build_test_covenant("permit read on '/data/**'");

    let issuer_kp = crypto::generate_key_pair().unwrap();
    let beneficiary_kp = crypto::generate_key_pair().unwrap();

    let child_doc = covenant::build_covenant(CovenantBuilderOptions {
        issuer: make_issuer(&issuer_kp),
        beneficiary: make_beneficiary(&beneficiary_kp),
        constraints: "permit read on '/data/subset'".to_string(),
        signing_key: issuer_kp.signing_key,
        chain: Some(ChainReference {
            parent_id: parent_doc.id.clone(),
            relation: "delegates".to_string(),
            depth: 1,
        }),
        expires_at: None,
        activates_at: None,
        metadata: None,
    })
    .unwrap();

    assert!(child_doc.chain.is_some());
    let chain = child_doc.chain.as_ref().unwrap();
    assert_eq!(chain.parent_id, parent_doc.id);
    assert_eq!(chain.relation, "delegates");
    assert_eq!(chain.depth, 1);

    let result = covenant::verify_covenant(&child_doc).unwrap();
    assert!(result.valid, "Chained covenant verification failed: {:?}", result.checks);
}

#[test]
fn test_covenant_chain_depth_exceeds_maximum() {
    let issuer_kp = crypto::generate_key_pair().unwrap();
    let beneficiary_kp = crypto::generate_key_pair().unwrap();

    let result = covenant::build_covenant(CovenantBuilderOptions {
        issuer: make_issuer(&issuer_kp),
        beneficiary: make_beneficiary(&beneficiary_kp),
        constraints: "permit read on '/data/**'".to_string(),
        signing_key: issuer_kp.signing_key,
        chain: Some(ChainReference {
            parent_id: "some-parent-id".to_string(),
            relation: "delegates".to_string(),
            depth: MAX_CHAIN_DEPTH + 1,
        }),
        expires_at: None,
        activates_at: None,
        metadata: None,
    });

    assert!(result.is_err());
}

#[test]
fn test_covenant_chain_narrowing_valid() {
    let (parent, _) = build_test_covenant("permit read on '/data/**'");

    let issuer_kp = crypto::generate_key_pair().unwrap();
    let beneficiary_kp = crypto::generate_key_pair().unwrap();
    let child = covenant::build_covenant(CovenantBuilderOptions {
        issuer: make_issuer(&issuer_kp),
        beneficiary: make_beneficiary(&beneficiary_kp),
        constraints: "permit read on '/data/subset'".to_string(),
        signing_key: issuer_kp.signing_key,
        chain: Some(ChainReference {
            parent_id: parent.id.clone(),
            relation: "restricts".to_string(),
            depth: 1,
        }),
        expires_at: None,
        activates_at: None,
        metadata: None,
    })
    .unwrap();

    let narrowing = covenant::validate_chain_narrowing(&child, &parent).unwrap();
    assert!(narrowing.valid);
}

#[test]
fn test_covenant_chain_narrowing_violation() {
    let (parent, _) = build_test_covenant("permit read on '/data/**'");

    let issuer_kp = crypto::generate_key_pair().unwrap();
    let beneficiary_kp = crypto::generate_key_pair().unwrap();
    let child = covenant::build_covenant(CovenantBuilderOptions {
        issuer: make_issuer(&issuer_kp),
        beneficiary: make_beneficiary(&beneficiary_kp),
        constraints: "permit write on '/other/**'".to_string(),
        signing_key: issuer_kp.signing_key,
        chain: Some(ChainReference {
            parent_id: parent.id.clone(),
            relation: "restricts".to_string(),
            depth: 1,
        }),
        expires_at: None,
        activates_at: None,
        metadata: None,
    })
    .unwrap();

    let narrowing = covenant::validate_chain_narrowing(&child, &parent).unwrap();
    assert!(!narrowing.valid);
}

#[test]
fn test_covenant_with_metadata() {
    let issuer_kp = crypto::generate_key_pair().unwrap();
    let beneficiary_kp = crypto::generate_key_pair().unwrap();

    let doc = covenant::build_covenant(CovenantBuilderOptions {
        issuer: make_issuer(&issuer_kp),
        beneficiary: make_beneficiary(&beneficiary_kp),
        constraints: "permit read on '/data/**'".to_string(),
        signing_key: issuer_kp.signing_key,
        chain: None,
        expires_at: None,
        activates_at: None,
        metadata: Some(serde_json::json!({
            "name": "Test Covenant",
            "description": "A test covenant for integration testing",
            "tags": ["test", "integration"]
        })),
    })
    .unwrap();

    assert!(doc.metadata.is_some());
    let result = covenant::verify_covenant(&doc).unwrap();
    assert!(result.valid);
}

#[test]
fn test_covenant_requires_issuer_role() {
    let kp = crypto::generate_key_pair().unwrap();
    let bene_kp = crypto::generate_key_pair().unwrap();

    let result = covenant::build_covenant(CovenantBuilderOptions {
        issuer: Party {
            id: "wrong".to_string(),
            public_key: kp.public_key_hex.clone(),
            role: "beneficiary".to_string(), // wrong role
        },
        beneficiary: make_beneficiary(&bene_kp),
        constraints: "permit read on '/data/**'".to_string(),
        signing_key: kp.signing_key,
        chain: None,
        expires_at: None,
        activates_at: None,
        metadata: None,
    });

    assert!(result.is_err());
}

#[test]
fn test_covenant_requires_non_empty_constraints() {
    let kp = crypto::generate_key_pair().unwrap();
    let bene_kp = crypto::generate_key_pair().unwrap();

    let result = covenant::build_covenant(CovenantBuilderOptions {
        issuer: make_issuer(&kp),
        beneficiary: make_beneficiary(&bene_kp),
        constraints: "".to_string(),
        signing_key: kp.signing_key,
        chain: None,
        expires_at: None,
        activates_at: None,
        metadata: None,
    });

    assert!(result.is_err());
}

#[test]
fn test_covenant_nonce_check() {
    let (doc, _) = build_test_covenant("permit read on '/data/**'");
    let result = covenant::verify_covenant(&doc).unwrap();
    let nonce_check = result.checks.iter().find(|c| c.name == "nonce_present").unwrap();
    assert!(nonce_check.passed);
}

#[test]
fn test_covenant_all_11_checks_present() {
    let (doc, _) = build_test_covenant("permit read on '/data/**'");
    let result = covenant::verify_covenant(&doc).unwrap();

    let check_names: Vec<&str> = result.checks.iter().map(|c| c.name.as_str()).collect();
    assert!(check_names.contains(&"id_match"));
    assert!(check_names.contains(&"signature_valid"));
    assert!(check_names.contains(&"not_expired"));
    assert!(check_names.contains(&"active"));
    assert!(check_names.contains(&"ccl_parses"));
    assert!(check_names.contains(&"enforcement_valid"));
    assert!(check_names.contains(&"proof_valid"));
    assert!(check_names.contains(&"chain_depth"));
    assert!(check_names.contains(&"document_size"));
    assert!(check_names.contains(&"countersignatures"));
    assert!(check_names.contains(&"nonce_present"));
    assert_eq!(result.checks.len(), 11);
}

// ===========================================================================
// Identity tests
// ===========================================================================

#[test]
fn test_identity_create() {
    let kp = crypto::generate_key_pair().unwrap();
    let ident = identity::create_identity(CreateIdentityOptions {
        signing_key: kp.signing_key,
        public_key_hex: kp.public_key_hex.clone(),
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

    assert!(!ident.id.is_empty());
    assert_eq!(ident.version, 1);
    assert_eq!(ident.lineage.len(), 1);
    assert_eq!(ident.lineage[0].change_type, "created");
    assert!(ident.lineage[0].parent_hash.is_none());
    assert_eq!(ident.operator_public_key, kp.public_key_hex);
    assert!(!ident.signature.is_empty());
}

#[test]
fn test_identity_capabilities_sorted() {
    let kp = crypto::generate_key_pair().unwrap();
    let ident = identity::create_identity(CreateIdentityOptions {
        signing_key: kp.signing_key,
        public_key_hex: kp.public_key_hex,
        model: ModelInfo {
            provider: "anthropic".to_string(),
            model_id: "claude-3".to_string(),
        },
        capabilities: vec!["write".to_string(), "admin".to_string(), "read".to_string()],
        deployment: DeploymentInfo {
            runtime: "container".to_string(),
        },
    })
    .unwrap();

    assert_eq!(
        ident.capabilities,
        vec!["admin", "read", "write"]
    );
}

#[test]
fn test_identity_evolve() {
    let kp = crypto::generate_key_pair().unwrap();
    let original = identity::create_identity(CreateIdentityOptions {
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

    let evolved = identity::evolve_identity(
        &original,
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
    assert_ne!(original.id, evolved.id);
    assert_eq!(evolved.lineage[1].change_type, "capability_change");
    assert_eq!(evolved.capabilities, vec!["read", "write"]);

    // Parent hash of second entry should reference first entry
    assert!(evolved.lineage[1].parent_hash.is_some());
    assert_eq!(
        evolved.lineage[1].parent_hash.as_ref().unwrap(),
        &original.lineage[0].identity_hash
    );
}

#[test]
fn test_identity_evolve_model_update() {
    let kp = crypto::generate_key_pair().unwrap();
    let original = identity::create_identity(CreateIdentityOptions {
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

    let evolved = identity::evolve_identity(
        &original,
        EvolveIdentityOptions {
            signing_key: kp.signing_key,
            change_type: "model_update".to_string(),
            description: "Upgraded to claude-4".to_string(),
            model: Some(ModelInfo {
                provider: "anthropic".to_string(),
                model_id: "claude-4".to_string(),
            }),
            capabilities: None,
            deployment: None,
        },
    )
    .unwrap();

    assert_eq!(evolved.model.model_id, "claude-4");
    assert_eq!(evolved.version, 2);
}

#[test]
fn test_identity_verify() {
    let kp = crypto::generate_key_pair().unwrap();
    let ident = identity::create_identity(CreateIdentityOptions {
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

    let result = identity::verify_identity(&ident).unwrap();
    assert!(result.valid, "Identity verification failed: {:?}", result.checks);

    // Check that all individual checks passed
    for check in &result.checks {
        assert!(check.passed, "Check '{}' failed: {}", check.name, check.message);
    }
}

#[test]
fn test_identity_serialize_deserialize() {
    let kp = crypto::generate_key_pair().unwrap();
    let original = identity::create_identity(CreateIdentityOptions {
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

    let json = identity::serialize_identity(&original).unwrap();
    assert!(!json.is_empty());
    assert!(json.contains("anthropic"));
    assert!(json.contains("claude-3"));

    let restored = identity::deserialize_identity(&json).unwrap();
    assert_eq!(original.id, restored.id);
    assert_eq!(original.signature, restored.signature);
    assert_eq!(original.version, restored.version);
    assert_eq!(original.capabilities, restored.capabilities);
}

#[test]
fn test_identity_create_requires_public_key() {
    let kp = crypto::generate_key_pair().unwrap();
    let result = identity::create_identity(CreateIdentityOptions {
        signing_key: kp.signing_key,
        public_key_hex: String::new(),
        model: ModelInfo {
            provider: "anthropic".to_string(),
            model_id: "claude-3".to_string(),
        },
        capabilities: vec!["read".to_string()],
        deployment: DeploymentInfo {
            runtime: "container".to_string(),
        },
    });
    assert!(result.is_err());
}

#[test]
fn test_identity_create_requires_capabilities() {
    let kp = crypto::generate_key_pair().unwrap();
    let result = identity::create_identity(CreateIdentityOptions {
        signing_key: kp.signing_key,
        public_key_hex: kp.public_key_hex,
        model: ModelInfo {
            provider: "anthropic".to_string(),
            model_id: "claude-3".to_string(),
        },
        capabilities: vec![],
        deployment: DeploymentInfo {
            runtime: "container".to_string(),
        },
    });
    assert!(result.is_err());
}

#[test]
fn test_identity_evolve_preserves_created_at() {
    let kp = crypto::generate_key_pair().unwrap();
    let original = identity::create_identity(CreateIdentityOptions {
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

    let evolved = identity::evolve_identity(
        &original,
        EvolveIdentityOptions {
            signing_key: kp.signing_key,
            change_type: "capability_change".to_string(),
            description: "Test".to_string(),
            model: None,
            capabilities: Some(vec!["read".to_string(), "write".to_string()]),
            deployment: None,
        },
    )
    .unwrap();

    assert_eq!(original.created_at, evolved.created_at);
}

#[test]
fn test_identity_hash_determinism() {
    let body = serde_json::json!({
        "operatorPublicKey": "abc123",
        "model": {"provider": "test", "modelId": "v1"},
        "capabilities": ["read"],
    });
    let hash1 = identity::compute_identity_hash(&body);
    let hash2 = identity::compute_identity_hash(&body);
    assert_eq!(hash1, hash2);
}

// ===========================================================================
// Store tests
// ===========================================================================

#[test]
fn test_store_put_and_get() {
    let mut store = MemoryStore::new();
    let (doc, _) = build_test_covenant("permit read on '/data/**'");
    let id = doc.id.clone();

    store.put(&id, doc).unwrap();
    assert!(store.has(&id));

    let retrieved = store.get(&id).unwrap().unwrap();
    assert_eq!(retrieved.id, id);
}

#[test]
fn test_store_get_nonexistent() {
    let store = MemoryStore::new();
    let result = store.get("nonexistent").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_store_has_nonexistent() {
    let store = MemoryStore::new();
    assert!(!store.has("nonexistent"));
}

#[test]
fn test_store_delete_existing() {
    let mut store = MemoryStore::new();
    let (doc, _) = build_test_covenant("permit read on '/data/**'");
    let id = doc.id.clone();

    store.put(&id, doc).unwrap();
    assert_eq!(store.count(), 1);

    let deleted = store.delete(&id).unwrap();
    assert!(deleted);
    assert_eq!(store.count(), 0);
    assert!(!store.has(&id));
}

#[test]
fn test_store_delete_nonexistent() {
    let mut store = MemoryStore::new();
    let deleted = store.delete("nonexistent").unwrap();
    assert!(!deleted);
}

#[test]
fn test_store_list() {
    let mut store = MemoryStore::new();
    let (doc1, _) = build_test_covenant("permit read on '/data/**'");
    let (doc2, _) = build_test_covenant("permit write on '/data/**'");
    let id1 = doc1.id.clone();
    let id2 = doc2.id.clone();

    store.put(&id1, doc1).unwrap();
    store.put(&id2, doc2).unwrap();

    assert_eq!(store.list().len(), 2);
    assert_eq!(store.count(), 2);
}

#[test]
fn test_store_count_empty() {
    let store = MemoryStore::new();
    assert_eq!(store.count(), 0);
}

#[test]
fn test_store_overwrite() {
    let mut store = MemoryStore::new();
    let (doc1, _) = build_test_covenant("permit read on '/data/**'");
    let id = doc1.id.clone();

    store.put(&id, doc1).unwrap();

    let (doc2, _) = build_test_covenant("permit write on '/data/**'");
    store.put(&id, doc2).unwrap();

    // Store should still have only 1 entry
    assert_eq!(store.count(), 1);
}

#[test]
fn test_store_empty_id_rejected() {
    let mut store = MemoryStore::new();
    let (doc, _) = build_test_covenant("permit read on '/data/**'");
    let result = store.put("", doc);
    assert!(result.is_err());
}

// ===========================================================================
// End-to-end integration test
// ===========================================================================

#[test]
fn test_full_protocol_flow() {
    // 1. Generate keys for all parties
    let operator_kp = crypto::generate_key_pair().unwrap();
    let agent_kp = crypto::generate_key_pair().unwrap();
    let auditor_kp = crypto::generate_key_pair().unwrap();

    // 2. Create agent identity
    let agent_identity = identity::create_identity(CreateIdentityOptions {
        signing_key: operator_kp.signing_key.clone(),
        public_key_hex: operator_kp.public_key_hex.clone(),
        model: ModelInfo {
            provider: "anthropic".to_string(),
            model_id: "claude-3".to_string(),
        },
        capabilities: vec![
            "read".to_string(),
            "write".to_string(),
            "api.call".to_string(),
        ],
        deployment: DeploymentInfo {
            runtime: "container".to_string(),
        },
    })
    .unwrap();
    assert_eq!(agent_identity.version, 1);

    // 3. Build a root covenant
    let constraints = "permit read on '/data/**'\npermit write on '/data/agent/**'\ndeny write on '/data/system/**'\nlimit api.call 100 per 1 hours";
    let root_covenant = covenant::build_covenant(CovenantBuilderOptions {
        issuer: Party {
            id: "operator".to_string(),
            public_key: operator_kp.public_key_hex.clone(),
            role: "issuer".to_string(),
        },
        beneficiary: Party {
            id: "agent".to_string(),
            public_key: agent_kp.public_key_hex.clone(),
            role: "beneficiary".to_string(),
        },
        constraints: constraints.to_string(),
        signing_key: operator_kp.signing_key.clone(),
        chain: None,
        expires_at: None,
        activates_at: None,
        metadata: Some(serde_json::json!({
            "name": "Agent Root Covenant",
            "description": "Root covenant for the AI agent"
        })),
    })
    .unwrap();

    // 4. Verify the root covenant
    let root_result = covenant::verify_covenant(&root_covenant).unwrap();
    assert!(root_result.valid, "Root covenant verification failed: {:?}", root_result.checks);

    // 5. Countersign with auditor
    let audited_covenant =
        covenant::countersign_covenant(&root_covenant, &auditor_kp, "auditor").unwrap();
    let audited_result = covenant::verify_covenant(&audited_covenant).unwrap();
    assert!(audited_result.valid, "Audited covenant verification failed");

    // 6. Build a child (delegated) covenant
    let child_constraints = "permit read on '/data/agent/**'\npermit write on '/data/agent/workspace'";
    let child_kp = crypto::generate_key_pair().unwrap();
    let child_covenant = covenant::build_covenant(CovenantBuilderOptions {
        issuer: Party {
            id: "agent".to_string(),
            public_key: agent_kp.public_key_hex.clone(),
            role: "issuer".to_string(),
        },
        beneficiary: Party {
            id: "sub-agent".to_string(),
            public_key: child_kp.public_key_hex.clone(),
            role: "beneficiary".to_string(),
        },
        constraints: child_constraints.to_string(),
        signing_key: agent_kp.signing_key.clone(),
        chain: Some(ChainReference {
            parent_id: root_covenant.id.clone(),
            relation: "delegates".to_string(),
            depth: 1,
        }),
        expires_at: None,
        activates_at: None,
        metadata: None,
    })
    .unwrap();

    let child_result = covenant::verify_covenant(&child_covenant).unwrap();
    assert!(child_result.valid, "Child covenant verification failed: {:?}", child_result.checks);

    // 7. Validate chain narrowing
    let narrowing = covenant::validate_chain_narrowing(&child_covenant, &root_covenant).unwrap();
    assert!(narrowing.valid, "Chain narrowing should be valid");

    // 8. Evaluate CCL constraints
    let ccl_doc = ccl::parse(constraints).unwrap();
    let ctx = HashMap::new();

    // Should be permitted
    let read_result = ccl::evaluate(&ccl_doc, "read", "/data/users", &ctx);
    assert!(read_result.permitted, "Read on /data/users should be permitted");

    // Should be denied (explicit deny)
    let write_system = ccl::evaluate(&ccl_doc, "write", "/data/system/config", &ctx);
    assert!(!write_system.permitted, "Write on /data/system should be denied");

    // Should be permitted
    let write_agent = ccl::evaluate(&ccl_doc, "write", "/data/agent/log", &ctx);
    assert!(write_agent.permitted, "Write on /data/agent should be permitted");

    // Should be denied (no matching rule)
    let delete_result = ccl::evaluate(&ccl_doc, "delete", "/data/users", &ctx);
    assert!(!delete_result.permitted, "Delete should be default denied");

    // 9. Check rate limits
    let now_ms = 1000000i64;
    let rate_result = ccl::check_rate_limit(&ccl_doc, "api.call", 50, now_ms - 100, now_ms);
    assert!(!rate_result.exceeded);
    assert_eq!(rate_result.remaining, 50);

    let rate_exceeded = ccl::check_rate_limit(&ccl_doc, "api.call", 100, now_ms - 100, now_ms);
    assert!(rate_exceeded.exceeded);

    // 10. Store covenants
    let mut store = MemoryStore::new();
    store
        .put(&root_covenant.id, root_covenant.clone())
        .unwrap();
    store
        .put(&child_covenant.id, child_covenant.clone())
        .unwrap();
    assert_eq!(store.count(), 2);
    assert!(store.has(&root_covenant.id));
    assert!(store.has(&child_covenant.id));

    // 11. Evolve agent identity
    let evolved_identity = identity::evolve_identity(
        &agent_identity,
        EvolveIdentityOptions {
            signing_key: operator_kp.signing_key,
            change_type: "capability_change".to_string(),
            description: "Added admin capability".to_string(),
            model: None,
            capabilities: Some(vec![
                "read".to_string(),
                "write".to_string(),
                "api.call".to_string(),
                "admin".to_string(),
            ]),
            deployment: None,
        },
    )
    .unwrap();

    assert_eq!(evolved_identity.version, 2);
    assert_eq!(evolved_identity.lineage.len(), 2);
    assert_ne!(agent_identity.id, evolved_identity.id);

    // 12. Verify evolved identity
    let identity_result = identity::verify_identity(&evolved_identity).unwrap();
    assert!(
        identity_result.valid,
        "Evolved identity verification failed: {:?}",
        identity_result.checks
    );

    // 13. Serialize and deserialize round-trip
    let covenant_json = covenant::serialize_covenant(&audited_covenant).unwrap();
    let restored = covenant::deserialize_covenant(&covenant_json).unwrap();
    assert_eq!(audited_covenant.id, restored.id);

    let identity_json = identity::serialize_identity(&evolved_identity).unwrap();
    let restored_identity = identity::deserialize_identity(&identity_json).unwrap();
    assert_eq!(evolved_identity.id, restored_identity.id);
}
