//! Covenant document storage.
//!
//! Provides a trait-based storage abstraction and an in-memory implementation.
//! The `Store` trait defines the minimal interface for storing and retrieving
//! covenant documents; `MemoryStore` is a simple HashMap-backed implementation
//! suitable for testing and lightweight use cases.

use crate::covenant::CovenantDocument;
use crate::SteleError;
use std::collections::HashMap;

/// Trait for covenant document storage.
///
/// Implementations must support basic CRUD operations plus listing
/// and counting. Documents are keyed by their unique `id` field.
pub trait Store {
    /// Store a covenant document, keyed by its ID.
    ///
    /// If a document with the same ID already exists, it is overwritten.
    fn put(&mut self, id: &str, doc: CovenantDocument) -> Result<(), SteleError>;

    /// Retrieve a covenant document by ID.
    ///
    /// Returns `Ok(Some(&doc))` if found, `Ok(None)` if not found.
    fn get(&self, id: &str) -> Result<Option<&CovenantDocument>, SteleError>;

    /// Delete a covenant document by ID.
    ///
    /// Returns `Ok(true)` if the document existed and was deleted,
    /// `Ok(false)` if the document was not found.
    fn delete(&mut self, id: &str) -> Result<bool, SteleError>;

    /// List all stored covenant documents.
    fn list(&self) -> Vec<&CovenantDocument>;

    /// Check whether a document with the given ID exists.
    fn has(&self, id: &str) -> bool;

    /// Return the number of stored documents.
    fn count(&self) -> usize;
}

/// In-memory covenant store backed by a `HashMap`.
///
/// Suitable for testing and single-process use cases. Not persistent
/// across restarts and not thread-safe (wrap in a `Mutex` if needed).
pub struct MemoryStore {
    documents: HashMap<String, CovenantDocument>,
}

impl MemoryStore {
    /// Create a new, empty `MemoryStore`.
    pub fn new() -> Self {
        MemoryStore {
            documents: HashMap::new(),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for MemoryStore {
    fn put(&mut self, id: &str, doc: CovenantDocument) -> Result<(), SteleError> {
        if id.is_empty() {
            return Err(SteleError::StorageError("Document ID cannot be empty".to_string()));
        }
        self.documents.insert(id.to_string(), doc);
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<&CovenantDocument>, SteleError> {
        Ok(self.documents.get(id))
    }

    fn delete(&mut self, id: &str) -> Result<bool, SteleError> {
        Ok(self.documents.remove(id).is_some())
    }

    fn list(&self) -> Vec<&CovenantDocument> {
        self.documents.values().collect()
    }

    fn has(&self, id: &str) -> bool {
        self.documents.contains_key(id)
    }

    fn count(&self) -> usize {
        self.documents.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::covenant::{self, CovenantBuilderOptions, Party};
    use crate::crypto;

    fn make_test_covenant() -> CovenantDocument {
        let kp = crypto::generate_key_pair().unwrap();
        let issuer = Party {
            id: "issuer-1".to_string(),
            public_key: kp.public_key_hex.clone(),
            role: "issuer".to_string(),
        };
        let bene_kp = crypto::generate_key_pair().unwrap();
        let beneficiary = Party {
            id: "beneficiary-1".to_string(),
            public_key: bene_kp.public_key_hex,
            role: "beneficiary".to_string(),
        };
        covenant::build_covenant(CovenantBuilderOptions {
            issuer,
            beneficiary,
            constraints: "permit read on '/data/**'".to_string(),
            signing_key: kp.signing_key,
            chain: None,
            expires_at: None,
            activates_at: None,
            metadata: None,
        })
        .unwrap()
    }

    #[test]
    fn test_put_and_get() {
        let mut store = MemoryStore::new();
        let doc = make_test_covenant();
        let id = doc.id.clone();

        store.put(&id, doc).unwrap();
        assert!(store.has(&id));

        let retrieved = store.get(&id).unwrap().unwrap();
        assert_eq!(retrieved.id, id);
    }

    #[test]
    fn test_delete() {
        let mut store = MemoryStore::new();
        let doc = make_test_covenant();
        let id = doc.id.clone();

        store.put(&id, doc).unwrap();
        assert_eq!(store.count(), 1);

        let deleted = store.delete(&id).unwrap();
        assert!(deleted);
        assert_eq!(store.count(), 0);

        let deleted_again = store.delete(&id).unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn test_list() {
        let mut store = MemoryStore::new();
        let doc1 = make_test_covenant();
        let doc2 = make_test_covenant();
        let id1 = doc1.id.clone();
        let id2 = doc2.id.clone();

        store.put(&id1, doc1).unwrap();
        store.put(&id2, doc2).unwrap();

        assert_eq!(store.list().len(), 2);
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn test_has_nonexistent() {
        let store = MemoryStore::new();
        assert!(!store.has("nonexistent"));
    }

    #[test]
    fn test_empty_id_error() {
        let mut store = MemoryStore::new();
        let doc = make_test_covenant();
        let result = store.put("", doc);
        assert!(result.is_err());
    }
}
