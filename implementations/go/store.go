package stele

import (
	"encoding/json"
	"fmt"
	"sync"
)

// Store is the interface for covenant document storage.
type Store interface {
	// Put stores a covenant document, replacing any existing document
	// with the same ID.
	Put(id string, doc *CovenantDocument) error

	// Get retrieves a covenant document by its ID. Returns nil if not found.
	Get(id string) (*CovenantDocument, error)

	// Delete removes a document by ID. Returns an error if the document
	// does not exist.
	Delete(id string) error

	// List returns all stored documents.
	List() ([]*CovenantDocument, error)

	// Has checks whether a document with the given ID exists.
	Has(id string) bool

	// Count returns the number of documents in the store.
	Count() int
}

// MemoryStore is an in-memory implementation of the Store interface
// backed by a map. It is safe for concurrent use.
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]*CovenantDocument
}

// NewMemoryStore creates a new, empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string]*CovenantDocument),
	}
}

// Put stores a covenant document. The document is deep-copied so the
// caller's reference is not retained.
func (s *MemoryStore) Put(id string, doc *CovenantDocument) error {
	if id == "" {
		return fmt.Errorf("stele: store.Put: id must be a non-empty string")
	}
	if doc == nil {
		return fmt.Errorf("stele: store.Put: document is required")
	}

	// Deep copy via JSON round-trip
	copied, err := deepCopyDocument(doc)
	if err != nil {
		return fmt.Errorf("stele: store.Put: failed to copy document: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = copied
	return nil
}

// Get retrieves a covenant document by its ID. Returns a deep copy
// so callers cannot mutate the stored data. Returns nil if not found.
func (s *MemoryStore) Get(id string) (*CovenantDocument, error) {
	if id == "" {
		return nil, fmt.Errorf("stele: store.Get: id must be a non-empty string")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	doc, ok := s.data[id]
	if !ok {
		return nil, nil
	}

	copied, err := deepCopyDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("stele: store.Get: failed to copy document: %w", err)
	}
	return copied, nil
}

// Delete removes a document by ID. Returns an error if the document
// does not exist.
func (s *MemoryStore) Delete(id string) error {
	if id == "" {
		return fmt.Errorf("stele: store.Delete: id must be a non-empty string")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[id]; !ok {
		return fmt.Errorf("stele: store.Delete: document not found: %s", id)
	}

	delete(s.data, id)
	return nil
}

// List returns all stored documents. Each returned document is a deep copy.
func (s *MemoryStore) List() ([]*CovenantDocument, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*CovenantDocument, 0, len(s.data))
	for _, doc := range s.data {
		copied, err := deepCopyDocument(doc)
		if err != nil {
			return nil, fmt.Errorf("stele: store.List: failed to copy document: %w", err)
		}
		result = append(result, copied)
	}
	return result, nil
}

// Has checks whether a document with the given ID exists in the store.
func (s *MemoryStore) Has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[id]
	return ok
}

// Count returns the number of documents in the store.
func (s *MemoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

// Clear removes all documents from the store.
func (s *MemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = make(map[string]*CovenantDocument)
}

// deepCopyDocument creates a deep copy of a CovenantDocument via JSON
// round-trip serialization.
func deepCopyDocument(doc *CovenantDocument) (*CovenantDocument, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var copied CovenantDocument
	if err := json.Unmarshal(b, &copied); err != nil {
		return nil, err
	}
	return &copied, nil
}
