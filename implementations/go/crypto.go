package nobulex

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// KeyPair holds an Ed25519 key pair with a precomputed hex-encoded public key.
type KeyPair struct {
	PrivateKey   ed25519.PrivateKey
	PublicKey     ed25519.PublicKey
	PublicKeyHex string
}

// GenerateKeyPair generates a new Ed25519 key pair from cryptographically
// secure randomness.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("nobulex: failed to generate Ed25519 key pair: %w", err)
	}
	return &KeyPair{
		PrivateKey:   priv,
		PublicKey:     pub,
		PublicKeyHex: hex.EncodeToString(pub),
	}, nil
}

// KeyPairFromPrivateKey reconstructs a KeyPair from an existing Ed25519
// private key. The private key must be 64 bytes (Go's ed25519.PrivateKey
// format which includes the public key suffix).
func KeyPairFromPrivateKey(privateKey ed25519.PrivateKey) (*KeyPair, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("nobulex: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	pub := privateKey.Public().(ed25519.PublicKey)
	keyCopy := make(ed25519.PrivateKey, len(privateKey))
	copy(keyCopy, privateKey)
	return &KeyPair{
		PrivateKey:   keyCopy,
		PublicKey:     pub,
		PublicKeyHex: hex.EncodeToString(pub),
	}, nil
}

// Sign signs message bytes with an Ed25519 private key and returns
// the 64-byte signature.
func Sign(message []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("nobulex: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
	}
	sig := ed25519.Sign(privateKey, message)
	return sig, nil
}

// Verify checks an Ed25519 signature against a message and public key.
// Returns false for any error (malformed key, truncated signature, etc.).
func Verify(message, signature []byte, publicKey ed25519.PublicKey) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// SHA256Hex computes the SHA-256 hash of data and returns it as a
// lowercase hex string.
func SHA256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// SHA256String computes the SHA-256 hash of a UTF-8 string and returns
// it as a lowercase hex string.
func SHA256String(data string) string {
	return SHA256Hex([]byte(data))
}

// SHA256Object canonicalizes the object to JSON (RFC 8785) and then
// computes the SHA-256 hash, returning a lowercase hex string.
func SHA256Object(obj interface{}) (string, error) {
	canonical, err := CanonicalizeJSON(obj)
	if err != nil {
		return "", err
	}
	return SHA256String(canonical), nil
}

// CanonicalizeJSON produces a deterministic JSON serialization following
// JCS (RFC 8785). Object keys are sorted lexicographically at every
// nesting level. The output is identical regardless of the original
// key insertion order.
func CanonicalizeJSON(obj interface{}) (string, error) {
	sorted := sortKeys(obj)
	b, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("nobulex: failed to marshal canonical JSON: %w", err)
	}
	return string(b), nil
}

// sortKeys recursively sorts map keys and processes all nested structures.
func sortKeys(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := &orderedMap{keys: keys, values: make(map[string]interface{}, len(v))}
		for _, k := range keys {
			child := v[k]
			if child == nil {
				// Preserve explicit null values
				ordered.values[k] = nil
				ordered.hasNil = append(ordered.hasNil, k)
			} else {
				ordered.values[k] = sortKeys(child)
			}
		}
		return ordered
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = sortKeys(item)
		}
		return result
	default:
		return value
	}
}

// orderedMap preserves key order during JSON marshaling.
type orderedMap struct {
	keys   []string
	values map[string]interface{}
	hasNil []string // keys that have explicit nil values
}

func (o *orderedMap) MarshalJSON() ([]byte, error) {
	var buf strings.Builder
	buf.WriteByte('{')
	nilSet := make(map[string]bool, len(o.hasNil))
	for _, k := range o.hasNil {
		nilSet[k] = true
	}
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')
		v := o.values[k]
		if v == nil && nilSet[k] {
			buf.WriteString("null")
		} else if v == nil {
			buf.WriteString("null")
		} else {
			valBytes, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			buf.Write(valBytes)
		}
	}
	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

// ToHex encodes a byte slice to a lowercase hex string.
func ToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// FromHex decodes a hex string to a byte slice.
func FromHex(hexStr string) ([]byte, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("nobulex: invalid hex string: %w", err)
	}
	return b, nil
}

// GenerateNonce generates 32 cryptographically secure random bytes.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("nobulex: failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// ConstantTimeEqual compares two byte slices in constant time to
// prevent timing side-channel attacks.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Timestamp returns the current time as an ISO 8601 UTC string
// (e.g. "2025-01-15T12:00:00.000Z").
func Timestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// objectToMap converts any Go value to a map[string]interface{} via
// JSON round-trip. This is used internally to canonicalize arbitrary
// struct types.
func objectToMap(obj interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
