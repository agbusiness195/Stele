package grith

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Protocol constants.
const (
	ProtocolVersion = "1.0"
	MaxConstraints  = 256
	MaxChainDepth   = 16
	MaxDocumentSize = 1_048_576 // 1 MiB
)

// Party represents a participant in a covenant.
type Party struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
	Role      string `json:"role"`
}

// ChainReference links a child covenant to its parent in a delegation chain.
type ChainReference struct {
	ParentID string `json:"parentId"`
	Relation string `json:"relation"`
	Depth    int    `json:"depth"`
}

// Countersignature is a third-party signature over the canonical form.
type Countersignature struct {
	SignerPublicKey string `json:"signerPublicKey"`
	SignerRole      string `json:"signerRole"`
	Signature       string `json:"signature"`
	Timestamp       string `json:"timestamp"`
}

// CovenantDocument is a complete, signed covenant document.
type CovenantDocument struct {
	ID                string                 `json:"id"`
	Version           string                 `json:"version"`
	Issuer            Party                  `json:"issuer"`
	Beneficiary       Party                  `json:"beneficiary"`
	Constraints       string                 `json:"constraints"`
	Nonce             string                 `json:"nonce"`
	CreatedAt         string                 `json:"createdAt"`
	Signature         string                 `json:"signature"`
	Chain             *ChainReference        `json:"chain,omitempty"`
	ExpiresAt         string                 `json:"expiresAt,omitempty"`
	ActivatesAt       string                 `json:"activatesAt,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
	Countersignatures []Countersignature     `json:"countersignatures,omitempty"`
}

// VerificationCheck is the result of a single verification check.
type VerificationCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// VerificationResult is the complete result of verifying a covenant document.
type VerificationResult struct {
	Valid    bool                `json:"valid"`
	Checks  []VerificationCheck `json:"checks"`
	Document *CovenantDocument  `json:"document"`
}

// CovenantBuilderOptions are the options for building a new covenant document.
type CovenantBuilderOptions struct {
	Issuer      Party
	Beneficiary Party
	Constraints string
	PrivateKey  ed25519.PrivateKey
	Chain       *ChainReference
	ExpiresAt   string
	ActivatesAt string
	Metadata    map[string]interface{}
}

// CanonicalForm computes the canonical form of a covenant document.
// It strips the id, signature, and countersignatures fields, then
// produces deterministic JSON via JCS (RFC 8785) canonicalization.
func CanonicalForm(doc *CovenantDocument) (string, error) {
	// Convert to map, then strip the three mutable fields
	m, err := objectToMap(doc)
	if err != nil {
		return "", fmt.Errorf("grith: failed to convert document to map: %w", err)
	}

	delete(m, "id")
	delete(m, "signature")
	delete(m, "countersignatures")

	canonical, err := CanonicalizeJSON(m)
	if err != nil {
		return "", fmt.Errorf("grith: failed to canonicalize document: %w", err)
	}

	return canonical, nil
}

// ComputeID computes the SHA-256 document ID from the canonical form.
func ComputeID(doc *CovenantDocument) (string, error) {
	canonical, err := CanonicalForm(doc)
	if err != nil {
		return "", err
	}
	return SHA256String(canonical), nil
}

// BuildCovenant constructs, signs, and returns a new CovenantDocument.
// It validates all inputs, parses CCL constraints, generates a nonce,
// signs the canonical form, and computes the document ID.
func BuildCovenant(opts *CovenantBuilderOptions) (*CovenantDocument, error) {
	// Validate required inputs
	if opts.Issuer.ID == "" {
		return nil, fmt.Errorf("grith: issuer.id is required")
	}
	if opts.Issuer.PublicKey == "" {
		return nil, fmt.Errorf("grith: issuer.publicKey is required")
	}
	if opts.Issuer.Role != "issuer" {
		return nil, fmt.Errorf("grith: issuer.role must be 'issuer'")
	}
	if opts.Beneficiary.ID == "" {
		return nil, fmt.Errorf("grith: beneficiary.id is required")
	}
	if opts.Beneficiary.PublicKey == "" {
		return nil, fmt.Errorf("grith: beneficiary.publicKey is required")
	}
	if opts.Beneficiary.Role != "beneficiary" {
		return nil, fmt.Errorf("grith: beneficiary.role must be 'beneficiary'")
	}
	if strings.TrimSpace(opts.Constraints) == "" {
		return nil, fmt.Errorf("grith: constraints is required")
	}
	if len(opts.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("grith: privateKey must be %d bytes", ed25519.PrivateKeySize)
	}

	// Parse CCL to verify syntax and check constraint count
	parsedCCL, err := Parse(opts.Constraints)
	if err != nil {
		return nil, fmt.Errorf("grith: invalid CCL constraints: %w", err)
	}
	if len(parsedCCL.Statements) > MaxConstraints {
		return nil, fmt.Errorf("grith: constraints exceed maximum of %d statements (got %d)", MaxConstraints, len(parsedCCL.Statements))
	}

	// Validate chain reference
	if opts.Chain != nil {
		if opts.Chain.ParentID == "" {
			return nil, fmt.Errorf("grith: chain.parentId is required")
		}
		if opts.Chain.Relation == "" {
			return nil, fmt.Errorf("grith: chain.relation is required")
		}
		if opts.Chain.Depth < 1 {
			return nil, fmt.Errorf("grith: chain.depth must be a positive integer")
		}
		if opts.Chain.Depth > MaxChainDepth {
			return nil, fmt.Errorf("grith: chain.depth exceeds maximum of %d (got %d)", MaxChainDepth, opts.Chain.Depth)
		}
	}

	// Generate nonce and timestamp
	nonceBytes, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	nonce := ToHex(nonceBytes)
	createdAt := Timestamp()

	// Construct the document
	doc := &CovenantDocument{
		ID:          "",
		Version:     ProtocolVersion,
		Issuer:      opts.Issuer,
		Beneficiary: opts.Beneficiary,
		Constraints: opts.Constraints,
		Nonce:       nonce,
		CreatedAt:   createdAt,
		Signature:   "",
	}

	if opts.Chain != nil {
		doc.Chain = opts.Chain
	}
	if opts.ExpiresAt != "" {
		doc.ExpiresAt = opts.ExpiresAt
	}
	if opts.ActivatesAt != "" {
		doc.ActivatesAt = opts.ActivatesAt
	}
	if opts.Metadata != nil {
		doc.Metadata = opts.Metadata
	}

	// Compute canonical form, sign, and derive ID
	canonical, err := CanonicalForm(doc)
	if err != nil {
		return nil, err
	}

	sigBytes, err := Sign([]byte(canonical), opts.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("grith: failed to sign covenant: %w", err)
	}
	doc.Signature = ToHex(sigBytes)
	doc.ID = SHA256String(canonical)

	// Validate serialized size
	serialized, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("grith: failed to serialize covenant: %w", err)
	}
	if len(serialized) > MaxDocumentSize {
		return nil, fmt.Errorf("grith: serialized document exceeds maximum size of %d bytes", MaxDocumentSize)
	}

	return doc, nil
}

// VerifyCovenant runs all 11 specification checks on a covenant document.
//
// Checks:
//  1. id_match          - Document ID matches SHA-256 of canonical form
//  2. signature_valid   - Issuer's Ed25519 signature is valid
//  3. not_expired       - Current time is before expiresAt (if set)
//  4. active            - Current time is after activatesAt (if set)
//  5. ccl_parses        - Constraints parse as valid CCL
//  6. enforcement_valid - Enforcement config is valid (always passes without enforcement)
//  7. proof_valid       - Proof config is valid (always passes without proof)
//  8. chain_depth       - Chain depth does not exceed MaxChainDepth
//  9. document_size     - Serialized size does not exceed MaxDocumentSize
//  10. countersignatures - All countersignatures are valid
//  11. nonce_present     - Nonce is present and valid (64-char hex)
func VerifyCovenant(doc *CovenantDocument) (*VerificationResult, error) {
	var checks []VerificationCheck
	now := time.Now().UTC()

	// 1. ID match
	expectedID, err := ComputeID(doc)
	if err != nil {
		checks = append(checks, VerificationCheck{
			Name:    "id_match",
			Passed:  false,
			Message: fmt.Sprintf("Failed to compute ID: %v", err),
		})
	} else {
		idMatch := doc.ID == expectedID
		msg := "Document ID matches canonical hash"
		if !idMatch {
			msg = fmt.Sprintf("ID mismatch: expected %s, got %s", expectedID, doc.ID)
		}
		checks = append(checks, VerificationCheck{
			Name:    "id_match",
			Passed:  idMatch,
			Message: msg,
		})
	}

	// 2. Signature valid
	sigValid := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				sigValid = false
			}
		}()

		canonical, cerr := CanonicalForm(doc)
		if cerr != nil {
			return
		}
		sigBytes, herr := FromHex(doc.Signature)
		if herr != nil {
			return
		}
		pubKeyBytes, perr := FromHex(doc.Issuer.PublicKey)
		if perr != nil {
			return
		}
		sigValid = Verify([]byte(canonical), sigBytes, ed25519.PublicKey(pubKeyBytes))
	}()

	sigMsg := "Issuer signature is valid"
	if !sigValid {
		sigMsg = "Issuer signature verification failed"
	}
	checks = append(checks, VerificationCheck{
		Name:    "signature_valid",
		Passed:  sigValid,
		Message: sigMsg,
	})

	// 3. Not expired
	if doc.ExpiresAt != "" {
		expires, perr := time.Parse(time.RFC3339Nano, doc.ExpiresAt)
		if perr != nil {
			// Try other formats
			expires, perr = time.Parse("2006-01-02T15:04:05.000Z", doc.ExpiresAt)
		}
		notExpired := perr == nil && now.Before(expires)
		msg := "Document has not expired"
		if !notExpired {
			msg = fmt.Sprintf("Document expired at %s", doc.ExpiresAt)
		}
		checks = append(checks, VerificationCheck{
			Name:    "not_expired",
			Passed:  notExpired,
			Message: msg,
		})
	} else {
		checks = append(checks, VerificationCheck{
			Name:    "not_expired",
			Passed:  true,
			Message: "No expiry set",
		})
	}

	// 4. Active
	if doc.ActivatesAt != "" {
		activates, perr := time.Parse(time.RFC3339Nano, doc.ActivatesAt)
		if perr != nil {
			activates, perr = time.Parse("2006-01-02T15:04:05.000Z", doc.ActivatesAt)
		}
		isActive := perr == nil && !now.Before(activates)
		msg := "Document is active"
		if !isActive {
			msg = fmt.Sprintf("Document activates at %s", doc.ActivatesAt)
		}
		checks = append(checks, VerificationCheck{
			Name:    "active",
			Passed:  isActive,
			Message: msg,
		})
	} else {
		checks = append(checks, VerificationCheck{
			Name:    "active",
			Passed:  true,
			Message: "No activation time set",
		})
	}

	// 5. CCL parses
	cclParses := false
	cclMsg := ""
	parsed, cerr := Parse(doc.Constraints)
	if cerr != nil {
		cclMsg = fmt.Sprintf("CCL parse error: %v", cerr)
	} else if len(parsed.Statements) > MaxConstraints {
		cclMsg = fmt.Sprintf("Constraints exceed maximum of %d statements", MaxConstraints)
	} else {
		cclParses = true
		cclMsg = fmt.Sprintf("CCL parsed successfully (%d statement(s))", len(parsed.Statements))
	}
	checks = append(checks, VerificationCheck{
		Name:    "ccl_parses",
		Passed:  cclParses,
		Message: cclMsg,
	})

	// 6. Enforcement valid (always passes when no enforcement config)
	checks = append(checks, VerificationCheck{
		Name:    "enforcement_valid",
		Passed:  true,
		Message: "No enforcement config present",
	})

	// 7. Proof valid (always passes when no proof config)
	checks = append(checks, VerificationCheck{
		Name:    "proof_valid",
		Passed:  true,
		Message: "No proof config present",
	})

	// 8. Chain depth
	if doc.Chain != nil {
		depthOk := doc.Chain.Depth >= 1 && doc.Chain.Depth <= MaxChainDepth
		msg := fmt.Sprintf("Chain depth %d is within limit", doc.Chain.Depth)
		if !depthOk {
			msg = fmt.Sprintf("Chain depth %d exceeds maximum of %d", doc.Chain.Depth, MaxChainDepth)
		}
		checks = append(checks, VerificationCheck{
			Name:    "chain_depth",
			Passed:  depthOk,
			Message: msg,
		})
	} else {
		checks = append(checks, VerificationCheck{
			Name:    "chain_depth",
			Passed:  true,
			Message: "No chain reference present",
		})
	}

	// 9. Document size
	serialized, serErr := json.Marshal(doc)
	sizeOk := serErr == nil && len(serialized) <= MaxDocumentSize
	sizeMsg := fmt.Sprintf("Document size %d bytes is within limit", len(serialized))
	if !sizeOk {
		sizeMsg = fmt.Sprintf("Document size %d bytes exceeds maximum of %d", len(serialized), MaxDocumentSize)
	}
	checks = append(checks, VerificationCheck{
		Name:    "document_size",
		Passed:  sizeOk,
		Message: sizeMsg,
	})

	// 10. Countersignatures
	if len(doc.Countersignatures) > 0 {
		allCSValid := true
		var failedSigners []string

		for _, cs := range doc.Countersignatures {
			csValid := false
			func() {
				defer func() {
					if r := recover(); r != nil {
						csValid = false
					}
				}()

				canonical, cerr := CanonicalForm(doc)
				if cerr != nil {
					return
				}
				csSigBytes, herr := FromHex(cs.Signature)
				if herr != nil {
					return
				}
				csPubKeyBytes, perr := FromHex(cs.SignerPublicKey)
				if perr != nil {
					return
				}
				csValid = Verify([]byte(canonical), csSigBytes, ed25519.PublicKey(csPubKeyBytes))
			}()

			if !csValid {
				allCSValid = false
				truncKey := cs.SignerPublicKey
				if len(truncKey) > 16 {
					truncKey = truncKey[:16] + "..."
				}
				failedSigners = append(failedSigners, truncKey)
			}
		}

		csMsg := fmt.Sprintf("All %d countersignature(s) are valid", len(doc.Countersignatures))
		if !allCSValid {
			csMsg = fmt.Sprintf("Invalid countersignature(s) from: %s", strings.Join(failedSigners, ", "))
		}
		checks = append(checks, VerificationCheck{
			Name:    "countersignatures",
			Passed:  allCSValid,
			Message: csMsg,
		})
	} else {
		checks = append(checks, VerificationCheck{
			Name:    "countersignatures",
			Passed:  true,
			Message: "No countersignatures present",
		})
	}

	// 11. Nonce present
	nonceHexRegex := regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	nonceOk := nonceHexRegex.MatchString(doc.Nonce)
	nonceMsg := "Nonce is present and valid (64-char hex)"
	if !nonceOk {
		if doc.Nonce == "" {
			nonceMsg = "Nonce is missing or empty"
		} else {
			nonceMsg = fmt.Sprintf("Nonce is malformed: expected 64-char hex string, got %d chars", len(doc.Nonce))
		}
	}
	checks = append(checks, VerificationCheck{
		Name:    "nonce_present",
		Passed:  nonceOk,
		Message: nonceMsg,
	})

	// Aggregate
	valid := true
	for _, c := range checks {
		if !c.Passed {
			valid = false
			break
		}
	}

	return &VerificationResult{
		Valid:    valid,
		Checks:  checks,
		Document: doc,
	}, nil
}

// CountersignCovenant adds a countersignature from a third party.
// The countersigner signs the canonical form (which excludes existing
// countersignatures), so each countersignature is independent.
// Returns a new document; the original is not mutated.
func CountersignCovenant(doc *CovenantDocument, kp *KeyPair, role string) (*CovenantDocument, error) {
	canonical, err := CanonicalForm(doc)
	if err != nil {
		return nil, err
	}

	sigBytes, err := Sign([]byte(canonical), kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("grith: failed to countersign: %w", err)
	}

	cs := Countersignature{
		SignerPublicKey: kp.PublicKeyHex,
		SignerRole:      role,
		Signature:       ToHex(sigBytes),
		Timestamp:       Timestamp(),
	}

	// Create a copy of the document with the new countersignature appended
	newDoc := *doc
	newDoc.Countersignatures = make([]Countersignature, len(doc.Countersignatures)+1)
	copy(newDoc.Countersignatures, doc.Countersignatures)
	newDoc.Countersignatures[len(doc.Countersignatures)] = cs

	return &newDoc, nil
}

// SerializeCovenant serializes a covenant document to a JSON string.
func SerializeCovenant(doc *CovenantDocument) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("grith: failed to serialize covenant: %w", err)
	}
	return string(b), nil
}

// DeserializeCovenant parses a JSON string into a CovenantDocument.
// It performs structural validation to ensure all required fields are present.
func DeserializeCovenant(jsonStr string) (*CovenantDocument, error) {
	var doc CovenantDocument
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		return nil, fmt.Errorf("grith: invalid JSON: %w", err)
	}

	// Validate required fields
	if doc.ID == "" {
		return nil, fmt.Errorf("grith: missing required field: id")
	}
	if doc.Version == "" {
		return nil, fmt.Errorf("grith: missing required field: version")
	}
	if doc.Version != ProtocolVersion {
		return nil, fmt.Errorf("grith: unsupported protocol version: %s (expected %s)", doc.Version, ProtocolVersion)
	}
	if doc.Issuer.ID == "" || doc.Issuer.PublicKey == "" || doc.Issuer.Role != "issuer" {
		return nil, fmt.Errorf("grith: invalid issuer: must have id, publicKey, and role='issuer'")
	}
	if doc.Beneficiary.ID == "" || doc.Beneficiary.PublicKey == "" || doc.Beneficiary.Role != "beneficiary" {
		return nil, fmt.Errorf("grith: invalid beneficiary: must have id, publicKey, and role='beneficiary'")
	}
	if doc.Constraints == "" {
		return nil, fmt.Errorf("grith: missing required field: constraints")
	}
	if doc.Nonce == "" {
		return nil, fmt.Errorf("grith: missing required field: nonce")
	}
	if doc.CreatedAt == "" {
		return nil, fmt.Errorf("grith: missing required field: createdAt")
	}
	if doc.Signature == "" {
		return nil, fmt.Errorf("grith: missing required field: signature")
	}

	// Validate chain if present
	if doc.Chain != nil {
		if doc.Chain.ParentID == "" {
			return nil, fmt.Errorf("grith: invalid chain.parentId: must be a string")
		}
		if doc.Chain.Relation == "" {
			return nil, fmt.Errorf("grith: invalid chain.relation: must be a string")
		}
	}

	// Validate document size
	if len(jsonStr) > MaxDocumentSize {
		return nil, fmt.Errorf("grith: document size %d bytes exceeds maximum of %d bytes", len(jsonStr), MaxDocumentSize)
	}

	return &doc, nil
}

// ValidateChainNarrowing validates that a child covenant only narrows
// the constraints of its parent.
func ValidateChainNarrowing(child, parent *CovenantDocument) (*NarrowingResult, error) {
	parentCCL, err := Parse(parent.Constraints)
	if err != nil {
		return nil, fmt.Errorf("grith: failed to parse parent constraints: %w", err)
	}
	childCCL, err := Parse(child.Constraints)
	if err != nil {
		return nil, fmt.Errorf("grith: failed to parse child constraints: %w", err)
	}
	return ValidateNarrowing(parentCCL, childCCL), nil
}

// nonceHexValid checks if a nonce is a valid 64-character hex string.
func nonceHexValid(nonce string) bool {
	if len(nonce) != 64 {
		return false
	}
	_, err := hex.DecodeString(nonce)
	return err == nil
}
