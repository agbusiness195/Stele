package kervyx

import (
	"crypto/ed25519"
	"fmt"
	"sort"
)

// RuntimeType describes the execution environment for an agent.
type RuntimeType string

const (
	RuntimeWasm        RuntimeType = "wasm"
	RuntimeContainer   RuntimeType = "container"
	RuntimeTEE         RuntimeType = "tee"
	RuntimeFirecracker RuntimeType = "firecracker"
	RuntimeProcess     RuntimeType = "process"
	RuntimeBrowser     RuntimeType = "browser"
)

// ModelAttestation describes the AI model powering an agent.
type ModelAttestation struct {
	Provider        string `json:"provider"`
	ModelID         string `json:"modelId"`
	ModelVersion    string `json:"modelVersion,omitempty"`
	AttestationHash string `json:"attestationHash,omitempty"`
	AttestationType string `json:"attestationType,omitempty"`
}

// DeploymentContext describes where and how an agent is deployed.
type DeploymentContext struct {
	Runtime        RuntimeType `json:"runtime"`
	TEEAttestation string      `json:"teeAttestation,omitempty"`
	Region         string      `json:"region,omitempty"`
	Provider       string      `json:"provider,omitempty"`
}

// LineageEntry is a single entry in an agent's identity evolution chain.
type LineageEntry struct {
	IdentityHash           string  `json:"identityHash"`
	ChangeType             string  `json:"changeType"`
	Description            string  `json:"description"`
	Timestamp              string  `json:"timestamp"`
	ParentHash             *string `json:"parentHash"`
	Signature              string  `json:"signature"`
	ReputationCarryForward float64 `json:"reputationCarryForward"`
}

// AgentIdentity is a complete, signed AI agent identity.
type AgentIdentity struct {
	ID                     string            `json:"id"`
	OperatorPublicKey      string            `json:"operatorPublicKey"`
	OperatorIdentifier     string            `json:"operatorIdentifier,omitempty"`
	Model                  ModelAttestation  `json:"model"`
	Capabilities           []string          `json:"capabilities"`
	CapabilityManifestHash string            `json:"capabilityManifestHash"`
	Deployment             DeploymentContext `json:"deployment"`
	Lineage                []LineageEntry    `json:"lineage"`
	Version                int               `json:"version"`
	CreatedAt              string            `json:"createdAt"`
	UpdatedAt              string            `json:"updatedAt"`
	Signature              string            `json:"signature"`
}

// EvolutionPolicy defines reputation carry-forward rates for each
// type of identity evolution.
type EvolutionPolicy struct {
	MinorUpdate        float64
	ModelVersionChange float64
	ModelFamilyChange  float64
	OperatorTransfer   float64
	CapabilityExpansion float64
	CapabilityReduction float64
	FullRebuild        float64
}

// DefaultEvolutionPolicy is the default reputation carry-forward policy.
var DefaultEvolutionPolicy = EvolutionPolicy{
	MinorUpdate:        0.95,
	ModelVersionChange: 0.80,
	ModelFamilyChange:  0.20,
	OperatorTransfer:   0.50,
	CapabilityExpansion: 0.90,
	CapabilityReduction: 1.00,
	FullRebuild:        0.00,
}

// CreateIdentityOptions are the options for creating a new agent identity.
type CreateIdentityOptions struct {
	OperatorKeyPair    *KeyPair
	OperatorIdentifier string
	Model              ModelAttestation
	Capabilities       []string
	Deployment         DeploymentContext
}

// EvolveIdentityOptions are the options for evolving an existing identity.
type EvolveIdentityOptions struct {
	OperatorKeyPair        *KeyPair
	ChangeType             string
	Description            string
	Model                  *ModelAttestation
	Capabilities           []string
	Deployment             *DeploymentContext
	OperatorPublicKey      string
	OperatorIdentifier     string
	ReputationCarryForward *float64
}

// ComputeCapabilityManifestHash computes a canonical hash of a sorted
// capabilities list.
func ComputeCapabilityManifestHash(capabilities []string) string {
	sorted := make([]string, len(capabilities))
	copy(sorted, capabilities)
	sort.Strings(sorted)
	canonical, _ := CanonicalizeJSON(sorted)
	return SHA256String(canonical)
}

// computeIdentityHash computes the composite identity hash from the
// identity-defining fields.
func computeIdentityHash(identity *AgentIdentity) (string, error) {
	composite := map[string]interface{}{
		"operatorPublicKey":      identity.OperatorPublicKey,
		"model":                  identity.Model,
		"capabilityManifestHash": identity.CapabilityManifestHash,
		"deployment":             identity.Deployment,
		"lineage":                identity.Lineage,
	}
	return SHA256Object(composite)
}

// identitySigningPayload builds the canonical string representation of
// an identity for signing. Excludes the "signature" field.
func identitySigningPayload(identity *AgentIdentity) (string, error) {
	m, err := objectToMap(identity)
	if err != nil {
		return "", err
	}
	delete(m, "signature")
	return CanonicalizeJSON(m)
}

// lineageSigningPayload builds the canonical string for a lineage entry
// before its signature is set.
func lineageSigningPayload(entry *LineageEntry) (string, error) {
	m, err := objectToMap(entry)
	if err != nil {
		return "", err
	}
	delete(m, "signature")
	return CanonicalizeJSON(m)
}

// CreateIdentity creates a brand-new agent identity. It computes the
// capability manifest hash and composite identity hash, initializes a
// single lineage entry of type "created", and signs the whole identity.
func CreateIdentity(opts *CreateIdentityOptions) (*AgentIdentity, error) {
	if opts == nil {
		return nil, fmt.Errorf("kervyx: createIdentity requires options")
	}
	if opts.OperatorKeyPair == nil {
		return nil, fmt.Errorf("kervyx: operatorKeyPair is required")
	}
	if opts.Model.Provider == "" || opts.Model.ModelID == "" {
		return nil, fmt.Errorf("kervyx: model.provider and model.modelId are required")
	}
	if opts.Capabilities == nil {
		return nil, fmt.Errorf("kervyx: capabilities array is required")
	}

	now := Timestamp()

	// Sort capabilities
	sortedCaps := make([]string, len(opts.Capabilities))
	copy(sortedCaps, opts.Capabilities)
	sort.Strings(sortedCaps)

	capabilityManifestHash := ComputeCapabilityManifestHash(sortedCaps)

	identity := &AgentIdentity{
		ID:                     "",
		OperatorPublicKey:      opts.OperatorKeyPair.PublicKeyHex,
		OperatorIdentifier:     opts.OperatorIdentifier,
		Model:                  opts.Model,
		Capabilities:           sortedCaps,
		CapabilityManifestHash: capabilityManifestHash,
		Deployment:             opts.Deployment,
		Lineage:                nil,
		Version:                1,
		CreatedAt:              now,
		UpdatedAt:              now,
		Signature:              "",
	}

	// Compute identity hash
	idHash, err := computeIdentityHash(identity)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to compute identity hash: %w", err)
	}

	// Create initial lineage entry
	lineageEntry := &LineageEntry{
		IdentityHash:           idHash,
		ChangeType:             "created",
		Description:            "Identity created",
		Timestamp:              now,
		ParentHash:             nil,
		Signature:              "",
		ReputationCarryForward: 1.0,
	}

	// Sign lineage entry
	lineagePayload, err := lineageSigningPayload(lineageEntry)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to compute lineage signing payload: %w", err)
	}
	lineageSig, err := Sign([]byte(lineagePayload), opts.OperatorKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to sign lineage entry: %w", err)
	}
	lineageEntry.Signature = ToHex(lineageSig)

	identity.Lineage = []LineageEntry{*lineageEntry}

	// Recompute identity hash with lineage
	idHash, err = computeIdentityHash(identity)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to recompute identity hash: %w", err)
	}
	identity.ID = idHash

	// Sign the identity
	payload, err := identitySigningPayload(identity)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to compute identity signing payload: %w", err)
	}
	sig, err := Sign([]byte(payload), opts.OperatorKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to sign identity: %w", err)
	}
	identity.Signature = ToHex(sig)

	return identity, nil
}

// EvolveIdentity creates a new version of an existing identity.
// The new identity is linked to the previous one via the lineage chain.
func EvolveIdentity(current *AgentIdentity, opts *EvolveIdentityOptions) (*AgentIdentity, error) {
	if current == nil {
		return nil, fmt.Errorf("kervyx: current identity is required")
	}
	if opts == nil {
		return nil, fmt.Errorf("kervyx: evolve options are required")
	}
	if opts.OperatorKeyPair == nil {
		return nil, fmt.Errorf("kervyx: operatorKeyPair is required")
	}
	if opts.ChangeType == "" {
		return nil, fmt.Errorf("kervyx: changeType is required")
	}
	if opts.Description == "" {
		return nil, fmt.Errorf("kervyx: description is required")
	}

	now := Timestamp()

	// Start from current values
	newIdentity := &AgentIdentity{
		ID:                     "",
		OperatorPublicKey:      current.OperatorPublicKey,
		OperatorIdentifier:     current.OperatorIdentifier,
		Model:                  current.Model,
		Capabilities:           current.Capabilities,
		CapabilityManifestHash: current.CapabilityManifestHash,
		Deployment:             current.Deployment,
		Lineage:                make([]LineageEntry, len(current.Lineage)),
		Version:                current.Version + 1,
		CreatedAt:              current.CreatedAt,
		UpdatedAt:              now,
		Signature:              "",
	}
	copy(newIdentity.Lineage, current.Lineage)

	// Apply updates
	if opts.Model != nil {
		newIdentity.Model = *opts.Model
	}
	if opts.Capabilities != nil {
		sorted := make([]string, len(opts.Capabilities))
		copy(sorted, opts.Capabilities)
		sort.Strings(sorted)
		newIdentity.Capabilities = sorted
		newIdentity.CapabilityManifestHash = ComputeCapabilityManifestHash(sorted)
	}
	if opts.Deployment != nil {
		newIdentity.Deployment = *opts.Deployment
	}
	if opts.OperatorPublicKey != "" {
		newIdentity.OperatorPublicKey = opts.OperatorPublicKey
	}
	if opts.OperatorIdentifier != "" {
		newIdentity.OperatorIdentifier = opts.OperatorIdentifier
	}

	// Determine carry-forward rate
	carryForward := getCarryForwardRate(opts.ChangeType, DefaultEvolutionPolicy)
	if opts.ReputationCarryForward != nil {
		carryForward = *opts.ReputationCarryForward
	}

	// Compute new identity hash
	idHash, err := computeIdentityHash(newIdentity)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to compute identity hash: %w", err)
	}

	// Get parent hash from the last lineage entry
	var parentHash *string
	if len(current.Lineage) > 0 {
		lastEntry := current.Lineage[len(current.Lineage)-1]
		parentHash = &lastEntry.IdentityHash
	}

	// Create new lineage entry
	lineageEntry := &LineageEntry{
		IdentityHash:           idHash,
		ChangeType:             opts.ChangeType,
		Description:            opts.Description,
		Timestamp:              now,
		ParentHash:             parentHash,
		Signature:              "",
		ReputationCarryForward: carryForward,
	}

	// Sign lineage entry
	lineagePayload, err := lineageSigningPayload(lineageEntry)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to compute lineage signing payload: %w", err)
	}
	lineageSig, err := Sign([]byte(lineagePayload), opts.OperatorKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to sign lineage entry: %w", err)
	}
	lineageEntry.Signature = ToHex(lineageSig)

	newIdentity.Lineage = append(newIdentity.Lineage, *lineageEntry)

	// Recompute identity hash with updated lineage
	idHash, err = computeIdentityHash(newIdentity)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to recompute identity hash: %w", err)
	}
	newIdentity.ID = idHash

	// Sign the identity
	payload, err := identitySigningPayload(newIdentity)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to compute identity signing payload: %w", err)
	}
	sig, err := Sign([]byte(payload), opts.OperatorKeyPair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("kervyx: failed to sign identity: %w", err)
	}
	newIdentity.Signature = ToHex(sig)

	return newIdentity, nil
}

// VerifyIdentity verifies an agent identity by checking the signature
// over the canonical form.
func VerifyIdentity(identity *AgentIdentity) (bool, error) {
	if identity == nil {
		return false, fmt.Errorf("kervyx: identity is required")
	}

	// Verify the identity signature
	payload, err := identitySigningPayload(identity)
	if err != nil {
		return false, fmt.Errorf("kervyx: failed to compute signing payload: %w", err)
	}

	sigBytes, err := FromHex(identity.Signature)
	if err != nil {
		return false, nil
	}

	pubKeyBytes, err := FromHex(identity.OperatorPublicKey)
	if err != nil {
		return false, nil
	}

	return Verify([]byte(payload), sigBytes, ed25519.PublicKey(pubKeyBytes)), nil
}

// ComputeEffectiveCarryForward computes the multiplicative carry-forward
// rate across an identity's entire lineage chain.
func ComputeEffectiveCarryForward(identity *AgentIdentity) float64 {
	rate := 1.0
	for _, entry := range identity.Lineage {
		rate *= entry.ReputationCarryForward
	}
	return rate
}

// getCarryForwardRate returns the default carry-forward rate for a
// given change type using the evolution policy.
func getCarryForwardRate(changeType string, policy EvolutionPolicy) float64 {
	switch changeType {
	case "created":
		return 1.0
	case "model_update":
		return policy.ModelVersionChange
	case "capability_change":
		return policy.CapabilityExpansion
	case "operator_transfer":
		return policy.OperatorTransfer
	case "fork":
		return policy.ModelFamilyChange
	case "merge":
		return policy.MinorUpdate
	default:
		return policy.MinorUpdate
	}
}
