package stele

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Crypto tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("PrivateKey length = %d, want %d", len(kp.PrivateKey), ed25519.PrivateKeySize)
	}
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey length = %d, want %d", len(kp.PublicKey), ed25519.PublicKeySize)
	}
	if len(kp.PublicKeyHex) != 64 {
		t.Errorf("PublicKeyHex length = %d, want 64", len(kp.PublicKeyHex))
	}
}

func TestKeyPairFromPrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	restored, err := KeyPairFromPrivateKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("KeyPairFromPrivateKey() error: %v", err)
	}

	if restored.PublicKeyHex != kp.PublicKeyHex {
		t.Errorf("restored PublicKeyHex = %s, want %s", restored.PublicKeyHex, kp.PublicKeyHex)
	}
}

func TestKeyPairFromPrivateKeyInvalid(t *testing.T) {
	_, err := KeyPairFromPrivateKey([]byte("too short"))
	if err == nil {
		t.Error("KeyPairFromPrivateKey should fail with invalid key length")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	message := []byte("hello stele protocol")
	sig, err := Sign(message, kp.PrivateKey)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}

	if !Verify(message, sig, kp.PublicKey) {
		t.Error("Verify() returned false for valid signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	message := []byte("test message")
	sig, _ := Sign(message, kp1.PrivateKey)

	if Verify(message, sig, kp2.PublicKey) {
		t.Error("Verify() should return false for wrong public key")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	kp, _ := GenerateKeyPair()

	message := []byte("original message")
	sig, _ := Sign(message, kp.PrivateKey)

	tampered := []byte("tampered message")
	if Verify(tampered, sig, kp.PublicKey) {
		t.Error("Verify() should return false for tampered message")
	}
}

func TestVerifyRejectsInvalidInputs(t *testing.T) {
	if Verify([]byte("msg"), []byte("short"), []byte("short")) {
		t.Error("Verify() should return false for invalid key/signature lengths")
	}
}

func TestSHA256Hex(t *testing.T) {
	hash := SHA256Hex([]byte("hello"))
	// Known SHA-256 of "hello"
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash != expected {
		t.Errorf("SHA256Hex('hello') = %s, want %s", hash, expected)
	}
}

func TestSHA256String(t *testing.T) {
	hash := SHA256String("hello world")
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Errorf("SHA256String('hello world') = %s, want %s", hash, expected)
	}
}

func TestSHA256Object(t *testing.T) {
	// Two objects with same keys but different insertion order should hash the same
	obj1 := map[string]interface{}{"b": 2, "a": 1}
	obj2 := map[string]interface{}{"a": 1, "b": 2}

	h1, err := SHA256Object(obj1)
	if err != nil {
		t.Fatalf("SHA256Object(obj1) error: %v", err)
	}
	h2, err := SHA256Object(obj2)
	if err != nil {
		t.Fatalf("SHA256Object(obj2) error: %v", err)
	}

	if h1 != h2 {
		t.Errorf("SHA256Object should produce same hash for structurally equal objects: %s != %s", h1, h2)
	}
}

func TestCanonicalizeJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{
			name:     "sorted keys",
			input:    map[string]interface{}{"z": 1, "a": 2},
			expected: `{"a":2,"z":1}`,
		},
		{
			name: "nested objects",
			input: map[string]interface{}{
				"b": map[string]interface{}{"d": 4, "c": 3},
				"a": 1,
			},
			expected: `{"a":1,"b":{"c":3,"d":4}}`,
		},
		{
			name:     "arrays preserved",
			input:    map[string]interface{}{"items": []interface{}{3, 1, 2}},
			expected: `{"items":[3,1,2]}`,
		},
		{
			name:     "null values",
			input:    map[string]interface{}{"a": nil, "b": 1},
			expected: `{"a":null,"b":1}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalizeJSON(tt.input)
			if err != nil {
				t.Fatalf("CanonicalizeJSON() error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("CanonicalizeJSON() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestToHexFromHexRoundTrip(t *testing.T) {
	data := []byte{0xff, 0x00, 0xab, 0xcd}
	hexStr := ToHex(data)
	if hexStr != "ff00abcd" {
		t.Errorf("ToHex() = %s, want ff00abcd", hexStr)
	}

	decoded, err := FromHex(hexStr)
	if err != nil {
		t.Fatalf("FromHex() error: %v", err)
	}
	if !ConstantTimeEqual(data, decoded) {
		t.Error("FromHex round-trip did not produce original data")
	}
}

func TestFromHexInvalid(t *testing.T) {
	_, err := FromHex("xyz")
	if err == nil {
		t.Error("FromHex should fail with invalid hex")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}
	if len(nonce) != 32 {
		t.Errorf("nonce length = %d, want 32", len(nonce))
	}

	// Two nonces should be different
	nonce2, _ := GenerateNonce()
	if ConstantTimeEqual(nonce, nonce2) {
		t.Error("two nonces should not be equal")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	c := []byte{1, 2, 4}
	d := []byte{1, 2}

	if !ConstantTimeEqual(a, b) {
		t.Error("ConstantTimeEqual should return true for equal slices")
	}
	if ConstantTimeEqual(a, c) {
		t.Error("ConstantTimeEqual should return false for different slices")
	}
	if ConstantTimeEqual(a, d) {
		t.Error("ConstantTimeEqual should return false for different lengths")
	}
}

func TestTimestamp(t *testing.T) {
	ts := Timestamp()
	if !strings.HasSuffix(ts, "Z") {
		t.Errorf("Timestamp() = %s, expected UTC suffix 'Z'", ts)
	}
	if len(ts) != 24 {
		t.Errorf("Timestamp() length = %d, want 24 (2006-01-02T15:04:05.000Z)", len(ts))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CCL tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestParseCCLPermit(t *testing.T) {
	doc, err := Parse("permit read on '/data/**'")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
	if doc.Statements[0].Type != StatementPermit {
		t.Errorf("statement type = %s, want permit", doc.Statements[0].Type)
	}
	if doc.Statements[0].Action != "read" {
		t.Errorf("action = %s, want read", doc.Statements[0].Action)
	}
	if doc.Statements[0].Resource != "/data/**" {
		t.Errorf("resource = %s, want /data/**", doc.Statements[0].Resource)
	}
	if len(doc.Permits) != 1 {
		t.Errorf("permits count = %d, want 1", len(doc.Permits))
	}
}

func TestParseCCLDeny(t *testing.T) {
	doc, err := Parse("deny write on '/secret/**'")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(doc.Denies) != 1 {
		t.Fatalf("expected 1 deny, got %d", len(doc.Denies))
	}
	if doc.Denies[0].Type != StatementDeny {
		t.Errorf("type = %s, want deny", doc.Denies[0].Type)
	}
}

func TestParseCCLRequire(t *testing.T) {
	doc, err := Parse("require audit.log on '/system/**'")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(doc.Obligations) != 1 {
		t.Fatalf("expected 1 obligation, got %d", len(doc.Obligations))
	}
	if doc.Obligations[0].Action != "audit.log" {
		t.Errorf("action = %s, want audit.log", doc.Obligations[0].Action)
	}
}

func TestParseCCLLimit(t *testing.T) {
	doc, err := Parse("limit api.call 100 per 1 hours")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(doc.Limits) != 1 {
		t.Fatalf("expected 1 limit, got %d", len(doc.Limits))
	}
	limit := doc.Limits[0]
	if limit.Action != "api.call" {
		t.Errorf("action = %s, want api.call", limit.Action)
	}
	if limit.Limit != 100 {
		t.Errorf("limit = %f, want 100", limit.Limit)
	}
	if limit.Period != 3_600_000 {
		t.Errorf("period = %f, want 3600000 (ms)", limit.Period)
	}
}

func TestParseCCLWithCondition(t *testing.T) {
	doc, err := Parse("permit transfer on '/treasury/*' when amount <= 10000")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(doc.Permits) != 1 {
		t.Fatalf("expected 1 permit, got %d", len(doc.Permits))
	}
	stmt := doc.Permits[0]
	if stmt.Condition == nil {
		t.Fatal("expected condition, got nil")
	}
	if stmt.Condition.Field != "amount" {
		t.Errorf("condition field = %s, want amount", stmt.Condition.Field)
	}
	if stmt.Condition.Operator != "<=" {
		t.Errorf("condition operator = %s, want <=", stmt.Condition.Operator)
	}
	if stmt.Condition.Value != "10000" {
		t.Errorf("condition value = %s, want 10000", stmt.Condition.Value)
	}
}

func TestParseCCLMultipleStatements(t *testing.T) {
	source := `permit read on '/data/**'
deny write on '/data/secret'
require audit.log on '/data/**'
limit api.call 50 per 1 hours`

	doc, err := Parse(source)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(doc.Statements) != 4 {
		t.Errorf("expected 4 statements, got %d", len(doc.Statements))
	}
	if len(doc.Permits) != 1 {
		t.Errorf("expected 1 permit, got %d", len(doc.Permits))
	}
	if len(doc.Denies) != 1 {
		t.Errorf("expected 1 deny, got %d", len(doc.Denies))
	}
	if len(doc.Obligations) != 1 {
		t.Errorf("expected 1 obligation, got %d", len(doc.Obligations))
	}
	if len(doc.Limits) != 1 {
		t.Errorf("expected 1 limit, got %d", len(doc.Limits))
	}
}

func TestParseCCLComments(t *testing.T) {
	source := `# This is a comment
permit read on '/data/**'
# Another comment
deny write on '/secret/**'`

	doc, err := Parse(source)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(doc.Statements) != 2 {
		t.Errorf("expected 2 statements, got %d", len(doc.Statements))
	}
}

func TestParseCCLDottedAction(t *testing.T) {
	doc, err := Parse("permit file.read.all on '/data'")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if doc.Permits[0].Action != "file.read.all" {
		t.Errorf("action = %s, want file.read.all", doc.Permits[0].Action)
	}
}

func TestParseCCLWildcardAction(t *testing.T) {
	doc, err := Parse("permit file.* on '/data'")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if doc.Permits[0].Action != "file.*" {
		t.Errorf("action = %s, want file.*", doc.Permits[0].Action)
	}
}

func TestParseCCLDoubleWildcardAction(t *testing.T) {
	doc, err := Parse("permit ** on '/data'")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if doc.Permits[0].Action != "**" {
		t.Errorf("action = %s, want **", doc.Permits[0].Action)
	}
}

func TestParseCCLInvalid(t *testing.T) {
	_, err := Parse("invalid syntax here")
	if err == nil {
		t.Error("Parse should fail with invalid syntax")
	}
}

// ── Evaluation tests ────────────────────────────────────────────────

func TestEvaluateDefaultDeny(t *testing.T) {
	doc, _ := Parse("permit read on '/data/**'")
	result := Evaluate(doc, "write", "/data/file", nil)
	if result.Permitted {
		t.Error("expected default deny for unmatched action")
	}
	if result.Reason != "No matching rules found; default deny" {
		t.Errorf("unexpected reason: %s", result.Reason)
	}
}

func TestEvaluatePermit(t *testing.T) {
	doc, _ := Parse("permit read on '/data/**'")
	result := Evaluate(doc, "read", "/data/users", nil)
	if !result.Permitted {
		t.Error("expected permitted for matching read on /data/**")
	}
}

func TestEvaluateDenyWinsOverPermit(t *testing.T) {
	source := `permit read on '/data/**'
deny read on '/data/secret'`
	doc, _ := Parse(source)

	// /data/users should still be permitted
	result1 := Evaluate(doc, "read", "/data/users", nil)
	if !result1.Permitted {
		t.Error("expected /data/users to be permitted")
	}

	// /data/secret should be denied (deny wins at higher specificity)
	result2 := Evaluate(doc, "read", "/data/secret", nil)
	if result2.Permitted {
		t.Error("expected /data/secret to be denied")
	}
}

func TestEvaluateSpecificity(t *testing.T) {
	source := `deny read on '**'
permit read on '/data/public'`
	doc, _ := Parse(source)

	// /data/public has higher specificity and should be permitted
	result := Evaluate(doc, "read", "/data/public", nil)
	if !result.Permitted {
		t.Error("expected specific permit to win over broad deny")
	}
}

func TestEvaluateDenyWinsAtEqualSpecificity(t *testing.T) {
	source := `permit read on '/data/file'
deny read on '/data/file'`
	doc, _ := Parse(source)

	result := Evaluate(doc, "read", "/data/file", nil)
	if result.Permitted {
		t.Error("deny should win at equal specificity")
	}
}

func TestEvaluateWithCondition(t *testing.T) {
	doc, _ := Parse("permit transfer on '/treasury' when amount <= 10000")

	// Should permit when condition is met
	result1 := Evaluate(doc, "transfer", "/treasury", map[string]interface{}{
		"amount": float64(5000),
	})
	if !result1.Permitted {
		t.Error("expected permitted when amount <= 10000")
	}

	// Should deny when condition is not met
	result2 := Evaluate(doc, "transfer", "/treasury", map[string]interface{}{
		"amount": float64(20000),
	})
	if result2.Permitted {
		t.Error("expected denied when amount > 10000")
	}
}

func TestEvaluateConditionMissingField(t *testing.T) {
	doc, _ := Parse("permit transfer on '/treasury' when amount <= 10000")
	result := Evaluate(doc, "transfer", "/treasury", map[string]interface{}{})
	if result.Permitted {
		t.Error("expected denied when condition field is missing")
	}
}

// ── MatchAction tests ──────────────────────────────────────────────

func TestMatchAction(t *testing.T) {
	tests := []struct {
		pattern string
		action  string
		want    bool
	}{
		{"read", "read", true},
		{"read", "write", false},
		{"file.read", "file.read", true},
		{"file.read", "file.write", false},
		{"file.*", "file.read", true},
		{"file.*", "file.write", true},
		{"file.*", "file.read.all", false},
		{"**", "anything", true},
		{"**", "any.thing.here", true},
		{"file.**", "file.read", true},
		{"file.**", "file.read.all", true},
		{"file.**", "network.read", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.action, func(t *testing.T) {
			got := MatchAction(tt.pattern, tt.action)
			if got != tt.want {
				t.Errorf("MatchAction(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
			}
		})
	}
}

// ── MatchResource tests ────────────────────────────────────────────

func TestMatchResource(t *testing.T) {
	tests := []struct {
		pattern  string
		resource string
		want     bool
	}{
		{"/data", "/data", true},
		{"/data", "/other", false},
		{"/data/**", "/data/users", true},
		{"/data/**", "/data/users/123", true},
		{"/data/*", "/data/users", true},
		{"/data/*", "/data/users/123", false},
		{"**", "/anything/here", true},
		{"*", "/data", true},
		{"*", "/data/nested", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.resource, func(t *testing.T) {
			got := MatchResource(tt.pattern, tt.resource)
			if got != tt.want {
				t.Errorf("MatchResource(%q, %q) = %v, want %v", tt.pattern, tt.resource, got, tt.want)
			}
		})
	}
}

// ── Rate limit tests ───────────────────────────────────────────────

func TestCheckRateLimit(t *testing.T) {
	doc, _ := Parse("limit api.call 100 per 1 hours")
	now := time.Now().UnixMilli()

	// Under limit
	result := CheckRateLimit(doc, "api.call", 50, now-1000, now)
	if result.Exceeded {
		t.Error("expected not exceeded at 50/100")
	}
	if result.Remaining != 50 {
		t.Errorf("remaining = %d, want 50", result.Remaining)
	}

	// At limit
	result2 := CheckRateLimit(doc, "api.call", 100, now-1000, now)
	if !result2.Exceeded {
		t.Error("expected exceeded at 100/100")
	}
	if result2.Remaining != 0 {
		t.Errorf("remaining = %d, want 0", result2.Remaining)
	}

	// Over limit
	result3 := CheckRateLimit(doc, "api.call", 150, now-1000, now)
	if !result3.Exceeded {
		t.Error("expected exceeded at 150/100")
	}

	// No matching limit
	result4 := CheckRateLimit(doc, "other.action", 50, now-1000, now)
	if result4.Exceeded {
		t.Error("expected not exceeded for unmatched action")
	}
}

func TestCheckRateLimitPeriodExpired(t *testing.T) {
	doc, _ := Parse("limit api.call 100 per 1 hours")
	now := time.Now().UnixMilli()

	// Window started more than 1 hour ago
	result := CheckRateLimit(doc, "api.call", 150, now-4_000_000, now)
	if result.Exceeded {
		t.Error("expected not exceeded when period has expired")
	}
}

// ── Narrowing validation tests ─────────────────────────────────────

func TestValidateNarrowingValid(t *testing.T) {
	parent, _ := Parse("permit read on '/data/**'")
	child, _ := Parse("permit read on '/data/public'")

	result := ValidateNarrowing(parent, child)
	if !result.Valid {
		t.Errorf("expected valid narrowing, got violations: %v", result.Violations)
	}
}

func TestValidateNarrowingInvalid(t *testing.T) {
	parent, _ := Parse("permit read on '/data/**'")
	child, _ := Parse("permit write on '/data/**'")

	result := ValidateNarrowing(parent, child)
	if result.Valid {
		t.Error("expected narrowing violation: child permits write which parent doesn't")
	}
	if len(result.Violations) == 0 {
		t.Error("expected at least one violation")
	}
}

func TestValidateNarrowingDenyConflict(t *testing.T) {
	parent, _ := Parse("deny read on '/secret/**'")
	child, _ := Parse("permit read on '/secret/file'")

	result := ValidateNarrowing(parent, child)
	if result.Valid {
		t.Error("expected violation: child permits what parent denies")
	}
}

// ── Merge tests ────────────────────────────────────────────────────

func TestMerge(t *testing.T) {
	parent, _ := Parse("permit read on '/data/**'")
	child, _ := Parse("deny read on '/data/secret'")

	merged := Merge(parent, child)

	if len(merged.Permits) != 1 {
		t.Errorf("merged permits = %d, want 1", len(merged.Permits))
	}
	if len(merged.Denies) != 1 {
		t.Errorf("merged denies = %d, want 1", len(merged.Denies))
	}
}

func TestMergeLimits(t *testing.T) {
	parent, _ := Parse("limit api.call 100 per 1 hours")
	child, _ := Parse("limit api.call 50 per 1 hours")

	merged := Merge(parent, child)

	if len(merged.Limits) != 1 {
		t.Fatalf("merged limits = %d, want 1", len(merged.Limits))
	}
	if merged.Limits[0].Limit != 50 {
		t.Errorf("merged limit = %f, want 50 (more restrictive)", merged.Limits[0].Limit)
	}
}

// ── Serialize tests ────────────────────────────────────────────────

func TestSerialize(t *testing.T) {
	source := `permit read on '/data/**'
deny write on '/secret/**'
require audit.log on '/system/**'
limit api.call 100 per 1 hours`

	doc, err := Parse(source)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	serialized := Serialize(doc)

	// Re-parse the serialized output
	doc2, err := Parse(serialized)
	if err != nil {
		t.Fatalf("Parse(serialized) error: %v", err)
	}

	if len(doc2.Statements) != len(doc.Statements) {
		t.Errorf("re-parsed statement count = %d, want %d", len(doc2.Statements), len(doc.Statements))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Covenant tests
// ═══════════════════════════════════════════════════════════════════════════════

func makeTestKeyPairs(t *testing.T) (*KeyPair, *KeyPair) {
	t.Helper()
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	return kp1, kp2
}

func buildTestCovenant(t *testing.T) (*CovenantDocument, *KeyPair) {
	t.Helper()
	issuerKP, beneficiaryKP := makeTestKeyPairs(t)

	doc, err := BuildCovenant(&CovenantBuilderOptions{
		Issuer: Party{
			ID:        "alice",
			PublicKey: issuerKP.PublicKeyHex,
			Role:      "issuer",
		},
		Beneficiary: Party{
			ID:        "bob",
			PublicKey: beneficiaryKP.PublicKeyHex,
			Role:      "beneficiary",
		},
		Constraints: "permit read on '/data/**'",
		PrivateKey:  issuerKP.PrivateKey,
	})
	if err != nil {
		t.Fatalf("BuildCovenant() error: %v", err)
	}
	return doc, issuerKP
}

func TestBuildCovenantBasic(t *testing.T) {
	doc, _ := buildTestCovenant(t)

	if doc.ID == "" {
		t.Error("document ID should not be empty")
	}
	if doc.Version != ProtocolVersion {
		t.Errorf("version = %s, want %s", doc.Version, ProtocolVersion)
	}
	if doc.Issuer.ID != "alice" {
		t.Errorf("issuer.id = %s, want alice", doc.Issuer.ID)
	}
	if doc.Beneficiary.ID != "bob" {
		t.Errorf("beneficiary.id = %s, want bob", doc.Beneficiary.ID)
	}
	if doc.Nonce == "" {
		t.Error("nonce should not be empty")
	}
	if len(doc.Nonce) != 64 {
		t.Errorf("nonce hex length = %d, want 64", len(doc.Nonce))
	}
	if doc.Signature == "" {
		t.Error("signature should not be empty")
	}
	if doc.CreatedAt == "" {
		t.Error("createdAt should not be empty")
	}
}

func TestBuildCovenantWithOptionalFields(t *testing.T) {
	issuerKP, beneficiaryKP := makeTestKeyPairs(t)

	future := time.Now().Add(24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	past := time.Now().Add(-1 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")

	doc, err := BuildCovenant(&CovenantBuilderOptions{
		Issuer: Party{
			ID:        "alice",
			PublicKey: issuerKP.PublicKeyHex,
			Role:      "issuer",
		},
		Beneficiary: Party{
			ID:        "bob",
			PublicKey: beneficiaryKP.PublicKeyHex,
			Role:      "beneficiary",
		},
		Constraints: "permit read on '/data/**'",
		PrivateKey:  issuerKP.PrivateKey,
		ExpiresAt:   future,
		ActivatesAt: past,
		Metadata:    map[string]interface{}{"name": "test-covenant"},
		Chain: &ChainReference{
			ParentID: "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
			Relation: "delegates",
			Depth:    1,
		},
	})
	if err != nil {
		t.Fatalf("BuildCovenant() error: %v", err)
	}

	if doc.ExpiresAt != future {
		t.Errorf("expiresAt = %s, want %s", doc.ExpiresAt, future)
	}
	if doc.ActivatesAt != past {
		t.Errorf("activatesAt = %s, want %s", doc.ActivatesAt, past)
	}
	if doc.Metadata["name"] != "test-covenant" {
		t.Error("metadata not preserved")
	}
	if doc.Chain == nil {
		t.Error("chain should not be nil")
	}
}

func TestBuildCovenantValidation(t *testing.T) {
	kp, _ := GenerateKeyPair()

	tests := []struct {
		name string
		opts CovenantBuilderOptions
	}{
		{
			name: "missing issuer id",
			opts: CovenantBuilderOptions{
				Issuer:      Party{PublicKey: kp.PublicKeyHex, Role: "issuer"},
				Beneficiary: Party{ID: "bob", PublicKey: kp.PublicKeyHex, Role: "beneficiary"},
				Constraints: "permit read on '/data'",
				PrivateKey:  kp.PrivateKey,
			},
		},
		{
			name: "missing beneficiary",
			opts: CovenantBuilderOptions{
				Issuer:      Party{ID: "alice", PublicKey: kp.PublicKeyHex, Role: "issuer"},
				Beneficiary: Party{PublicKey: kp.PublicKeyHex, Role: "beneficiary"},
				Constraints: "permit read on '/data'",
				PrivateKey:  kp.PrivateKey,
			},
		},
		{
			name: "empty constraints",
			opts: CovenantBuilderOptions{
				Issuer:      Party{ID: "alice", PublicKey: kp.PublicKeyHex, Role: "issuer"},
				Beneficiary: Party{ID: "bob", PublicKey: kp.PublicKeyHex, Role: "beneficiary"},
				Constraints: "",
				PrivateKey:  kp.PrivateKey,
			},
		},
		{
			name: "wrong issuer role",
			opts: CovenantBuilderOptions{
				Issuer:      Party{ID: "alice", PublicKey: kp.PublicKeyHex, Role: "wrong"},
				Beneficiary: Party{ID: "bob", PublicKey: kp.PublicKeyHex, Role: "beneficiary"},
				Constraints: "permit read on '/data'",
				PrivateKey:  kp.PrivateKey,
			},
		},
		{
			name: "chain depth too high",
			opts: CovenantBuilderOptions{
				Issuer:      Party{ID: "alice", PublicKey: kp.PublicKeyHex, Role: "issuer"},
				Beneficiary: Party{ID: "bob", PublicKey: kp.PublicKeyHex, Role: "beneficiary"},
				Constraints: "permit read on '/data'",
				PrivateKey:  kp.PrivateKey,
				Chain:       &ChainReference{ParentID: "parent-id", Relation: "delegates", Depth: 100},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildCovenant(&tt.opts)
			if err == nil {
				t.Errorf("BuildCovenant should fail: %s", tt.name)
			}
		})
	}
}

func TestVerifyCovenantRoundTrip(t *testing.T) {
	doc, _ := buildTestCovenant(t)

	result, err := VerifyCovenant(doc)
	if err != nil {
		t.Fatalf("VerifyCovenant() error: %v", err)
	}
	if !result.Valid {
		for _, check := range result.Checks {
			if !check.Passed {
				t.Errorf("check %s failed: %s", check.Name, check.Message)
			}
		}
	}

	// Verify all 11 checks are present
	expectedChecks := []string{
		"id_match", "signature_valid", "not_expired", "active",
		"ccl_parses", "enforcement_valid", "proof_valid",
		"chain_depth", "document_size", "countersignatures", "nonce_present",
	}
	if len(result.Checks) != len(expectedChecks) {
		t.Errorf("expected %d checks, got %d", len(expectedChecks), len(result.Checks))
	}
	for i, expected := range expectedChecks {
		if i < len(result.Checks) && result.Checks[i].Name != expected {
			t.Errorf("check[%d] name = %s, want %s", i, result.Checks[i].Name, expected)
		}
	}
}

func TestVerifyCovenantTamperedID(t *testing.T) {
	doc, _ := buildTestCovenant(t)
	doc.ID = "0000000000000000000000000000000000000000000000000000000000000000"

	result, _ := VerifyCovenant(doc)
	if result.Valid {
		t.Error("verification should fail with tampered ID")
	}

	found := false
	for _, check := range result.Checks {
		if check.Name == "id_match" && !check.Passed {
			found = true
		}
	}
	if !found {
		t.Error("id_match check should have failed")
	}
}

func TestVerifyCovenantTamperedSignature(t *testing.T) {
	doc, _ := buildTestCovenant(t)
	// Flip a byte in the signature
	sigBytes, _ := FromHex(doc.Signature)
	sigBytes[0] ^= 0xFF
	doc.Signature = ToHex(sigBytes)

	result, _ := VerifyCovenant(doc)

	found := false
	for _, check := range result.Checks {
		if check.Name == "signature_valid" && !check.Passed {
			found = true
		}
	}
	if !found {
		t.Error("signature_valid check should have failed")
	}
}

func TestVerifyCovenantExpired(t *testing.T) {
	issuerKP, beneficiaryKP := makeTestKeyPairs(t)
	past := time.Now().Add(-1 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")

	doc, err := BuildCovenant(&CovenantBuilderOptions{
		Issuer:      Party{ID: "alice", PublicKey: issuerKP.PublicKeyHex, Role: "issuer"},
		Beneficiary: Party{ID: "bob", PublicKey: beneficiaryKP.PublicKeyHex, Role: "beneficiary"},
		Constraints: "permit read on '/data/**'",
		PrivateKey:  issuerKP.PrivateKey,
		ExpiresAt:   past,
	})
	if err != nil {
		t.Fatalf("BuildCovenant() error: %v", err)
	}

	result, _ := VerifyCovenant(doc)

	found := false
	for _, check := range result.Checks {
		if check.Name == "not_expired" && !check.Passed {
			found = true
		}
	}
	if !found {
		t.Error("not_expired check should have failed")
	}
}

func TestVerifyCovenantNotYetActive(t *testing.T) {
	issuerKP, beneficiaryKP := makeTestKeyPairs(t)
	future := time.Now().Add(24 * time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")

	doc, err := BuildCovenant(&CovenantBuilderOptions{
		Issuer:      Party{ID: "alice", PublicKey: issuerKP.PublicKeyHex, Role: "issuer"},
		Beneficiary: Party{ID: "bob", PublicKey: beneficiaryKP.PublicKeyHex, Role: "beneficiary"},
		Constraints: "permit read on '/data/**'",
		PrivateKey:  issuerKP.PrivateKey,
		ActivatesAt: future,
	})
	if err != nil {
		t.Fatalf("BuildCovenant() error: %v", err)
	}

	result, _ := VerifyCovenant(doc)

	found := false
	for _, check := range result.Checks {
		if check.Name == "active" && !check.Passed {
			found = true
		}
	}
	if !found {
		t.Error("active check should have failed for future activation")
	}
}

func TestVerifyCovenantBadNonce(t *testing.T) {
	doc, _ := buildTestCovenant(t)
	doc.Nonce = "bad-nonce"

	result, _ := VerifyCovenant(doc)

	found := false
	for _, check := range result.Checks {
		if check.Name == "nonce_present" && !check.Passed {
			found = true
		}
	}
	if !found {
		t.Error("nonce_present check should have failed")
	}
}

// ── Countersignature tests ─────────────────────────────────────────

func TestCountersignCovenant(t *testing.T) {
	doc, _ := buildTestCovenant(t)
	auditorKP, _ := GenerateKeyPair()

	signed, err := CountersignCovenant(doc, auditorKP, "auditor")
	if err != nil {
		t.Fatalf("CountersignCovenant() error: %v", err)
	}

	if len(signed.Countersignatures) != 1 {
		t.Fatalf("expected 1 countersignature, got %d", len(signed.Countersignatures))
	}

	cs := signed.Countersignatures[0]
	if cs.SignerPublicKey != auditorKP.PublicKeyHex {
		t.Error("countersigner public key mismatch")
	}
	if cs.SignerRole != "auditor" {
		t.Errorf("countersigner role = %s, want auditor", cs.SignerRole)
	}
	if cs.Signature == "" {
		t.Error("countersignature should not be empty")
	}

	// Original should not be mutated
	if len(doc.Countersignatures) != 0 {
		t.Error("original document should not be mutated")
	}

	// Verify the countersigned document
	result, _ := VerifyCovenant(signed)
	if !result.Valid {
		for _, check := range result.Checks {
			if !check.Passed {
				t.Errorf("check %s failed: %s", check.Name, check.Message)
			}
		}
	}
}

func TestMultipleCountersignatures(t *testing.T) {
	doc, _ := buildTestCovenant(t)
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	signed1, _ := CountersignCovenant(doc, kp1, "auditor")
	signed2, err := CountersignCovenant(signed1, kp2, "regulator")
	if err != nil {
		t.Fatalf("second CountersignCovenant() error: %v", err)
	}

	if len(signed2.Countersignatures) != 2 {
		t.Errorf("expected 2 countersignatures, got %d", len(signed2.Countersignatures))
	}

	result, _ := VerifyCovenant(signed2)
	if !result.Valid {
		for _, check := range result.Checks {
			if !check.Passed {
				t.Errorf("check %s failed: %s", check.Name, check.Message)
			}
		}
	}
}

// ── Serialization round-trip tests ─────────────────────────────────

func TestSerializeDeserializeRoundTrip(t *testing.T) {
	doc, _ := buildTestCovenant(t)

	serialized, err := SerializeCovenant(doc)
	if err != nil {
		t.Fatalf("SerializeCovenant() error: %v", err)
	}

	restored, err := DeserializeCovenant(serialized)
	if err != nil {
		t.Fatalf("DeserializeCovenant() error: %v", err)
	}

	if restored.ID != doc.ID {
		t.Errorf("restored ID = %s, want %s", restored.ID, doc.ID)
	}
	if restored.Version != doc.Version {
		t.Errorf("restored Version = %s, want %s", restored.Version, doc.Version)
	}
	if restored.Issuer.ID != doc.Issuer.ID {
		t.Errorf("restored Issuer.ID = %s, want %s", restored.Issuer.ID, doc.Issuer.ID)
	}
	if restored.Constraints != doc.Constraints {
		t.Errorf("restored Constraints = %s, want %s", restored.Constraints, doc.Constraints)
	}
	if restored.Nonce != doc.Nonce {
		t.Errorf("restored Nonce = %s, want %s", restored.Nonce, doc.Nonce)
	}
	if restored.Signature != doc.Signature {
		t.Errorf("restored Signature = %s, want %s", restored.Signature, doc.Signature)
	}

	// Verify the restored document
	result, _ := VerifyCovenant(restored)
	if !result.Valid {
		for _, check := range result.Checks {
			if !check.Passed {
				t.Errorf("check %s failed: %s", check.Name, check.Message)
			}
		}
	}
}

func TestDeserializeInvalidJSON(t *testing.T) {
	_, err := DeserializeCovenant("not json")
	if err == nil {
		t.Error("DeserializeCovenant should fail with invalid JSON")
	}
}

func TestDeserializeMissingFields(t *testing.T) {
	_, err := DeserializeCovenant(`{"id":"abc"}`)
	if err == nil {
		t.Error("DeserializeCovenant should fail with missing required fields")
	}
}

func TestDeserializeWrongVersion(t *testing.T) {
	doc := `{"id":"abc","version":"99.0","issuer":{"id":"a","publicKey":"b","role":"issuer"},"beneficiary":{"id":"c","publicKey":"d","role":"beneficiary"},"constraints":"permit read on '/data'","nonce":"abc","createdAt":"2025-01-01","signature":"sig"}`
	_, err := DeserializeCovenant(doc)
	if err == nil {
		t.Error("DeserializeCovenant should fail with wrong version")
	}
	if !strings.Contains(err.Error(), "unsupported protocol version") {
		t.Errorf("error should mention unsupported version, got: %v", err)
	}
}

// ── Chain narrowing tests ──────────────────────────────────────────

func TestValidateChainNarrowing(t *testing.T) {
	issuerKP, beneficiaryKP := makeTestKeyPairs(t)

	parent, _ := BuildCovenant(&CovenantBuilderOptions{
		Issuer:      Party{ID: "alice", PublicKey: issuerKP.PublicKeyHex, Role: "issuer"},
		Beneficiary: Party{ID: "bob", PublicKey: beneficiaryKP.PublicKeyHex, Role: "beneficiary"},
		Constraints: "permit read on '/data/**'",
		PrivateKey:  issuerKP.PrivateKey,
	})

	child, _ := BuildCovenant(&CovenantBuilderOptions{
		Issuer:      Party{ID: "alice", PublicKey: issuerKP.PublicKeyHex, Role: "issuer"},
		Beneficiary: Party{ID: "bob", PublicKey: beneficiaryKP.PublicKeyHex, Role: "beneficiary"},
		Constraints: "permit read on '/data/public'",
		PrivateKey:  issuerKP.PrivateKey,
		Chain: &ChainReference{
			ParentID: parent.ID,
			Relation: "restricts",
			Depth:    1,
		},
	})

	result, err := ValidateChainNarrowing(child, parent)
	if err != nil {
		t.Fatalf("ValidateChainNarrowing() error: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid chain narrowing")
	}
}

func TestValidateChainNarrowingViolation(t *testing.T) {
	issuerKP, beneficiaryKP := makeTestKeyPairs(t)

	parent, _ := BuildCovenant(&CovenantBuilderOptions{
		Issuer:      Party{ID: "alice", PublicKey: issuerKP.PublicKeyHex, Role: "issuer"},
		Beneficiary: Party{ID: "bob", PublicKey: beneficiaryKP.PublicKeyHex, Role: "beneficiary"},
		Constraints: "permit read on '/data/**'",
		PrivateKey:  issuerKP.PrivateKey,
	})

	child, _ := BuildCovenant(&CovenantBuilderOptions{
		Issuer:      Party{ID: "alice", PublicKey: issuerKP.PublicKeyHex, Role: "issuer"},
		Beneficiary: Party{ID: "bob", PublicKey: beneficiaryKP.PublicKeyHex, Role: "beneficiary"},
		Constraints: "permit write on '/data/**'",
		PrivateKey:  issuerKP.PrivateKey,
		Chain: &ChainReference{
			ParentID: parent.ID,
			Relation: "delegates",
			Depth:    1,
		},
	})

	result, err := ValidateChainNarrowing(child, parent)
	if err != nil {
		t.Fatalf("ValidateChainNarrowing() error: %v", err)
	}
	if result.Valid {
		t.Error("expected narrowing violation for broadened permissions")
	}
}

// ── Canonical form tests ───────────────────────────────────────────

func TestCanonicalFormExcludesFields(t *testing.T) {
	doc, _ := buildTestCovenant(t)

	canonical, err := CanonicalForm(doc)
	if err != nil {
		t.Fatalf("CanonicalForm() error: %v", err)
	}

	// Canonical form should not contain id, signature, or countersignatures
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(canonical), &parsed); err != nil {
		t.Fatalf("failed to parse canonical form: %v", err)
	}

	if _, ok := parsed["id"]; ok {
		t.Error("canonical form should not contain 'id'")
	}
	if _, ok := parsed["signature"]; ok {
		t.Error("canonical form should not contain 'signature'")
	}
	if _, ok := parsed["countersignatures"]; ok {
		t.Error("canonical form should not contain 'countersignatures'")
	}
}

func TestCanonicalFormDeterministic(t *testing.T) {
	doc, _ := buildTestCovenant(t)

	c1, err := CanonicalForm(doc)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := CanonicalForm(doc)
	if err != nil {
		t.Fatal(err)
	}

	if c1 != c2 {
		t.Error("CanonicalForm should produce identical output for the same document")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Identity tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestCreateIdentity(t *testing.T) {
	kp, _ := GenerateKeyPair()

	identity, err := CreateIdentity(&CreateIdentityOptions{
		OperatorKeyPair:    kp,
		OperatorIdentifier: "test-operator",
		Model: ModelAttestation{
			Provider: "anthropic",
			ModelID:  "claude-3",
		},
		Capabilities: []string{"write", "read"},
		Deployment: DeploymentContext{
			Runtime: RuntimeContainer,
		},
	})
	if err != nil {
		t.Fatalf("CreateIdentity() error: %v", err)
	}

	if identity.ID == "" {
		t.Error("identity ID should not be empty")
	}
	if identity.OperatorPublicKey != kp.PublicKeyHex {
		t.Error("operator public key mismatch")
	}
	if identity.OperatorIdentifier != "test-operator" {
		t.Error("operator identifier mismatch")
	}
	if identity.Version != 1 {
		t.Errorf("version = %d, want 1", identity.Version)
	}
	if len(identity.Lineage) != 1 {
		t.Errorf("lineage length = %d, want 1", len(identity.Lineage))
	}
	if identity.Lineage[0].ChangeType != "created" {
		t.Errorf("lineage[0].changeType = %s, want created", identity.Lineage[0].ChangeType)
	}
	if identity.Lineage[0].ReputationCarryForward != 1.0 {
		t.Errorf("lineage[0].reputationCarryForward = %f, want 1.0", identity.Lineage[0].ReputationCarryForward)
	}
	if identity.Signature == "" {
		t.Error("signature should not be empty")
	}
	if identity.CapabilityManifestHash == "" {
		t.Error("capability manifest hash should not be empty")
	}

	// Capabilities should be sorted
	if identity.Capabilities[0] != "read" || identity.Capabilities[1] != "write" {
		t.Error("capabilities should be sorted")
	}
}

func TestCreateIdentityValidation(t *testing.T) {
	_, err := CreateIdentity(nil)
	if err == nil {
		t.Error("CreateIdentity(nil) should fail")
	}

	kp, _ := GenerateKeyPair()

	_, err = CreateIdentity(&CreateIdentityOptions{
		OperatorKeyPair: kp,
		Model:           ModelAttestation{},
		Capabilities:    []string{},
		Deployment:      DeploymentContext{Runtime: RuntimeContainer},
	})
	if err == nil {
		t.Error("CreateIdentity with empty model should fail")
	}
}

func TestVerifyIdentity(t *testing.T) {
	kp, _ := GenerateKeyPair()

	identity, _ := CreateIdentity(&CreateIdentityOptions{
		OperatorKeyPair: kp,
		Model: ModelAttestation{
			Provider: "anthropic",
			ModelID:  "claude-3",
		},
		Capabilities: []string{"read"},
		Deployment:   DeploymentContext{Runtime: RuntimeContainer},
	})

	valid, err := VerifyIdentity(identity)
	if err != nil {
		t.Fatalf("VerifyIdentity() error: %v", err)
	}
	if !valid {
		t.Error("expected identity to be valid")
	}
}

func TestVerifyIdentityTampered(t *testing.T) {
	kp, _ := GenerateKeyPair()

	identity, _ := CreateIdentity(&CreateIdentityOptions{
		OperatorKeyPair: kp,
		Model: ModelAttestation{
			Provider: "anthropic",
			ModelID:  "claude-3",
		},
		Capabilities: []string{"read"},
		Deployment:   DeploymentContext{Runtime: RuntimeContainer},
	})

	// Tamper with the operator identifier
	identity.OperatorIdentifier = "tampered"

	valid, err := VerifyIdentity(identity)
	if err != nil {
		t.Fatalf("VerifyIdentity() error: %v", err)
	}
	if valid {
		t.Error("tampered identity should not be valid")
	}
}

func TestEvolveIdentity(t *testing.T) {
	kp, _ := GenerateKeyPair()

	identity, _ := CreateIdentity(&CreateIdentityOptions{
		OperatorKeyPair: kp,
		Model: ModelAttestation{
			Provider: "anthropic",
			ModelID:  "claude-3",
		},
		Capabilities: []string{"read"},
		Deployment:   DeploymentContext{Runtime: RuntimeContainer},
	})

	evolved, err := EvolveIdentity(identity, &EvolveIdentityOptions{
		OperatorKeyPair: kp,
		ChangeType:      "model_update",
		Description:     "Updated to claude-3.5",
		Model: &ModelAttestation{
			Provider:     "anthropic",
			ModelID:      "claude-3.5",
			ModelVersion: "3.5",
		},
	})
	if err != nil {
		t.Fatalf("EvolveIdentity() error: %v", err)
	}

	if evolved.Version != 2 {
		t.Errorf("version = %d, want 2", evolved.Version)
	}
	if len(evolved.Lineage) != 2 {
		t.Errorf("lineage length = %d, want 2", len(evolved.Lineage))
	}
	if evolved.Model.ModelID != "claude-3.5" {
		t.Errorf("model.modelId = %s, want claude-3.5", evolved.Model.ModelID)
	}
	if evolved.Lineage[1].ChangeType != "model_update" {
		t.Errorf("lineage[1].changeType = %s, want model_update", evolved.Lineage[1].ChangeType)
	}
	if evolved.Lineage[1].ParentHash == nil {
		t.Error("lineage[1].parentHash should not be nil")
	}
	if evolved.Lineage[1].ReputationCarryForward != DefaultEvolutionPolicy.ModelVersionChange {
		t.Errorf("carry-forward = %f, want %f", evolved.Lineage[1].ReputationCarryForward, DefaultEvolutionPolicy.ModelVersionChange)
	}
	if evolved.ID == identity.ID {
		t.Error("evolved identity should have different ID")
	}
	if evolved.Signature == "" {
		t.Error("evolved identity should be signed")
	}

	// Verify evolved identity
	valid, _ := VerifyIdentity(evolved)
	if !valid {
		t.Error("evolved identity should be valid")
	}
}

func TestComputeEffectiveCarryForward(t *testing.T) {
	kp, _ := GenerateKeyPair()

	identity, _ := CreateIdentity(&CreateIdentityOptions{
		OperatorKeyPair: kp,
		Model: ModelAttestation{
			Provider: "anthropic",
			ModelID:  "claude-3",
		},
		Capabilities: []string{"read"},
		Deployment:   DeploymentContext{Runtime: RuntimeContainer},
	})

	// Initially 1.0
	rate := ComputeEffectiveCarryForward(identity)
	if rate != 1.0 {
		t.Errorf("initial carry-forward = %f, want 1.0", rate)
	}

	// After model update (0.8)
	evolved, _ := EvolveIdentity(identity, &EvolveIdentityOptions{
		OperatorKeyPair: kp,
		ChangeType:      "model_update",
		Description:     "model update",
		Model: &ModelAttestation{
			Provider: "anthropic",
			ModelID:  "claude-3.5",
		},
	})

	rate = ComputeEffectiveCarryForward(evolved)
	expected := 1.0 * DefaultEvolutionPolicy.ModelVersionChange
	if rate != expected {
		t.Errorf("carry-forward after model update = %f, want %f", rate, expected)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Store tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestMemoryStorePutGet(t *testing.T) {
	store := NewMemoryStore()
	doc, _ := buildTestCovenant(t)

	err := store.Put(doc.ID, doc)
	if err != nil {
		t.Fatalf("Put() error: %v", err)
	}

	retrieved, err := store.Get(doc.ID)
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Get() returned nil for stored document")
	}
	if retrieved.ID != doc.ID {
		t.Errorf("retrieved ID = %s, want %s", retrieved.ID, doc.ID)
	}
}

func TestMemoryStoreGetNotFound(t *testing.T) {
	store := NewMemoryStore()

	retrieved, err := store.Get("nonexistent")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if retrieved != nil {
		t.Error("Get() should return nil for nonexistent document")
	}
}

func TestMemoryStoreHas(t *testing.T) {
	store := NewMemoryStore()
	doc, _ := buildTestCovenant(t)

	if store.Has(doc.ID) {
		t.Error("Has() should return false before Put()")
	}

	store.Put(doc.ID, doc)

	if !store.Has(doc.ID) {
		t.Error("Has() should return true after Put()")
	}
}

func TestMemoryStoreDelete(t *testing.T) {
	store := NewMemoryStore()
	doc, _ := buildTestCovenant(t)
	store.Put(doc.ID, doc)

	err := store.Delete(doc.ID)
	if err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	if store.Has(doc.ID) {
		t.Error("document should not exist after Delete()")
	}
}

func TestMemoryStoreDeleteNotFound(t *testing.T) {
	store := NewMemoryStore()
	err := store.Delete("nonexistent")
	if err == nil {
		t.Error("Delete() should fail for nonexistent document")
	}
}

func TestMemoryStoreList(t *testing.T) {
	store := NewMemoryStore()

	// Build two different covenants
	doc1, _ := buildTestCovenant(t)
	store.Put(doc1.ID, doc1)

	doc2, _ := buildTestCovenant(t) // different nonce -> different ID
	store.Put(doc2.ID, doc2)

	docs, err := store.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(docs) != 2 {
		t.Errorf("List() returned %d documents, want 2", len(docs))
	}
}

func TestMemoryStoreCount(t *testing.T) {
	store := NewMemoryStore()
	if store.Count() != 0 {
		t.Error("empty store should have count 0")
	}

	doc, _ := buildTestCovenant(t)
	store.Put(doc.ID, doc)

	if store.Count() != 1 {
		t.Errorf("store count = %d, want 1", store.Count())
	}
}

func TestMemoryStoreDefensiveCopy(t *testing.T) {
	store := NewMemoryStore()
	doc, _ := buildTestCovenant(t)
	store.Put(doc.ID, doc)

	// Mutate the original
	doc.Constraints = "mutated"

	// Retrieve should return original
	retrieved, _ := store.Get(doc.ID)
	if retrieved.Constraints == "mutated" {
		t.Error("store should defensively copy on Put()")
	}

	// Mutate the retrieved copy
	retrieved.Constraints = "also mutated"

	// Re-retrieve should be unaffected
	retrieved2, _ := store.Get(doc.ID)
	if retrieved2.Constraints == "also mutated" {
		t.Error("store should defensively copy on Get()")
	}
}

func TestMemoryStoreClear(t *testing.T) {
	store := NewMemoryStore()
	doc, _ := buildTestCovenant(t)
	store.Put(doc.ID, doc)

	store.Clear()

	if store.Count() != 0 {
		t.Error("store should be empty after Clear()")
	}
}

func TestMemoryStoreValidation(t *testing.T) {
	store := NewMemoryStore()

	err := store.Put("", &CovenantDocument{})
	if err == nil {
		t.Error("Put() with empty ID should fail")
	}

	err = store.Put("id", nil)
	if err == nil {
		t.Error("Put() with nil document should fail")
	}

	_, err = store.Get("")
	if err == nil {
		t.Error("Get() with empty ID should fail")
	}

	err = store.Delete("")
	if err == nil {
		t.Error("Delete() with empty ID should fail")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Integration tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestFullWorkflow(t *testing.T) {
	// 1. Generate key pairs
	issuerKP, _ := GenerateKeyPair()
	beneficiaryKP, _ := GenerateKeyPair()
	auditorKP, _ := GenerateKeyPair()

	// 2. Build a covenant
	doc, err := BuildCovenant(&CovenantBuilderOptions{
		Issuer: Party{
			ID:        "alice",
			PublicKey: issuerKP.PublicKeyHex,
			Role:      "issuer",
		},
		Beneficiary: Party{
			ID:        "bob",
			PublicKey: beneficiaryKP.PublicKeyHex,
			Role:      "beneficiary",
		},
		Constraints: "permit read on '/data/**'\ndeny read on '/data/secret'",
		PrivateKey:  issuerKP.PrivateKey,
	})
	if err != nil {
		t.Fatalf("BuildCovenant() error: %v", err)
	}

	// 3. Verify the covenant
	result, _ := VerifyCovenant(doc)
	if !result.Valid {
		t.Fatal("freshly built covenant should be valid")
	}

	// 4. Add a countersignature
	signed, err := CountersignCovenant(doc, auditorKP, "auditor")
	if err != nil {
		t.Fatalf("CountersignCovenant() error: %v", err)
	}

	// 5. Verify with countersignature
	result2, _ := VerifyCovenant(signed)
	if !result2.Valid {
		t.Fatal("countersigned covenant should be valid")
	}

	// 6. Store the covenant
	store := NewMemoryStore()
	if err := store.Put(signed.ID, signed); err != nil {
		t.Fatalf("store.Put() error: %v", err)
	}

	// 7. Retrieve and verify from store
	retrieved, _ := store.Get(signed.ID)
	result3, _ := VerifyCovenant(retrieved)
	if !result3.Valid {
		t.Fatal("retrieved covenant should be valid")
	}

	// 8. Evaluate CCL
	ccl, _ := Parse(doc.Constraints)
	evalResult := Evaluate(ccl, "read", "/data/users", nil)
	if !evalResult.Permitted {
		t.Error("read on /data/users should be permitted")
	}

	evalResult2 := Evaluate(ccl, "read", "/data/secret", nil)
	if evalResult2.Permitted {
		t.Error("read on /data/secret should be denied")
	}

	// 9. Serialize and deserialize
	serialized, _ := SerializeCovenant(signed)
	restored, _ := DeserializeCovenant(serialized)
	result4, _ := VerifyCovenant(restored)
	if !result4.Valid {
		t.Fatal("deserialized covenant should be valid")
	}
}

func TestCovenantChainWorkflow(t *testing.T) {
	issuerKP, _ := GenerateKeyPair()
	beneficiaryKP, _ := GenerateKeyPair()

	// Build parent covenant
	parent, err := BuildCovenant(&CovenantBuilderOptions{
		Issuer: Party{
			ID:        "alice",
			PublicKey: issuerKP.PublicKeyHex,
			Role:      "issuer",
		},
		Beneficiary: Party{
			ID:        "bob",
			PublicKey: beneficiaryKP.PublicKeyHex,
			Role:      "beneficiary",
		},
		Constraints: "permit read on '/data/**'\npermit write on '/data/**'",
		PrivateKey:  issuerKP.PrivateKey,
	})
	if err != nil {
		t.Fatalf("BuildCovenant(parent) error: %v", err)
	}

	// Build child covenant (narrows parent)
	child, err := BuildCovenant(&CovenantBuilderOptions{
		Issuer: Party{
			ID:        "alice",
			PublicKey: issuerKP.PublicKeyHex,
			Role:      "issuer",
		},
		Beneficiary: Party{
			ID:        "bob",
			PublicKey: beneficiaryKP.PublicKeyHex,
			Role:      "beneficiary",
		},
		Constraints: "permit read on '/data/public'",
		PrivateKey:  issuerKP.PrivateKey,
		Chain: &ChainReference{
			ParentID: parent.ID,
			Relation: "restricts",
			Depth:    1,
		},
	})
	if err != nil {
		t.Fatalf("BuildCovenant(child) error: %v", err)
	}

	// Validate narrowing
	result, err := ValidateChainNarrowing(child, parent)
	if err != nil {
		t.Fatalf("ValidateChainNarrowing() error: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid narrowing for restrictive child")
	}

	// Verify both
	parentResult, _ := VerifyCovenant(parent)
	if !parentResult.Valid {
		t.Error("parent should be valid")
	}
	childResult, _ := VerifyCovenant(child)
	if !childResult.Valid {
		t.Error("child should be valid")
	}
}

func TestIdentityCovenantWorkflow(t *testing.T) {
	kp, _ := GenerateKeyPair()

	// Create identity
	identity, err := CreateIdentity(&CreateIdentityOptions{
		OperatorKeyPair: kp,
		Model: ModelAttestation{
			Provider: "anthropic",
			ModelID:  "claude-3",
		},
		Capabilities: []string{"read", "write"},
		Deployment:   DeploymentContext{Runtime: RuntimeContainer},
	})
	if err != nil {
		t.Fatalf("CreateIdentity() error: %v", err)
	}

	// Use the identity's key to build a covenant
	beneficiaryKP, _ := GenerateKeyPair()
	doc, err := BuildCovenant(&CovenantBuilderOptions{
		Issuer: Party{
			ID:        identity.ID,
			PublicKey: identity.OperatorPublicKey,
			Role:      "issuer",
		},
		Beneficiary: Party{
			ID:        "beneficiary",
			PublicKey: beneficiaryKP.PublicKeyHex,
			Role:      "beneficiary",
		},
		Constraints: "permit read on '/data/**'",
		PrivateKey:  kp.PrivateKey,
	})
	if err != nil {
		t.Fatalf("BuildCovenant() error: %v", err)
	}

	result, _ := VerifyCovenant(doc)
	if !result.Valid {
		t.Error("covenant signed by identity key should be valid")
	}
}
