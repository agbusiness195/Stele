# Kervyx Covenant Protocol Specification

| Field   | Value                  |
|---------|------------------------|
| Version | 1.0.0                 |
| Status  | Draft                  |
| Date    | 2026-02-17             |
| License | See LICENSE             |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Covenant Document Schema](#3-covenant-document-schema)
4. [Covenant Constraint Language (CCL) Grammar](#4-covenant-constraint-language-ccl-grammar)
5. [CCL Evaluation Semantics](#5-ccl-evaluation-semantics)
6. [Canonical Form Algorithm](#6-canonical-form-algorithm)
7. [Document ID Computation](#7-document-id-computation)
8. [Signing and Verification](#8-signing-and-verification)
9. [Verification Algorithm](#9-verification-algorithm)
10. [Chain Composition](#10-chain-composition)
11. [Countersignature Protocol](#11-countersignature-protocol)
12. [Protocol Constants](#12-protocol-constants)
13. [Cryptographic Requirements](#13-cryptographic-requirements)
14. [Appendix A: Test Vectors](#appendix-a-test-vectors)
15. [Appendix B: JSON Schema Definitions](#appendix-b-json-schema-definitions)

---

## 1. Introduction

This document is the formal, implementation-independent specification of the Kervyx Covenant Protocol version 1.0. It defines the data structures, algorithms, and invariants that any conformant implementation MUST satisfy. The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

The Kervyx Covenant Protocol provides cryptographic behavioral commitments for autonomous AI agents. A covenant is a signed, content-addressed document in which a party declares behavioral constraints. Covenants are immutable once signed, independently verifiable without trusted intermediaries, and composable through delegation chains with monotonic constraint narrowing.

This specification is sufficient for building an interoperable implementation from scratch. Any two conformant implementations MUST produce identical results for the same inputs across all deterministic operations defined herein.

---

## 2. Terminology

**Covenant.** A signed, content-addressed JSON document that declares behavioral constraints binding an issuer's actions with respect to a beneficiary. A covenant is immutable once signed: its identifier is derived from its content, and any modification invalidates both the identifier and the cryptographic signature.

**Agent.** An autonomous software entity capable of executing actions on external systems. In the Kervyx protocol, an agent is identified by an Ed25519 key pair and participates in covenants as either an issuer or a beneficiary.

**Issuer.** The party that creates, signs, and is bound by a covenant. The issuer's Ed25519 private key produces the covenant's signature. The issuer commits to operating within the constraints declared in the covenant.

**Beneficiary.** The party on whose behalf the covenant's constraints are enforced. The beneficiary is identified in the covenant by a public key and can independently verify covenant compliance.

**CCL (Covenant Constraint Language).** A declarative, side-effect-free language for expressing behavioral constraints within a covenant. CCL programs consist of permit, deny, require, and limit statements that define an access-control policy over actions and resources.

**Canonical Form.** The deterministic JSON serialization of a covenant document, produced by removing the `id`, `signature`, and `countersignatures` fields and applying JCS (RFC 8785) canonicalization to the remainder. The canonical form is the byte string over which signatures and content addresses are computed.

**Content Address.** A unique identifier for a covenant document, computed as the hexadecimal encoding of the SHA-256 hash of the document's canonical form. The content address serves as the document's `id` field. Because it is derived from the document's content, any modification to the document produces a different content address.

**Chain.** An ordered sequence of covenant documents linked by parent references, forming a delegation hierarchy. Each child covenant in a chain MUST only narrow (never broaden) the constraints of its parent. The chain forms a directed acyclic structure from root (most permissive) to leaf (most restrictive).

**Narrowing.** The property that a child covenant's permitted behavior set is a subset of its parent's permitted behavior set. Formally, for a child covenant C_child with parent C_parent: `permitted(C_child) subset_of permitted(C_parent)`. Narrowing ensures that delegation never escalates privileges.

---

## 3. Covenant Document Schema

A covenant document is a JSON object conforming to the schema defined in this section. Implementations MUST validate all structural constraints before performing cryptographic verification.

### 3.1 Required Fields

| Field           | Type   | Constraints                                    | Description                                                  |
|-----------------|--------|------------------------------------------------|--------------------------------------------------------------|
| `id`            | string | 64 hexadecimal characters (SHA-256 output)     | Content address of the document, computed per Section 7.     |
| `version`       | string | Exactly `"1.0"`                                | Protocol version identifier.                                 |
| `issuer`        | object | Party object with `role: "issuer"`             | The party that created and signed this covenant.             |
| `beneficiary`   | object | Party object with `role: "beneficiary"`        | The party bound by this covenant.                            |
| `constraints`   | string | Non-empty; valid CCL per Section 4             | CCL source text defining the covenant's behavioral bounds.   |
| `nonce`         | string | 64 hexadecimal characters (32 bytes)           | Cryptographic nonce for replay protection.                   |
| `createdAt`     | string | ISO 8601 UTC datetime                          | Timestamp of document creation.                              |
| `signature`     | string | 128 hexadecimal characters (Ed25519 signature) | Issuer's Ed25519 signature over the canonical form.          |

### 3.2 Optional Fields

| Field               | Type   | Constraints                                              | Description                                               |
|---------------------|--------|----------------------------------------------------------|-----------------------------------------------------------|
| `chain`             | object | ChainReference object                                    | Reference to parent covenant in a delegation chain.       |
| `expiresAt`         | string | ISO 8601 UTC datetime                                    | Timestamp after which the covenant is no longer valid.    |
| `activatesAt`       | string | ISO 8601 UTC datetime                                    | Timestamp before which the covenant is not yet active.    |
| `metadata`          | object | Arbitrary JSON object                                    | Application-defined metadata.                             |
| `countersignatures` | array  | Array of Countersignature objects                        | Third-party countersignatures appended after creation.    |
| `obligations`       | array  | Array of Obligation objects                              | Structured obligations that must be fulfilled.            |
| `enforcement`       | object | EnforcementConfig with valid `type`                      | Runtime enforcement configuration.                        |
| `proof`             | object | ProofConfig with valid `type`                            | Compliance proof configuration.                           |
| `revocation`        | object | RevocationConfig                                         | Revocation mechanism configuration.                       |

### 3.3 Party Object

A Party object identifies a participant in a covenant.

| Field       | Type   | Constraints                                | Required |
|-------------|--------|--------------------------------------------|----------|
| `id`        | string | Non-empty                                  | Yes      |
| `publicKey` | string | 64 hexadecimal characters (Ed25519 pubkey) | Yes      |
| `role`      | string | `"issuer"` or `"beneficiary"`              | Yes      |
| `name`      | string | Non-empty                                  | No       |
| `metadata`  | object | Arbitrary JSON object                      | No       |

The `publicKey` field MUST contain the hexadecimal encoding of a 32-byte Ed25519 public key (64 hex characters). The `role` field MUST be `"issuer"` for the issuer party and `"beneficiary"` for the beneficiary party.

### 3.4 ChainReference Object

A ChainReference links a child covenant to its parent in a delegation chain.

| Field      | Type    | Constraints                                        | Required |
|------------|---------|----------------------------------------------------|----------|
| `parentId` | string  | 64 hexadecimal characters (parent document ID)     | Yes      |
| `relation` | string  | One of: `"delegates"`, `"restricts"`, `"extends"`  | Yes      |
| `depth`    | integer | `>= 1` and `<= 16`                                | Yes      |

The `depth` field represents the distance from the root covenant. A direct child of the root has `depth = 1`, a grandchild has `depth = 2`, and so on. Implementations MUST reject documents with `depth < 1` or `depth > MAX_CHAIN_DEPTH` (16).

### 3.5 Countersignature Object

A Countersignature is an independent Ed25519 signature over the same canonical form, created by a third party.

| Field            | Type   | Constraints                                 | Required |
|------------------|--------|---------------------------------------------|----------|
| `signerPublicKey`| string | 64 hexadecimal characters (Ed25519 pubkey)  | Yes      |
| `signerRole`     | string | Non-empty (e.g. `"auditor"`, `"regulator"`) | Yes      |
| `signature`      | string | 128 hexadecimal characters (Ed25519 sig)    | Yes      |
| `timestamp`      | string | ISO 8601 UTC datetime                       | Yes      |

### 3.6 EnforcementConfig Object

| Field         | Type   | Constraints                                                             | Required |
|---------------|--------|-------------------------------------------------------------------------|----------|
| `type`        | string | One of: `"capability"`, `"monitor"`, `"audit"`, `"bond"`, `"composite"`| Yes      |
| `config`      | object | Arbitrary JSON object                                                   | Yes      |
| `description` | string | Non-empty                                                               | No       |

### 3.7 ProofConfig Object

| Field         | Type   | Constraints                                                                                      | Required |
|---------------|--------|--------------------------------------------------------------------------------------------------|----------|
| `type`        | string | One of: `"tee"`, `"capability_manifest"`, `"audit_log"`, `"bond_reference"`, `"zkp"`, `"composite"` | Yes      |
| `config`      | object | Arbitrary JSON object                                                                            | Yes      |
| `description` | string | Non-empty                                                                                        | No       |

### 3.8 RevocationConfig Object

| Field      | Type   | Constraints                                            | Required |
|------------|--------|--------------------------------------------------------|----------|
| `method`   | string | One of: `"crl"`, `"status_endpoint"`, `"onchain"`     | Yes      |
| `endpoint` | string | Valid URI                                              | No       |
| `config`   | object | Arbitrary JSON object                                  | No       |

### 3.9 Obligation Object

| Field         | Type   | Constraints      | Required |
|---------------|--------|------------------|----------|
| `id`          | string | Non-empty        | Yes      |
| `description` | string | Non-empty        | Yes      |
| `action`      | string | Non-empty        | Yes      |
| `deadline`    | string | ISO 8601 UTC     | No       |

---

## 4. Covenant Constraint Language (CCL) Grammar

CCL is a declarative, pure-functional constraint language for expressing behavioral bounds within a covenant. CCL programs are total (they always terminate) and side-effect free. The language defines four statement types: `permit`, `deny`, `require`, and `limit`.

### 4.1 Formal Grammar (EBNF)

```ebnf
program        = { statement newline } ;
statement      = permit_deny | require_stmt | limit_stmt ;
permit_deny    = ( "permit" | "deny" ) action "on" resource [ condition ] [ severity_clause ] ;
require_stmt   = "require" action "on" resource [ condition ] [ severity_clause ] ;
limit_stmt     = "limit" action number "per" number time_unit [ severity_clause ] ;
action         = glob_pattern ;
resource       = "'" path_glob "'" | path_glob | wildcard ;
glob_pattern   = segment { "." segment } ;
path_glob      = "/" { path_segment "/" } [ path_segment ] ;
segment        = identifier | "*" | "**" ;
path_segment   = identifier | "*" | "**" ;
condition      = "when" or_expr ;
or_expr        = and_expr { "or" and_expr } ;
and_expr       = not_expr { "and" not_expr } ;
not_expr       = "not" not_expr | primary_cond ;
primary_cond   = "(" or_expr ")" | comparison ;
comparison     = field operator value ;
operator       = "=" | "!=" | "<" | ">" | "<=" | ">="
               | "contains" | "not_contains"
               | "in" | "not_in"
               | "matches" | "starts_with" | "ends_with" ;
field          = identifier { "." identifier } ;
value          = number | "'" string "'" | identifier | array ;
array          = "[" value { "," value } "]" ;
severity_clause = "severity" severity_level ;
severity_level = "critical" | "high" | "medium" | "low" ;
metric         = identifier { "." identifier } ;
time_unit      = "seconds" | "second" | "minutes" | "minute"
               | "hours" | "hour" | "days" | "day" ;
identifier     = letter { letter | digit | "_" | "-" } ;
number         = digit { digit } [ "." digit { digit } ] ;
letter         = "a" | ... | "z" | "A" | ... | "Z" | "_" ;
digit          = "0" | ... | "9" ;
newline        = "\n" ;
```

### 4.2 Comments

Lines beginning with `#` are comments and MUST be ignored by the parser. A comment extends from `#` to the end of the line.

```
# This is a comment
permit read on '/data/**'  # Inline comments are also permitted
```

### 4.3 Statement Semantics

**`permit`**: Grants access to the specified action on the specified resource. Without an explicit `permit`, all actions are denied (default-deny semantics).

**`deny`**: Explicitly denies access to the specified action on the specified resource. A `deny` ALWAYS takes precedence over a `permit` at equal or lower specificity.

**`require`**: Declares an obligation that MUST be fulfilled. A `require` statement does not grant or deny access; it declares that the specified action MUST be performed on the specified resource. Violation of a `require` constitutes a breach.

**`limit`**: Imposes a rate limit on the specified action. The syntax `limit ACTION COUNT per PERIOD UNIT` means: at most COUNT invocations of ACTION are permitted within any sliding window of PERIOD time units. Time units map to seconds as follows: `seconds` = 1, `minutes` = 60, `hours` = 3600, `days` = 86400.

### 4.4 Default Severity

If no `severity` clause is present, the default severity is `high`.

---

## 5. CCL Evaluation Semantics

### 5.1 Evaluation Function Signature

```
evaluate(doc: CCLDocument, action: string, resource: string, context: map<string, any>) -> EvaluationResult
```

**Inputs:**
- `doc`: A parsed CCL document containing categorized statement arrays.
- `action`: The action string to evaluate (e.g., `"read"`, `"api.call"`).
- `resource`: The resource path to evaluate (e.g., `"/data/users"`).
- `context`: A key-value map for condition evaluation. Supports nested access via dotted paths (e.g., `context["user.role"]` resolves to `context.user.role`).

**Output:**
- `permitted`: Boolean indicating whether the action is permitted.
- `matchedRule`: The winning rule that determined the outcome, or null.
- `allMatches`: All statements that matched the action/resource pair.
- `reason`: Human-readable explanation of the decision.
- `severity`: Severity of the matched rule, if any.

### 5.2 Evaluation Algorithm

```
function evaluate(doc, action, resource, context):
    matchedPermitDeny = []

    // Step 1: Collect all matching permit/deny statements
    for stmt in doc.permits:
        if matchAction(stmt.action, action) AND matchResource(stmt.resource, resource):
            if stmt.condition is null OR evaluateCondition(stmt.condition, context):
                matchedPermitDeny.append(stmt)

    for stmt in doc.denies:
        if matchAction(stmt.action, action) AND matchResource(stmt.resource, resource):
            if stmt.condition is null OR evaluateCondition(stmt.condition, context):
                matchedPermitDeny.append(stmt)

    // Step 2: If no rules match, default deny
    if matchedPermitDeny is empty:
        return { permitted: false, reason: "No matching rules found; default deny" }

    // Step 3: Sort by specificity descending; at equal specificity, deny wins
    sort matchedPermitDeny by:
        primary key: specificity(stmt.action, stmt.resource) DESCENDING
        secondary key: stmt.type == "deny" FIRST

    // Step 4: The first element is the winner
    winner = matchedPermitDeny[0]
    return {
        permitted: winner.type == "permit",
        matchedRule: winner,
        reason: "Matched " + winner.type + " rule for " + winner.action + " on " + winner.resource
    }
```

### 5.3 Conflict Resolution Rules

1. **Deny wins at equal specificity.** When a `deny` and a `permit` match the same action/resource pair with equal specificity scores, the `deny` takes precedence.
2. **Most specific wins among different specificities.** A more specific pattern beats a less specific pattern, regardless of whether it is a permit or deny.
3. **Default deny.** If no `permit` or `deny` statement matches, the action is DENIED.

### 5.4 Glob Matching Algorithm

Two glob matchers are defined: one for actions (dot-separated segments) and one for resources (slash-separated segments). Both use the same underlying segment matching algorithm.

**Action Matching** (`matchAction`):

Segments are split on `.` (dot). For example, `"api.call"` splits into `["api", "call"]`.

**Resource Matching** (`matchResource`):

Segments are split on `/` (slash). Leading and trailing slashes are stripped before splitting. For example, `"/data/users/"` normalizes to `"data/users"` and splits into `["data", "users"]`.

**Wildcard Rules:**
- `*` matches exactly one segment (any content).
- `**` matches zero or more segments.
- A literal segment matches only itself (exact string equality).

**Segment Matching Algorithm** (recursive):

```
function matchSegments(pattern[], pi, target[], ti):
    while pi < len(pattern) AND ti < len(target):
        p = pattern[pi]

        if p == "**":
            // ** can match zero or more segments
            // Try matching zero segments (advance pattern only)
            if matchSegments(pattern, pi + 1, target, ti):
                return true
            // Try matching one or more segments (advance target)
            return matchSegments(pattern, pi, target, ti + 1)

        if p == "*":
            // * matches exactly one segment (any content)
            pi = pi + 1
            ti = ti + 1
            continue

        // Literal match
        if p != target[ti]:
            return false
        pi = pi + 1
        ti = ti + 1

    // Skip trailing ** patterns (they can match zero segments)
    while pi < len(pattern) AND pattern[pi] == "**":
        pi = pi + 1

    return pi == len(pattern) AND ti == len(target)
```

### 5.5 Specificity Scoring

Specificity determines which rule wins when multiple rules match. Higher specificity means a more precise match.

```
function specificity(actionPattern, resourcePattern):
    score = 0

    for segment in actionPattern.split("."):
        if segment == "**":   score += 0
        else if segment == "*": score += 1
        else:                   score += 2

    normalizedResource = resourcePattern.strip("/")
    if normalizedResource is not empty:
        for segment in normalizedResource.split("/"):
            if segment == "**":   score += 0
            else if segment == "*": score += 1
            else:                   score += 2

    return score
```

**Specificity ordering:** literal (2 points) > `*` (1 point) > `**` (0 points). Longer paths with more literal segments produce higher scores.

### 5.6 Condition Evaluation

Conditions support simple comparisons and compound boolean expressions (`and`, `or`, `not`).

**Simple Condition Evaluation:**

```
function evaluateSimpleCondition(condition, context):
    fieldValue = resolveField(context, condition.field)

    // Missing fields evaluate to false (safe default-deny)
    if fieldValue is undefined:
        return false

    switch condition.operator:
        "=":           return fieldValue == condition.value
        "!=":          return fieldValue != condition.value
        "<":           return fieldValue < condition.value    // numeric only
        ">":           return fieldValue > condition.value    // numeric only
        "<=":          return fieldValue <= condition.value   // numeric only
        ">=":          return fieldValue >= condition.value   // numeric only
        "contains":    return fieldValue.includes(condition.value)
        "not_contains": return NOT fieldValue.includes(condition.value)
        "in":          return condition.value.includes(fieldValue)
        "not_in":      return NOT condition.value.includes(fieldValue)
        "matches":     return regex_match(condition.value, fieldValue)
        "starts_with": return fieldValue.startsWith(condition.value)
        "ends_with":   return fieldValue.endsWith(condition.value)
```

**Compound Condition Evaluation:**

```
function evaluateCompoundCondition(condition, context):
    switch condition.type:
        "and": return ALL(evaluateCondition(c, context) for c in condition.conditions)
        "or":  return ANY(evaluateCondition(c, context) for c in condition.conditions)
        "not": return NOT evaluateCondition(condition.conditions[0], context)
```

**Field Resolution:**

Dotted field paths are resolved by traversing nested objects. For example, `"user.role"` applied to context `{ "user": { "role": "admin" } }` resolves to `"admin"`. If any intermediate key is missing, the resolution returns `undefined`.

### 5.7 Rate Limit Evaluation

```
function checkRateLimit(doc, action, currentCount, periodStartTime, now):
    // Find the most specific matching limit
    matchedLimit = null
    bestSpecificity = -1

    for limit in doc.limits:
        if matchAction(limit.action, action):
            spec = specificity(limit.action, "")
            if spec > bestSpecificity:
                bestSpecificity = spec
                matchedLimit = limit

    if matchedLimit is null:
        return { exceeded: false, remaining: Infinity }

    periodMs = matchedLimit.periodSeconds * 1000
    elapsed = now - periodStartTime

    if elapsed > periodMs:
        // Period has expired; the count resets
        return { exceeded: false, remaining: matchedLimit.count }

    remaining = max(0, matchedLimit.count - currentCount)
    return {
        exceeded: currentCount >= matchedLimit.count,
        remaining: remaining
    }
```

---

## 6. Canonical Form Algorithm

The canonical form of a covenant document is a deterministic byte string used as input for signing, verification, and content addressing. It is computed by removing non-deterministic fields and applying JCS canonicalization.

### 6.1 Algorithm

```
function canonical_form(doc):
    body = shallow_copy(doc)
    delete body.id
    delete body.signature
    delete body.countersignatures
    return JCS_canonicalize(body)
```

### 6.2 Fields Excluded from Canonical Form

Exactly three fields are excluded from the canonical form:

1. **`id`**: Derived from the canonical form itself; including it would create a circular dependency.
2. **`signature`**: Produced by signing the canonical form; cannot exist before the canonical form is computed.
3. **`countersignatures`**: Added after document creation by third parties; their inclusion would make the canonical form (and therefore the document ID) change when countersignatures are added or removed.

All other fields present in the document, including all optional fields, are included in the canonical form.

### 6.3 JCS Canonicalization (RFC 8785)

The JSON Canonicalization Scheme (JCS) as specified in RFC 8785 MUST be applied to the body after field removal. The following rules apply:

1. **Object key ordering.** At every nesting level, object keys MUST be sorted in lexicographic order using Unicode code point comparison.
2. **No whitespace.** No whitespace is inserted between structural characters. No indentation, no trailing spaces, no trailing newline.
3. **Number serialization.** Numbers MUST be serialized using the IEEE 754 double-precision representation rules defined in RFC 8785 Section 3.2.2.3. In practice, integers are serialized without decimal points (e.g., `1` not `1.0`), and floating-point values use minimal representation.
4. **String serialization.** Strings MUST be serialized with the minimal JSON escape sequences defined in RFC 8785. Characters that do not require escaping MUST NOT be escaped.
5. **Null, boolean.** `null`, `true`, and `false` are serialized as their literal JSON representations.
6. **Undefined/absent values.** Fields with `undefined` values MUST be omitted entirely from the output. Only fields explicitly present in the object are included.
7. **Array ordering.** Array elements MUST be serialized in their original order. Arrays are NOT sorted.
8. **Encoding.** The output MUST be encoded as UTF-8.

### 6.4 Determinism Guarantee

For any two conformant implementations, given the same input document, `canonical_form` MUST produce byte-identical output. This is the foundation of cross-implementation interoperability.

---

## 7. Document ID Computation

The document ID is the hexadecimal encoding of the SHA-256 hash of the canonical form.

### 7.1 Algorithm

```
function compute_id(doc):
    canonical = canonical_form(doc)
    hash_bytes = SHA-256(UTF8_encode(canonical))
    return hex_encode(hash_bytes)
```

### 7.2 Properties

- The ID is a 64-character lowercase hexadecimal string (256 bits).
- The ID is deterministic: the same document always produces the same ID.
- The ID is collision-resistant: it is computationally infeasible to find two distinct documents with the same ID (SHA-256 collision resistance).
- Any modification to any field included in the canonical form changes the ID.

---

## 8. Signing and Verification

All signatures in the Kervyx protocol use the Ed25519 digital signature algorithm as specified in RFC 8032.

### 8.1 Signing Algorithm

```
function sign(doc, private_key):
    canonical = canonical_form(doc)
    message_bytes = UTF8_encode(canonical)
    signature_bytes = Ed25519_sign(message_bytes, private_key)
    return hex_encode(signature_bytes)
```

The signature is a 64-byte Ed25519 signature, hex-encoded to 128 characters.

### 8.2 Signature Verification Algorithm

```
function verify_signature(doc):
    canonical = canonical_form(doc)
    message_bytes = UTF8_encode(canonical)
    signature_bytes = hex_decode(doc.signature)
    public_key_bytes = hex_decode(doc.issuer.publicKey)
    return Ed25519_verify(message_bytes, signature_bytes, public_key_bytes)
```

### 8.3 Countersignature Signing

Countersignatures sign the same canonical form as the issuer's signature. This means a countersignature remains valid regardless of other countersignatures being added or removed.

```
function countersign(doc, signer_key_pair, signer_role):
    canonical = canonical_form(doc)
    message_bytes = UTF8_encode(canonical)
    signature_bytes = Ed25519_sign(message_bytes, signer_key_pair.private_key)

    countersig = {
        signerPublicKey: hex_encode(signer_key_pair.public_key),
        signerRole: signer_role,
        signature: hex_encode(signature_bytes),
        timestamp: current_UTC_ISO8601()
    }

    new_doc = copy(doc)
    new_doc.countersignatures = (doc.countersignatures or []) + [countersig]
    return new_doc
```

---

## 9. Verification Algorithm

Verification of a covenant document consists of 11 independent checks. A document is valid if and only if ALL checks pass. Implementations MUST execute all 11 checks and report the result of each, even if an earlier check fails.

### 9.1 Check Definitions

#### Check 1: `id_match`

**Condition:** `doc.id == compute_id(doc)`

Verifies that the document's `id` field matches the SHA-256 hash of its canonical form. A mismatch indicates that the document has been modified after ID computation, or that the ID was computed incorrectly.

```
function check_id_match(doc):
    expected_id = hex_encode(SHA-256(UTF8_encode(canonical_form(doc))))
    return doc.id == expected_id
```

#### Check 2: `signature_valid`

**Condition:** `Ed25519_verify(UTF8_encode(canonical_form(doc)), hex_decode(doc.signature), hex_decode(doc.issuer.publicKey))`

Verifies that the issuer's Ed25519 signature over the canonical form is valid. A failure indicates that the document was not signed by the claimed issuer, or that the document has been modified after signing.

```
function check_signature_valid(doc):
    canonical = canonical_form(doc)
    message = UTF8_encode(canonical)
    signature = hex_decode(doc.signature)
    public_key = hex_decode(doc.issuer.publicKey)
    return Ed25519_verify(message, signature, public_key)
```

#### Check 3: `not_expired`

**Condition:** `doc.expiresAt == null OR current_time() < parse_ISO8601(doc.expiresAt)`

If an expiration timestamp is set, the document MUST NOT have expired. If no expiration is set, this check passes unconditionally.

```
function check_not_expired(doc):
    if doc.expiresAt is null:
        return true
    return current_UTC_time() < parse_ISO8601(doc.expiresAt)
```

#### Check 4: `active`

**Condition:** `doc.activatesAt == null OR current_time() >= parse_ISO8601(doc.activatesAt)`

If an activation timestamp is set, the current time MUST be at or after the activation time. If no activation time is set, this check passes unconditionally.

```
function check_active(doc):
    if doc.activatesAt is null:
        return true
    return current_UTC_time() >= parse_ISO8601(doc.activatesAt)
```

#### Check 5: `ccl_parses`

**Condition:** `parse_ccl(doc.constraints)` succeeds without error AND statement count <= MAX_CONSTRAINTS

The CCL constraint text MUST parse successfully according to the grammar in Section 4, and the total number of statements MUST NOT exceed `MAX_CONSTRAINTS` (256).

```
function check_ccl_parses(doc):
    try:
        parsed = parse_ccl(doc.constraints)
        return len(parsed.statements) <= MAX_CONSTRAINTS
    catch:
        return false
```

#### Check 6: `enforcement_valid`

**Condition:** `doc.enforcement == null OR doc.enforcement.type in {"capability", "monitor", "audit", "bond", "composite"}`

If an enforcement configuration is present, its `type` field MUST be one of the recognized enforcement types.

```
function check_enforcement_valid(doc):
    if doc.enforcement is null:
        return true
    valid_types = {"capability", "monitor", "audit", "bond", "composite"}
    return doc.enforcement.type in valid_types
```

#### Check 7: `proof_valid`

**Condition:** `doc.proof == null OR doc.proof.type in {"tee", "capability_manifest", "audit_log", "bond_reference", "zkp", "composite"}`

If a proof configuration is present, its `type` field MUST be one of the recognized proof types.

```
function check_proof_valid(doc):
    if doc.proof is null:
        return true
    valid_types = {"tee", "capability_manifest", "audit_log", "bond_reference", "zkp", "composite"}
    return doc.proof.type in valid_types
```

#### Check 8: `chain_depth`

**Condition:** `doc.chain == null OR (1 <= doc.chain.depth <= MAX_CHAIN_DEPTH)`

If a chain reference is present, the depth MUST be a positive integer not exceeding `MAX_CHAIN_DEPTH` (16).

```
function check_chain_depth(doc):
    if doc.chain is null:
        return true
    return doc.chain.depth >= 1 AND doc.chain.depth <= MAX_CHAIN_DEPTH
```

#### Check 9: `document_size`

**Condition:** `byte_length(UTF8_encode(JSON_serialize(doc))) <= MAX_DOCUMENT_SIZE`

The UTF-8 encoded JSON serialization of the complete document (including all fields) MUST NOT exceed `MAX_DOCUMENT_SIZE` (1,048,576 bytes, i.e., 1 MiB).

```
function check_document_size(doc):
    serialized = JSON_serialize(doc)
    byte_count = byte_length(UTF8_encode(serialized))
    return byte_count <= MAX_DOCUMENT_SIZE
```

#### Check 10: `countersignatures`

**Condition:** For each countersignature `cs` in `doc.countersignatures`: `Ed25519_verify(UTF8_encode(canonical_form(doc)), hex_decode(cs.signature), hex_decode(cs.signerPublicKey))`

Every countersignature present MUST be a valid Ed25519 signature over the canonical form of the document. If no countersignatures are present, this check passes unconditionally.

```
function check_countersignatures(doc):
    if doc.countersignatures is null or empty:
        return true
    canonical = canonical_form(doc)
    message = UTF8_encode(canonical)
    for cs in doc.countersignatures:
        sig = hex_decode(cs.signature)
        pubkey = hex_decode(cs.signerPublicKey)
        if NOT Ed25519_verify(message, sig, pubkey):
            return false
    return true
```

#### Check 11: `nonce_present`

**Condition:** `doc.nonce` matches the regular expression `/^[0-9a-fA-F]{64}$/`

The nonce MUST be present and MUST be a 64-character hexadecimal string representing 32 bytes generated from a cryptographically secure pseudorandom number generator (CSPRNG).

```
function check_nonce_present(doc):
    return typeof(doc.nonce) == "string"
        AND regex_match("^[0-9a-fA-F]{64}$", doc.nonce)
```

### 9.2 Aggregate Result

```
function verify_covenant(doc):
    checks = [
        { name: "id_match",          passed: check_id_match(doc) },
        { name: "signature_valid",    passed: check_signature_valid(doc) },
        { name: "not_expired",        passed: check_not_expired(doc) },
        { name: "active",             passed: check_active(doc) },
        { name: "ccl_parses",         passed: check_ccl_parses(doc) },
        { name: "enforcement_valid",  passed: check_enforcement_valid(doc) },
        { name: "proof_valid",        passed: check_proof_valid(doc) },
        { name: "chain_depth",        passed: check_chain_depth(doc) },
        { name: "document_size",      passed: check_document_size(doc) },
        { name: "countersignatures",  passed: check_countersignatures(doc) },
        { name: "nonce_present",      passed: check_nonce_present(doc) },
    ]
    valid = ALL(check.passed for check in checks)
    return { valid, checks }
```

---

## 10. Chain Composition

Covenants can form delegation chains through the `chain` field. The fundamental invariant of chain composition is **monotonic constraint narrowing**: a child covenant's permitted behavior set MUST be a strict subset of (or equal to) its parent's permitted behavior set.

### 10.1 Monotonic Constraint Narrowing Invariant

For any child covenant C_child with parent C_parent:

```
permitted(C_child) is subset of permitted(C_parent)
```

This invariant ensures that delegation never escalates privileges. Formally:

- Every `permit` in the child MUST be covered by a `permit` in the parent (the child's permitted action/resource scope is a subset of the parent's).
- Every `deny` in the parent MUST be preserved in the child (the child cannot remove a parent's denial).
- Every `require` in the parent MUST be preserved in the child (the child cannot remove a parent's obligation).
- Every `limit` in the child MUST be equal to or stricter than the corresponding `limit` in the parent (lower count or shorter period).

### 10.2 Narrowing Validation Algorithm

```
function validate_narrowing(parent_ccl, child_ccl):
    violations = []

    // Check 1: Child permits must not overlap with parent denies
    for child_permit in child_ccl.permits:
        for parent_deny in parent_ccl.denies:
            if patterns_overlap(child_permit.action, parent_deny.action)
               AND patterns_overlap(child_permit.resource, parent_deny.resource):
                violations.append({
                    childRule: child_permit,
                    parentRule: parent_deny,
                    reason: "Child permits what parent denies"
                })

    // Check 2: Child permits must be subsets of parent permits
    for child_permit in child_ccl.permits:
        has_matching_parent = false
        for parent_permit in parent_ccl.permits:
            if is_subset_pattern(child_permit.action, parent_permit.action, ".")
               AND is_subset_pattern(child_permit.resource, parent_permit.resource, "/"):
                has_matching_parent = true
                break
        if parent_ccl.permits is not empty AND NOT has_matching_parent:
            violations.append({
                childRule: child_permit,
                parentRule: parent_ccl.permits[0],
                reason: "Child permit is not a subset of any parent permit"
            })

    return { valid: len(violations) == 0, violations }
```

**Pattern subset checking** (`is_subset_pattern`): A child pattern P_child is a subset of a parent pattern P_parent if every string matched by P_child is also matched by P_parent. The rules are:

- `**` in the parent matches everything, so any child pattern is a subset.
- `**` in the child (when parent is not `**`) is NOT a subset, because it can match strings the parent does not.
- `*` in the child is a subset of `*` or `**` in the parent at the same position.
- A literal in the child is a subset of a literal, `*`, or `**` in the parent at the same position (if the literal matches).
- `*` in the child is NOT a subset of a literal in the parent, because `*` matches strings the literal does not.

### 10.3 Effective Constraint Computation

The effective constraints for a covenant are computed by merging all constraints in its chain, from the root down to the leaf.

```
function compute_effective_constraints(doc, ancestors):
    // ancestors is ordered parent-first (immediate parent at index 0)
    // Reverse to get root-first ordering
    all_docs = reverse(ancestors) + [doc]

    effective = parse_ccl(all_docs[0].constraints)

    for i from 1 to len(all_docs) - 1:
        child_ccl = parse_ccl(all_docs[i].constraints)
        effective = merge(effective, child_ccl)

    return effective
```

### 10.4 Merge Semantics

```
function merge(parent_ccl, child_ccl):
    statements = []

    // All denies from both parent and child are included
    statements.extend(parent_ccl.denies)
    statements.extend(child_ccl.denies)

    // All permits from both are included (evaluation resolves conflicts)
    statements.extend(parent_ccl.permits)
    statements.extend(child_ccl.permits)

    // All obligations from both
    statements.extend(parent_ccl.obligations)
    statements.extend(child_ccl.obligations)

    // For limits on the same action, take the more restrictive (lower count)
    limits_by_action = {}
    for limit in parent_ccl.limits + child_ccl.limits:
        if limit.action not in limits_by_action
           OR limit.count < limits_by_action[limit.action].count:
            limits_by_action[limit.action] = limit
    statements.extend(limits_by_action.values())

    return build_ccl_document(statements)
```

### 10.5 Chain Verification

Verifying a chain of covenant documents requires:

1. **Individual validity.** Each document in the chain MUST pass all 11 verification checks (Section 9).
2. **Depth limit.** The chain length MUST NOT exceed `MAX_CHAIN_DEPTH` (16).
3. **Parent reference consistency.** For each non-root document at index `i`, `docs[i].chain.parentId` MUST equal `docs[i-1].id`.
4. **Depth monotonicity.** The `chain.depth` values MUST be monotonically increasing from root to leaf.
5. **Narrowing validity.** Each child MUST satisfy the narrowing invariant with respect to its parent (Section 10.2).

---

## 11. Countersignature Protocol

Countersignatures enable third parties (auditors, regulators, operators) to attest to a covenant document without modifying its content or identity.

### 11.1 Invariants

1. **Same canonical form.** A countersignature signs the same canonical form as the issuer's signature. The canonical form excludes the `countersignatures` field, so adding or removing countersignatures does not change the bytes being signed.

2. **Stable document ID.** Because the canonical form (and therefore the SHA-256 hash) does not include the `countersignatures` field, the document's `id` is unchanged by the addition or removal of countersignatures.

3. **Independent verifiability.** Each countersignature is independently verifiable using only the document's canonical form and the countersigner's public key. Verification of one countersignature does not depend on any other countersignature.

4. **Non-interfering.** The order of countersignatures in the array has no semantic significance. Countersignatures can be added in any order without affecting the validity of existing countersignatures or the issuer's signature.

### 11.2 Countersignature Verification

```
function verify_countersignature(doc, countersig):
    canonical = canonical_form(doc)
    message = UTF8_encode(canonical)
    signature = hex_decode(countersig.signature)
    public_key = hex_decode(countersig.signerPublicKey)
    return Ed25519_verify(message, signature, public_key)
```

### 11.3 Re-signing

When a document is re-signed (e.g., due to key rotation or nonce refresh), a new nonce is generated, which changes the canonical form. All existing countersignatures are therefore invalidated and MUST be stripped from the re-signed document. The re-signed document receives a new `id`, `signature`, and `nonce`.

---

## 12. Protocol Constants

The following constants are defined by the protocol and MUST be honored by all conformant implementations.

| Constant              | Value       | Description                                                |
|-----------------------|-------------|------------------------------------------------------------|
| `PROTOCOL_VERSION`    | `"1.0"`     | The protocol version string used in the `version` field.   |
| `MAX_CONSTRAINTS`     | 256         | Maximum number of CCL statements in a single covenant.     |
| `MAX_CHAIN_DEPTH`     | 16          | Maximum depth of a covenant delegation chain.              |
| `MAX_DOCUMENT_SIZE`   | 1,048,576   | Maximum serialized document size in bytes (1 MiB).         |

---

## 13. Cryptographic Requirements

### 13.1 Hash Function

**SHA-256** (FIPS 180-4) is used for all content addressing and document ID computation. The output is 32 bytes (256 bits), hex-encoded to 64 characters.

### 13.2 Digital Signature

**Ed25519** (RFC 8032, Section 5.1) is used for all signing and verification operations. Key sizes:

- Private key: 32 bytes (256 bits)
- Public key: 32 bytes (256 bits), hex-encoded to 64 characters
- Signature: 64 bytes (512 bits), hex-encoded to 128 characters

### 13.3 Canonicalization

**JCS** (RFC 8785) is used for deterministic JSON serialization. All implementations MUST produce byte-identical canonical forms for the same logical JSON document.

### 13.4 Nonce Generation

Nonces MUST be 32 bytes (256 bits) generated from a cryptographically secure pseudorandom number generator (CSPRNG) as defined by the implementation platform (e.g., `crypto.getRandomValues` in Web Crypto, `/dev/urandom` on POSIX systems, `CryptGenRandom` on Windows). The nonce is hex-encoded to 64 characters.

### 13.5 EVM Hash (On-Chain Operations)

**Keccak-256** (FIPS 202 / SHA-3, with the Ethereum-specific padding) is used exclusively for on-chain operations when interacting with Ethereum Virtual Machine (EVM) based blockchains. Keccak-256 is NOT used for any protocol-level operations defined in this specification; it is mentioned here for completeness as an interoperability consideration.

### 13.6 Encoding

All string-to-bytes conversions use **UTF-8** encoding (RFC 3629). Hexadecimal encoding uses lowercase characters (`0-9a-f`), though decoders MUST accept both lowercase and uppercase (`0-9a-fA-F`).

---

## Appendix A: Test Vectors

The following test vectors provide known-good inputs and expected outputs for cross-implementation validation. Any conformant implementation MUST produce identical results for all vectors.

### A.1 JCS Canonicalization Vectors

**Vector A.1.1: Simple key reordering**

Input object:
```json
{"b": 2, "a": 1}
```

Expected canonical form:
```
{"a":1,"b":2}
```

**Vector A.1.2: String value ordering**

Input object:
```json
{"z": "last", "a": "first", "m": "middle"}
```

Expected canonical form:
```
{"a":"first","m":"middle","z":"last"}
```

**Vector A.1.3: Nested object ordering**

Input object:
```json
{"nested": {"b": 2, "a": 1}, "top": "value"}
```

Expected canonical form:
```
{"nested":{"a":1,"b":2},"top":"value"}
```

**Vector A.1.4: Array preservation (arrays are NOT sorted)**

Input object:
```json
{"numbers": [3, 1, 2], "sorted": false}
```

Expected canonical form:
```
{"numbers":[3,1,2],"sorted":false}
```

**Vector A.1.5: Unicode handling**

Input object:
```json
{"unicode": "\u00e9", "ascii": "e"}
```

Expected canonical form:
```
{"ascii":"e","unicode":"é"}
```

### A.2 SHA-256 Hash Vectors

**Vector A.2.1: Empty string**

Input: `""` (empty string)
Expected hash: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

**Vector A.2.2: Simple string**

Input: `"hello"`
Expected hash: `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`

**Vector A.2.3: Canonical JSON string**

Input: `"{\"action\":\"read\",\"resource\":\"/data\"}"`
Expected hash: `28bd65473640e1a7a72cd10d2a775b9a478e491ff54279cb5829286eeff527dd`

### A.3 Ed25519 Signature Vectors

The following vectors use a fixed key pair for reproducibility.

Public key: `cbafbd7ff0c9cf1e7aec150ad3e2eb3a8c3635fcdfb855a61865e5711b7ca3ca`
Private key (seed): `48ba2a315d65e20a14e11d3715977c739ad2d2e20c1e46da327adc2f6fcd669e`

**Vector A.3.1: Sign "hello world"**

Input message: `"hello world"`
Expected signature: `897540d6afac1c2f38e0c1445c8a0e93df595c7b8ec5401db0f27d702c0ef101dac13cfe864fe9bba521d3ce978bb6524cc33a3ddbd611a8f1d836bb8153950a`
Expected verification result: `true`

**Vector A.3.2: Sign "The Kervyx Protocol"**

Input message: `"The Kervyx Protocol"`
Expected signature: `933256a7e4130a6f3c93a73170af28fcdc5edd4fd13c271c4bd60844017e4dcd2041334ae09b039367b7dfadaea0ed1dcbc74c705511e1b5efd72e79d9bd720f`
Expected verification result: `true`

**Vector A.3.3: Sign canonical JSON**

Input message: `"{\"action\":\"read\",\"resource\":\"/data\"}"`
Expected signature: `980ee5257dd6a40ffaf5ec81a25c4d1cef93e294ebd2b1919d3ff13a1a3d1ef40f0f327c353881a78a643f0653b2613cb51434d5c1a56d58854a5d6a5a92ad06`
Expected verification result: `true`

### A.4 CCL Evaluation Vectors

**Vector A.4.1: Simple permit**

```
Source:  permit read on '/data/**'
Action:  read
Resource: /data/users
Context: {}
Expected: permitted = true
```

**Vector A.4.2: Deny wins over permit at higher specificity**

```
Source:  permit read on '/data/**'
         deny read on '/data/secret'
Action:  read
Resource: /data/secret
Context: {}
Expected: permitted = false
Reason:  deny rule for "/data/secret" is more specific than permit for "/data/**"
```

**Vector A.4.3: Default deny when no rules match**

```
Source:  permit read on '/data/**'
Action:  write
Resource: /data/users
Context: {}
Expected: permitted = false
Reason:  No matching rules found; default deny
```

**Vector A.4.4: Condition match**

```
Source:  permit read on '/data/**' when role = 'admin'
Action:  read
Resource: /data/users
Context: { "role": "admin" }
Expected: permitted = true
```

**Vector A.4.5: Condition no match**

```
Source:  permit read on '/data/**' when role = 'admin'
Action:  read
Resource: /data/users
Context: { "role": "user" }
Expected: permitted = false
Reason:  Condition not satisfied; no matching rules; default deny
```

### A.5 Complete Document Verification Vector

The following is a complete, valid covenant document with all intermediate values shown.

**Key pair:**
- Public key: `cbafbd7ff0c9cf1e7aec150ad3e2eb3a8c3635fcdfb855a61865e5711b7ca3ca`
- Private key (seed): `48ba2a315d65e20a14e11d3715977c739ad2d2e20c1e46da327adc2f6fcd669e`

**Beneficiary public key:** `7144660c1341614e640eba63897285722edc25e3057b95e43eb31a9bcff62c06`

**Nonce:** `2d8918166e6122fa7559c3d13b03d52dc7fde7e1745668f609080f59e41364f5`

**Created at:** `2026-02-17T21:21:12.139Z`

**Canonical form** (with `id`, `signature`, `countersignatures` removed, JCS-canonicalized):
```
{"beneficiary":{"id":"test-beneficiary","publicKey":"7144660c1341614e640eba63897285722edc25e3057b95e43eb31a9bcff62c06","role":"beneficiary"},"constraints":"permit read on '/data/**'\ndeny delete on '/system/**'","createdAt":"2026-02-17T21:21:12.139Z","issuer":{"id":"test-issuer","publicKey":"cbafbd7ff0c9cf1e7aec150ad3e2eb3a8c3635fcdfb855a61865e5711b7ca3ca","role":"issuer"},"nonce":"2d8918166e6122fa7559c3d13b03d52dc7fde7e1745668f609080f59e41364f5","version":"1.0"}
```

**Document ID** (SHA-256 of canonical form): `cd653150d73b2bea652a9e4b15e83eee227370b72c2960e4984568c022d3b23e`

**Signature** (Ed25519 over canonical form): `ab1d758310973057f45857a2904581d1f71c1343c9c1e6c44a137d2900ecc3f3100b91657995f11a41dbe3ec387ddbec7ad55b16d12de744efb35cc9d1162501`

**Complete document:**
```json
{
  "id": "cd653150d73b2bea652a9e4b15e83eee227370b72c2960e4984568c022d3b23e",
  "version": "1.0",
  "issuer": {
    "id": "test-issuer",
    "publicKey": "cbafbd7ff0c9cf1e7aec150ad3e2eb3a8c3635fcdfb855a61865e5711b7ca3ca",
    "role": "issuer"
  },
  "beneficiary": {
    "id": "test-beneficiary",
    "publicKey": "7144660c1341614e640eba63897285722edc25e3057b95e43eb31a9bcff62c06",
    "role": "beneficiary"
  },
  "constraints": "permit read on '/data/**'\ndeny delete on '/system/**'",
  "nonce": "2d8918166e6122fa7559c3d13b03d52dc7fde7e1745668f609080f59e41364f5",
  "createdAt": "2026-02-17T21:21:12.139Z",
  "signature": "ab1d758310973057f45857a2904581d1f71c1343c9c1e6c44a137d2900ecc3f3100b91657995f11a41dbe3ec387ddbec7ad55b16d12de744efb35cc9d1162501"
}
```

**Verification result:** All 11 checks pass.

| Check               | Result |
|----------------------|--------|
| id_match             | PASS   |
| signature_valid      | PASS   |
| not_expired          | PASS   |
| active               | PASS   |
| ccl_parses           | PASS   |
| enforcement_valid    | PASS   |
| proof_valid          | PASS   |
| chain_depth          | PASS   |
| document_size        | PASS   |
| countersignatures    | PASS   |
| nonce_present        | PASS   |

**Tamper detection:** Modifying the first character of the signature from `a` to `0` yields signature `0b1d75...`. The `signature_valid` check MUST fail. The `id_match` check continues to pass because the ID is derived from the canonical form, which does not include the signature.

**Content tamper detection:** Changing the constraints from `"permit read on '/data/**'\ndeny delete on '/system/**'"` to `"permit write on '/data/**'"` causes both `id_match` and `signature_valid` to fail, because the canonical form has changed.

### A.6 Countersignature Vector

Starting from the document in A.5, a countersignature is added by an auditor.

**Auditor key pair:**
- Public key: `f22c2fd0da9aadbcb69e5222784ac5b1db04a0dceed46a83f58bcc03c83eca30`
- Private key (seed): `f1497702d8791c698f0d52223851f06e4e6e695f864cbb20effc4bb311ba77aa`

**Countersignature:**
```json
{
  "signerPublicKey": "f22c2fd0da9aadbcb69e5222784ac5b1db04a0dceed46a83f58bcc03c83eca30",
  "signerRole": "auditor",
  "signature": "bb6d3829fbcee5edcef653785caba26db9e47ee733b363475c6f800fe3bc83c3a33824a9cd30d9c579cb151308e8160698ce04df781ed789a215a10d6e646a0d",
  "timestamp": "2026-02-17T21:21:12.151Z"
}
```

**Verification result:** The document with countersignature passes all 11 checks. The document ID remains `cd653150d73b2bea652a9e4b15e83eee227370b72c2960e4984568c022d3b23e` (unchanged by the countersignature).

---

## Appendix B: JSON Schema Definitions

The following JSON Schema (Draft 2020-12) definitions provide machine-readable validation for covenant document structures.

### B.1 CovenantDocument Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://kervyx.dev/schema/covenant-document/1.0",
  "title": "CovenantDocument",
  "description": "A complete, signed Kervyx Covenant document conforming to protocol version 1.0.",
  "type": "object",
  "required": [
    "id",
    "version",
    "issuer",
    "beneficiary",
    "constraints",
    "nonce",
    "createdAt",
    "signature"
  ],
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[0-9a-fA-F]{64}$",
      "description": "SHA-256 content address of the canonical form (64 hex chars)."
    },
    "version": {
      "type": "string",
      "const": "1.0",
      "description": "Protocol version. MUST be '1.0'."
    },
    "issuer": {
      "$ref": "#/$defs/Party",
      "description": "The party that created and signed this covenant.",
      "properties": {
        "role": { "const": "issuer" }
      }
    },
    "beneficiary": {
      "$ref": "#/$defs/Party",
      "description": "The party bound by this covenant.",
      "properties": {
        "role": { "const": "beneficiary" }
      }
    },
    "constraints": {
      "type": "string",
      "minLength": 1,
      "description": "CCL source text defining behavioral constraints."
    },
    "nonce": {
      "type": "string",
      "pattern": "^[0-9a-fA-F]{64}$",
      "description": "Cryptographic nonce (32 bytes, hex-encoded)."
    },
    "createdAt": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of document creation."
    },
    "signature": {
      "type": "string",
      "pattern": "^[0-9a-fA-F]{128}$",
      "description": "Ed25519 signature over canonical form (64 bytes, hex-encoded)."
    },
    "chain": {
      "$ref": "#/$defs/ChainReference"
    },
    "expiresAt": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC expiration timestamp."
    },
    "activatesAt": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC activation timestamp."
    },
    "metadata": {
      "type": "object",
      "description": "Application-defined metadata."
    },
    "countersignatures": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/Countersignature"
      },
      "description": "Third-party countersignatures."
    },
    "obligations": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/Obligation"
      },
      "description": "Structured obligations."
    },
    "enforcement": {
      "$ref": "#/$defs/EnforcementConfig"
    },
    "proof": {
      "$ref": "#/$defs/ProofConfig"
    },
    "revocation": {
      "$ref": "#/$defs/RevocationConfig"
    }
  },
  "additionalProperties": false,
  "$defs": {
    "Party": {
      "type": "object",
      "required": ["id", "publicKey", "role"],
      "properties": {
        "id": {
          "type": "string",
          "minLength": 1,
          "description": "Unique identifier for this party."
        },
        "publicKey": {
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$",
          "description": "Hex-encoded Ed25519 public key (32 bytes)."
        },
        "role": {
          "type": "string",
          "enum": ["issuer", "beneficiary"],
          "description": "The role this party plays."
        },
        "name": {
          "type": "string",
          "minLength": 1,
          "description": "Optional human-readable name."
        },
        "metadata": {
          "type": "object",
          "description": "Arbitrary metadata."
        }
      },
      "additionalProperties": false
    },
    "ChainReference": {
      "type": "object",
      "required": ["parentId", "relation", "depth"],
      "properties": {
        "parentId": {
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$",
          "description": "SHA-256 ID of the parent covenant document."
        },
        "relation": {
          "type": "string",
          "enum": ["delegates", "restricts", "extends"],
          "description": "How this covenant relates to its parent."
        },
        "depth": {
          "type": "integer",
          "minimum": 1,
          "maximum": 16,
          "description": "Depth in the chain (1-indexed from root)."
        }
      },
      "additionalProperties": false
    },
    "Countersignature": {
      "type": "object",
      "required": ["signerPublicKey", "signerRole", "signature", "timestamp"],
      "properties": {
        "signerPublicKey": {
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$",
          "description": "Hex-encoded Ed25519 public key of the countersigner."
        },
        "signerRole": {
          "type": "string",
          "minLength": 1,
          "description": "Role of the countersigner (e.g., 'auditor', 'regulator')."
        },
        "signature": {
          "type": "string",
          "pattern": "^[0-9a-fA-F]{128}$",
          "description": "Ed25519 signature over the canonical form."
        },
        "timestamp": {
          "type": "string",
          "format": "date-time",
          "description": "ISO 8601 UTC timestamp of countersignature creation."
        }
      },
      "additionalProperties": false
    },
    "Obligation": {
      "type": "object",
      "required": ["id", "description", "action"],
      "properties": {
        "id": {
          "type": "string",
          "minLength": 1,
          "description": "Unique identifier for this obligation."
        },
        "description": {
          "type": "string",
          "minLength": 1,
          "description": "Human-readable description."
        },
        "action": {
          "type": "string",
          "minLength": 1,
          "description": "The action required to fulfill the obligation."
        },
        "deadline": {
          "type": "string",
          "format": "date-time",
          "description": "Optional ISO 8601 UTC deadline."
        }
      },
      "additionalProperties": false
    },
    "EnforcementConfig": {
      "type": "object",
      "required": ["type", "config"],
      "properties": {
        "type": {
          "type": "string",
          "enum": ["capability", "monitor", "audit", "bond", "composite"],
          "description": "The enforcement mechanism type."
        },
        "config": {
          "type": "object",
          "description": "Type-specific configuration."
        },
        "description": {
          "type": "string",
          "description": "Human-readable description."
        }
      },
      "additionalProperties": false
    },
    "ProofConfig": {
      "type": "object",
      "required": ["type", "config"],
      "properties": {
        "type": {
          "type": "string",
          "enum": ["tee", "capability_manifest", "audit_log", "bond_reference", "zkp", "composite"],
          "description": "The proof mechanism type."
        },
        "config": {
          "type": "object",
          "description": "Type-specific configuration."
        },
        "description": {
          "type": "string",
          "description": "Human-readable description."
        }
      },
      "additionalProperties": false
    },
    "RevocationConfig": {
      "type": "object",
      "required": ["method"],
      "properties": {
        "method": {
          "type": "string",
          "enum": ["crl", "status_endpoint", "onchain"],
          "description": "The revocation method."
        },
        "endpoint": {
          "type": "string",
          "format": "uri",
          "description": "URL for revocation checking."
        },
        "config": {
          "type": "object",
          "description": "Method-specific configuration."
        }
      },
      "additionalProperties": false
    }
  }
}
```

---

*End of Specification*
