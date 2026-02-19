"""
Comprehensive test suite for the Kova protocol Python implementation.

Covers: crypto, CCL, covenant, identity, and store modules.
"""

from __future__ import annotations

import json
import re
import time

import pytest

from kova import crypto, ccl, covenant, identity, store


# ==========================================================================
# Crypto tests
# ==========================================================================

class TestKeyPairGeneration:
    """Key pair generation and deterministic derivation."""

    def test_generate_key_pair_returns_correct_structure(self):
        kp = crypto.generate_key_pair()
        assert "private_key" in kp
        assert "public_key" in kp
        assert "public_key_hex" in kp

    def test_generate_key_pair_correct_sizes(self):
        kp = crypto.generate_key_pair()
        assert len(kp["private_key"]) == 32
        assert len(kp["public_key"]) == 32
        assert len(kp["public_key_hex"]) == 64

    def test_generate_key_pair_is_random(self):
        kp1 = crypto.generate_key_pair()
        kp2 = crypto.generate_key_pair()
        assert kp1["private_key"] != kp2["private_key"]
        assert kp1["public_key"] != kp2["public_key"]

    def test_key_pair_from_private_key_deterministic(self):
        kp = crypto.generate_key_pair()
        kp2 = crypto.key_pair_from_private_key(kp["private_key"])
        assert kp2["public_key"] == kp["public_key"]
        assert kp2["public_key_hex"] == kp["public_key_hex"]

    def test_key_pair_from_private_key_invalid_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            crypto.key_pair_from_private_key(b"\x00" * 16)

    def test_key_pair_from_private_key_wrong_type(self):
        with pytest.raises(ValueError):
            crypto.key_pair_from_private_key("not bytes")  # type: ignore

    def test_public_key_hex_is_lowercase_hex(self):
        kp = crypto.generate_key_pair()
        assert re.fullmatch(r"[0-9a-f]{64}", kp["public_key_hex"])


class TestSignAndVerify:
    """Sign/verify round-trip."""

    def test_sign_and_verify_round_trip(self):
        kp = crypto.generate_key_pair()
        message = b"hello kova"
        sig = crypto.sign(message, kp["private_key"])
        assert len(sig) == 64
        assert crypto.verify(message, sig, kp["public_key"]) is True

    def test_verify_wrong_message_returns_false(self):
        kp = crypto.generate_key_pair()
        sig = crypto.sign(b"correct message", kp["private_key"])
        assert crypto.verify(b"wrong message", sig, kp["public_key"]) is False

    def test_verify_wrong_key_returns_false(self):
        kp1 = crypto.generate_key_pair()
        kp2 = crypto.generate_key_pair()
        sig = crypto.sign(b"message", kp1["private_key"])
        assert crypto.verify(b"message", sig, kp2["public_key"]) is False

    def test_verify_tampered_signature_returns_false(self):
        kp = crypto.generate_key_pair()
        sig = bytearray(crypto.sign(b"message", kp["private_key"]))
        sig[0] ^= 0xFF
        assert crypto.verify(b"message", bytes(sig), kp["public_key"]) is False

    def test_verify_never_raises_on_bad_input(self):
        # Empty inputs should return False, not raise
        assert crypto.verify(b"", b"", b"") is False
        # Truncated signature (not 64 bytes) should return False
        assert crypto.verify(b"msg", b"\x01" * 32, b"\x02" * 32) is False
        # Garbage of correct size should return False (for non-trivial key)
        assert crypto.verify(b"msg", b"\xff" * 64, b"\x01" * 32) is False

    def test_sign_string(self):
        kp = crypto.generate_key_pair()
        sig = crypto.sign_string("hello", kp["private_key"])
        assert len(sig) == 64
        assert crypto.verify("hello".encode("utf-8"), sig, kp["public_key"]) is True

    def test_sign_string_type_check(self):
        kp = crypto.generate_key_pair()
        with pytest.raises(TypeError, match="str"):
            crypto.sign_string(123, kp["private_key"])  # type: ignore

    def test_sign_type_check(self):
        kp = crypto.generate_key_pair()
        with pytest.raises(TypeError, match="bytes"):
            crypto.sign("not bytes", kp["private_key"])  # type: ignore


class TestSha256:
    """SHA-256 hashing."""

    def test_sha256_known_value(self):
        # SHA-256 of empty string
        assert crypto.sha256(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_sha256_hello(self):
        result = crypto.sha256(b"hello")
        assert len(result) == 64
        assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_sha256_string(self):
        result = crypto.sha256_string("hello")
        assert result == crypto.sha256(b"hello")

    def test_sha256_object_key_order_independent(self):
        h1 = crypto.sha256_object({"b": 2, "a": 1})
        h2 = crypto.sha256_object({"a": 1, "b": 2})
        assert h1 == h2

    def test_sha256_object_nested(self):
        h1 = crypto.sha256_object({"outer": {"z": 1, "a": 2}})
        h2 = crypto.sha256_object({"outer": {"a": 2, "z": 1}})
        assert h1 == h2


class TestCanonicalization:
    """JSON canonicalization (key sorting, nested objects, arrays)."""

    def test_canonicalize_sorts_keys(self):
        result = crypto.canonicalize_json({"z": 1, "a": 2})
        assert result == '{"a":2,"z":1}'

    def test_canonicalize_nested_objects(self):
        result = crypto.canonicalize_json({"b": {"z": 1, "a": 2}, "a": 3})
        assert result == '{"a":3,"b":{"a":2,"z":1}}'

    def test_canonicalize_arrays_preserved(self):
        result = crypto.canonicalize_json({"arr": [3, 1, 2]})
        assert result == '{"arr":[3,1,2]}'

    def test_canonicalize_arrays_with_objects(self):
        result = crypto.canonicalize_json([{"b": 1, "a": 2}])
        assert result == '[{"a":2,"b":1}]'

    def test_canonicalize_null(self):
        result = crypto.canonicalize_json(None)
        assert result == "null"

    def test_canonicalize_booleans(self):
        result = crypto.canonicalize_json({"t": True, "f": False})
        assert result == '{"f":false,"t":true}'

    def test_canonicalize_strings(self):
        result = crypto.canonicalize_json("hello")
        assert result == '"hello"'

    def test_canonicalize_omits_none_values(self):
        result = crypto.canonicalize_json({"a": 1, "b": None})
        assert result == '{"a":1}'

    def test_canonicalize_empty_object(self):
        result = crypto.canonicalize_json({})
        assert result == "{}"


class TestHexConversion:
    """Hex encoding/decoding."""

    def test_to_hex(self):
        assert crypto.to_hex(b"\xff\x00") == "ff00"

    def test_from_hex(self):
        assert crypto.from_hex("ff00") == b"\xff\x00"

    def test_roundtrip(self):
        data = b"\xde\xad\xbe\xef"
        assert crypto.from_hex(crypto.to_hex(data)) == data

    def test_from_hex_odd_length_raises(self):
        with pytest.raises(ValueError, match="odd length"):
            crypto.from_hex("abc")

    def test_to_hex_non_bytes_raises(self):
        with pytest.raises(TypeError):
            crypto.to_hex("not bytes")  # type: ignore


class TestNonce:
    """Nonce generation."""

    def test_generate_nonce_size(self):
        nonce = crypto.generate_nonce()
        assert len(nonce) == 32

    def test_generate_nonce_is_random(self):
        n1 = crypto.generate_nonce()
        n2 = crypto.generate_nonce()
        assert n1 != n2


class TestConstantTimeEqual:
    """Constant-time comparison."""

    def test_equal_bytes(self):
        assert crypto.constant_time_equal(b"hello", b"hello") is True

    def test_unequal_bytes(self):
        assert crypto.constant_time_equal(b"hello", b"world") is False

    def test_different_length(self):
        assert crypto.constant_time_equal(b"short", b"longer") is False


class TestTimestamp:
    """Timestamp generation."""

    def test_timestamp_format(self):
        ts = crypto.timestamp()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", ts)

    def test_timestamp_is_utc(self):
        ts = crypto.timestamp()
        assert ts.endswith("Z")


# ==========================================================================
# CCL tests
# ==========================================================================

class TestCCLParsing:
    """CCL parsing all statement types."""

    def test_parse_empty_raises(self):
        with pytest.raises(ccl.CCLSyntaxError):
            ccl.parse("")

    def test_parse_whitespace_only_raises(self):
        with pytest.raises(ccl.CCLSyntaxError):
            ccl.parse("   \n   ")

    def test_parse_permit(self):
        doc = ccl.parse("permit read on '/data/**'")
        assert len(doc.permits) == 1
        assert doc.permits[0].action == "read"
        assert doc.permits[0].resource == "/data/**"
        assert doc.permits[0].type == "permit"

    def test_parse_deny(self):
        doc = ccl.parse("deny write on '/secret/**'")
        assert len(doc.denies) == 1
        assert doc.denies[0].action == "write"
        assert doc.denies[0].resource == "/secret/**"

    def test_parse_require(self):
        doc = ccl.parse("require audit.log on '/data/**'")
        assert len(doc.obligations) == 1
        assert doc.obligations[0].action == "audit.log"
        assert doc.obligations[0].resource == "/data/**"
        assert doc.obligations[0].type == "require"

    def test_parse_limit(self):
        doc = ccl.parse("limit api.call 100 per 1 hours")
        assert len(doc.limits) == 1
        assert doc.limits[0].action == "api.call"
        assert doc.limits[0].count == 100
        assert doc.limits[0].period_seconds == 3600

    def test_parse_limit_seconds(self):
        doc = ccl.parse("limit api.call 10 per 30 seconds")
        assert doc.limits[0].period_seconds == 30

    def test_parse_limit_minutes(self):
        doc = ccl.parse("limit api.call 50 per 5 minutes")
        assert doc.limits[0].period_seconds == 300

    def test_parse_limit_days(self):
        doc = ccl.parse("limit api.call 1000 per 1 days")
        assert doc.limits[0].period_seconds == 86400

    def test_parse_multiple_statements(self):
        source = "permit read on '/data/**'\ndeny write on '/secret/**'\nrequire audit on '/data/**'"
        doc = ccl.parse(source)
        assert len(doc.permits) == 1
        assert len(doc.denies) == 1
        assert len(doc.obligations) == 1
        assert len(doc.statements) == 3

    def test_parse_permit_with_condition(self):
        doc = ccl.parse("permit read on '/data/**' when user.role = 'admin'")
        stmt = doc.permits[0]
        assert stmt.condition is not None
        assert isinstance(stmt.condition, ccl.Condition)
        assert stmt.condition.field == "user.role"
        assert stmt.condition.operator == "="
        assert stmt.condition.value == "admin"

    def test_parse_permit_with_severity(self):
        doc = ccl.parse("permit read on '/data/**' severity critical")
        assert doc.permits[0].severity == "critical"

    def test_parse_wildcard_action(self):
        doc = ccl.parse("permit * on '/data/**'")
        assert doc.permits[0].action == "*"

    def test_parse_double_wildcard_action(self):
        doc = ccl.parse("permit ** on '/data/**'")
        assert doc.permits[0].action == "**"

    def test_parse_dotted_action(self):
        doc = ccl.parse("permit file.read.all on '/data/**'")
        assert doc.permits[0].action == "file.read.all"

    def test_parse_resource_path(self):
        doc = ccl.parse("permit read on /data/users")
        assert doc.permits[0].resource == "/data/users"

    def test_parse_comments_ignored(self):
        source = "# this is a comment\npermit read on '/data/**'"
        doc = ccl.parse(source)
        assert len(doc.permits) == 1

    def test_parse_compound_and_condition(self):
        doc = ccl.parse("permit read on '/data/**' when user.role = 'admin' and env = 'prod'")
        stmt = doc.permits[0]
        assert isinstance(stmt.condition, ccl.CompoundCondition)
        assert stmt.condition.type == "and"
        assert len(stmt.condition.conditions) == 2

    def test_parse_compound_or_condition(self):
        doc = ccl.parse("permit read on '/data/**' when user.role = 'admin' or user.role = 'editor'")
        stmt = doc.permits[0]
        assert isinstance(stmt.condition, ccl.CompoundCondition)
        assert stmt.condition.type == "or"
        assert len(stmt.condition.conditions) == 2


class TestCCLActionMatching:
    """CCL action pattern matching."""

    def test_exact_match(self):
        assert ccl.match_action("read", "read") is True
        assert ccl.match_action("read", "write") is False

    def test_wildcard_single(self):
        assert ccl.match_action("file.*", "file.read") is True
        assert ccl.match_action("file.*", "file.read.all") is False

    def test_double_wildcard(self):
        assert ccl.match_action("**", "anything.here") is True
        assert ccl.match_action("file.**", "file.read.all") is True
        assert ccl.match_action("file.**", "file") is True

    def test_dotted_exact(self):
        assert ccl.match_action("file.read", "file.read") is True
        assert ccl.match_action("file.read", "file.write") is False


class TestCCLResourceMatching:
    """CCL resource pattern matching."""

    def test_exact_match(self):
        assert ccl.match_resource("/data/users", "/data/users") is True
        assert ccl.match_resource("/data/users", "/data/other") is False

    def test_wildcard_single(self):
        assert ccl.match_resource("/data/*", "/data/users") is True
        assert ccl.match_resource("/data/*", "/data/users/123") is False

    def test_double_wildcard(self):
        assert ccl.match_resource("/data/**", "/data/users/123") is True
        assert ccl.match_resource("**", "/anything/here") is True

    def test_leading_trailing_slashes(self):
        assert ccl.match_resource("/data/", "/data") is True
        assert ccl.match_resource("data", "data") is True


class TestCCLEvaluation:
    """CCL evaluation (default deny, deny wins, specificity, wildcards)."""

    def test_default_deny(self):
        doc = ccl.parse("permit read on '/allowed'")
        result = ccl.evaluate(doc, "read", "/not-allowed")
        assert result.permitted is False
        assert "default deny" in (result.reason or "").lower()

    def test_permit_match(self):
        doc = ccl.parse("permit read on '/data/**'")
        result = ccl.evaluate(doc, "read", "/data/users")
        assert result.permitted is True

    def test_deny_wins_at_same_specificity(self):
        doc = ccl.parse("permit read on '/data/**'\ndeny read on '/data/**'")
        result = ccl.evaluate(doc, "read", "/data/users")
        assert result.permitted is False

    def test_more_specific_deny_wins(self):
        doc = ccl.parse("permit read on '/data/**'\ndeny read on '/data/secret'")
        result = ccl.evaluate(doc, "read", "/data/secret")
        assert result.permitted is False

    def test_more_specific_permit_at_different_scope(self):
        doc = ccl.parse("deny read on '/data/**'\npermit read on '/data/public'")
        result = ccl.evaluate(doc, "read", "/data/public")
        assert result.permitted is True

    def test_no_matching_action(self):
        doc = ccl.parse("permit read on '/data/**'")
        result = ccl.evaluate(doc, "write", "/data/users")
        assert result.permitted is False

    def test_condition_evaluation(self):
        doc = ccl.parse("permit read on '/data/**' when user.role = 'admin'")
        result_admin = ccl.evaluate(doc, "read", "/data/users", {"user": {"role": "admin"}})
        assert result_admin.permitted is True

        result_user = ccl.evaluate(doc, "read", "/data/users", {"user": {"role": "user"}})
        assert result_user.permitted is False

    def test_evaluation_result_has_matched_rule(self):
        doc = ccl.parse("permit read on '/data/**'")
        result = ccl.evaluate(doc, "read", "/data/users")
        assert result.matched_rule is not None
        assert result.matched_rule.type == "permit"

    def test_all_matches_populated(self):
        doc = ccl.parse("permit read on '/data/**'\npermit read on '**'")
        result = ccl.evaluate(doc, "read", "/data/users")
        assert len(result.all_matches) == 2


class TestCCLRateLimit:
    """CCL rate-limit checking."""

    def test_under_limit(self):
        doc = ccl.parse("limit api.call 100 per 1 hours")
        now = int(time.time() * 1000)
        result = ccl.check_rate_limit(doc, "api.call", 50, now - 1000, now)
        assert result.exceeded is False
        assert result.remaining == 50

    def test_at_limit(self):
        doc = ccl.parse("limit api.call 100 per 1 hours")
        now = int(time.time() * 1000)
        result = ccl.check_rate_limit(doc, "api.call", 100, now - 1000, now)
        assert result.exceeded is True
        assert result.remaining == 0

    def test_period_expired(self):
        doc = ccl.parse("limit api.call 100 per 1 hours")
        now = int(time.time() * 1000)
        result = ccl.check_rate_limit(doc, "api.call", 200, now - 4_000_000, now)
        assert result.exceeded is False
        assert result.remaining == 100

    def test_no_matching_limit(self):
        doc = ccl.parse("limit api.call 100 per 1 hours")
        now = int(time.time() * 1000)
        result = ccl.check_rate_limit(doc, "other.action", 50, now - 1000, now)
        assert result.exceeded is False


class TestCCLNarrowing:
    """CCL narrowing validation."""

    def test_valid_narrowing(self):
        parent = ccl.parse("permit read on '/data/**'")
        child = ccl.parse("permit read on '/data/public'")
        result = ccl.validate_narrowing(parent, child)
        assert result.valid is True

    def test_child_broadens_parent_is_invalid(self):
        parent = ccl.parse("permit read on '/data/**'")
        child = ccl.parse("permit write on '/data/**'")
        result = ccl.validate_narrowing(parent, child)
        assert result.valid is False
        assert len(result.violations) > 0

    def test_child_permits_parent_deny_is_invalid(self):
        parent = ccl.parse("permit read on '/data/**'\ndeny read on '/data/secret'")
        child = ccl.parse("permit read on '/data/secret'")
        result = ccl.validate_narrowing(parent, child)
        assert result.valid is False


class TestCCLMerge:
    """CCL merge operation."""

    def test_merge_includes_all_denies(self):
        parent = ccl.parse("deny read on '/secret/**'")
        child = ccl.parse("deny write on '/logs/**'")
        merged = ccl.merge(parent, child)
        assert len(merged.denies) == 2

    def test_merge_includes_all_permits(self):
        parent = ccl.parse("permit read on '/data/**'")
        child = ccl.parse("permit read on '/data/public'")
        merged = ccl.merge(parent, child)
        assert len(merged.permits) == 2

    def test_merge_limits_most_restrictive(self):
        parent = ccl.parse("limit api.call 100 per 1 hours")
        child = ccl.parse("limit api.call 50 per 1 hours")
        merged = ccl.merge(parent, child)
        assert len(merged.limits) == 1
        assert merged.limits[0].count == 50


class TestCCLSerialize:
    """CCL serialization."""

    def test_serialize_roundtrip(self):
        source = "permit read on '/data/**'"
        doc = ccl.parse(source)
        serialized = ccl.serialize(doc)
        assert "permit read on '/data/**'" in serialized

    def test_serialize_limit(self):
        doc = ccl.parse("limit api.call 100 per 1 hours")
        serialized = ccl.serialize(doc)
        assert "limit api.call 100 per 1 hours" in serialized


# ==========================================================================
# Covenant tests
# ==========================================================================

def _make_parties():
    """Helper to create issuer and beneficiary key pairs + party dicts."""
    issuer_kp = crypto.generate_key_pair()
    beneficiary_kp = crypto.generate_key_pair()

    issuer_party = {
        "id": "alice",
        "publicKey": issuer_kp["public_key_hex"],
        "role": "issuer",
    }
    beneficiary_party = {
        "id": "bob",
        "publicKey": beneficiary_kp["public_key_hex"],
        "role": "beneficiary",
    }
    return issuer_kp, beneficiary_kp, issuer_party, beneficiary_party


class TestCovenantBuildVerify:
    """Covenant build/verify round-trip."""

    def test_build_and_verify(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })

        assert doc["id"]
        assert doc["signature"]
        assert doc["nonce"]
        assert doc["version"] == "1.0"
        assert doc["issuer"]["role"] == "issuer"
        assert doc["beneficiary"]["role"] == "beneficiary"

        result = covenant.verify_covenant(doc)
        assert result["valid"] is True
        assert len(result["checks"]) == 11

    def test_build_missing_issuer(self):
        with pytest.raises(covenant.CovenantBuildError, match="issuer"):
            covenant.build_covenant({
                "beneficiary": {"id": "bob", "publicKey": "aa" * 32, "role": "beneficiary"},
                "constraints": "permit read on '/data/**'",
                "privateKey": b"\x00" * 32,
            })

    def test_build_missing_constraints(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        with pytest.raises(covenant.CovenantBuildError, match="constraints"):
            covenant.build_covenant({
                "issuer": issuer_party,
                "beneficiary": beneficiary_party,
                "constraints": "",
                "privateKey": issuer_kp["private_key"],
            })

    def test_build_invalid_ccl(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        with pytest.raises(covenant.CovenantBuildError, match="Invalid CCL"):
            covenant.build_covenant({
                "issuer": issuer_party,
                "beneficiary": beneficiary_party,
                "constraints": "not_valid_ccl syntax here",
                "privateKey": issuer_kp["private_key"],
            })


class TestVerificationChecks:
    """All 11 verification checks."""

    def _build_valid_doc(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })
        return doc, issuer_kp

    def test_id_match_check(self):
        doc, _ = self._build_valid_doc()
        result = covenant.verify_covenant(doc)
        id_check = next(c for c in result["checks"] if c["name"] == "id_match")
        assert id_check["passed"] is True

    def test_id_mismatch_detected(self):
        doc, _ = self._build_valid_doc()
        doc["id"] = "0" * 64
        result = covenant.verify_covenant(doc)
        id_check = next(c for c in result["checks"] if c["name"] == "id_match")
        assert id_check["passed"] is False

    def test_signature_valid_check(self):
        doc, _ = self._build_valid_doc()
        result = covenant.verify_covenant(doc)
        sig_check = next(c for c in result["checks"] if c["name"] == "signature_valid")
        assert sig_check["passed"] is True

    def test_signature_tampered_detected(self):
        doc, _ = self._build_valid_doc()
        sig_bytes = bytearray(crypto.from_hex(doc["signature"]))
        sig_bytes[0] ^= 0xFF
        doc["signature"] = crypto.to_hex(bytes(sig_bytes))
        result = covenant.verify_covenant(doc)
        sig_check = next(c for c in result["checks"] if c["name"] == "signature_valid")
        assert sig_check["passed"] is False

    def test_not_expired_check_passes(self):
        doc, _ = self._build_valid_doc()
        result = covenant.verify_covenant(doc)
        exp_check = next(c for c in result["checks"] if c["name"] == "not_expired")
        assert exp_check["passed"] is True

    def test_expired_document_fails(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
            "expiresAt": "2020-01-01T00:00:00.000Z",
        })
        result = covenant.verify_covenant(doc)
        exp_check = next(c for c in result["checks"] if c["name"] == "not_expired")
        assert exp_check["passed"] is False

    def test_not_yet_active_fails(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
            "activatesAt": "2099-01-01T00:00:00.000Z",
        })
        result = covenant.verify_covenant(doc)
        active_check = next(c for c in result["checks"] if c["name"] == "active")
        assert active_check["passed"] is False

    def test_ccl_parses_check(self):
        doc, _ = self._build_valid_doc()
        result = covenant.verify_covenant(doc)
        ccl_check = next(c for c in result["checks"] if c["name"] == "ccl_parses")
        assert ccl_check["passed"] is True

    def test_enforcement_valid_check(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
            "enforcement": {"type": "capability", "config": {}},
        })
        result = covenant.verify_covenant(doc)
        enf_check = next(c for c in result["checks"] if c["name"] == "enforcement_valid")
        assert enf_check["passed"] is True

    def test_invalid_enforcement_type_fails(self):
        doc, _ = self._build_valid_doc()
        doc["enforcement"] = {"type": "nonexistent", "config": {}}
        result = covenant.verify_covenant(doc)
        enf_check = next(c for c in result["checks"] if c["name"] == "enforcement_valid")
        assert enf_check["passed"] is False

    def test_proof_valid_check(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
            "proof": {"type": "tee", "config": {}},
        })
        result = covenant.verify_covenant(doc)
        proof_check = next(c for c in result["checks"] if c["name"] == "proof_valid")
        assert proof_check["passed"] is True

    def test_chain_depth_check(self):
        doc, _ = self._build_valid_doc()
        result = covenant.verify_covenant(doc)
        chain_check = next(c for c in result["checks"] if c["name"] == "chain_depth")
        assert chain_check["passed"] is True

    def test_chain_depth_exceeded_fails(self):
        doc, _ = self._build_valid_doc()
        doc["chain"] = {"parentId": "a" * 64, "relation": "delegates", "depth": 99}
        result = covenant.verify_covenant(doc)
        chain_check = next(c for c in result["checks"] if c["name"] == "chain_depth")
        assert chain_check["passed"] is False

    def test_document_size_check(self):
        doc, _ = self._build_valid_doc()
        result = covenant.verify_covenant(doc)
        size_check = next(c for c in result["checks"] if c["name"] == "document_size")
        assert size_check["passed"] is True

    def test_nonce_present_check(self):
        doc, _ = self._build_valid_doc()
        result = covenant.verify_covenant(doc)
        nonce_check = next(c for c in result["checks"] if c["name"] == "nonce_present")
        assert nonce_check["passed"] is True

    def test_nonce_missing_fails(self):
        doc, _ = self._build_valid_doc()
        doc["nonce"] = ""
        result = covenant.verify_covenant(doc)
        nonce_check = next(c for c in result["checks"] if c["name"] == "nonce_present")
        assert nonce_check["passed"] is False

    def test_nonce_wrong_format_fails(self):
        doc, _ = self._build_valid_doc()
        doc["nonce"] = "not-hex"
        result = covenant.verify_covenant(doc)
        nonce_check = next(c for c in result["checks"] if c["name"] == "nonce_present")
        assert nonce_check["passed"] is False


class TestCountersignatures:
    """Countersignatures."""

    def test_countersign_and_verify(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })

        auditor_kp = crypto.generate_key_pair()
        countersigned = covenant.countersign_covenant(doc, auditor_kp, "auditor")

        assert len(countersigned.get("countersignatures", [])) == 1
        cs = countersigned["countersignatures"][0]
        assert cs["signerRole"] == "auditor"
        assert cs["signerPublicKey"] == auditor_kp["public_key_hex"]

        result = covenant.verify_covenant(countersigned)
        cs_check = next(c for c in result["checks"] if c["name"] == "countersignatures")
        assert cs_check["passed"] is True

    def test_multiple_countersignatures(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })

        auditor1 = crypto.generate_key_pair()
        auditor2 = crypto.generate_key_pair()
        doc = covenant.countersign_covenant(doc, auditor1, "auditor")
        doc = covenant.countersign_covenant(doc, auditor2, "regulator")

        assert len(doc.get("countersignatures", [])) == 2

        result = covenant.verify_covenant(doc)
        cs_check = next(c for c in result["checks"] if c["name"] == "countersignatures")
        assert cs_check["passed"] is True

    def test_invalid_countersignature_detected(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })

        auditor_kp = crypto.generate_key_pair()
        doc = covenant.countersign_covenant(doc, auditor_kp, "auditor")

        # Tamper with the countersignature
        sig_bytes = bytearray(crypto.from_hex(doc["countersignatures"][0]["signature"]))
        sig_bytes[0] ^= 0xFF
        doc["countersignatures"][0]["signature"] = crypto.to_hex(bytes(sig_bytes))

        result = covenant.verify_covenant(doc)
        cs_check = next(c for c in result["checks"] if c["name"] == "countersignatures")
        assert cs_check["passed"] is False


class TestChainNarrowing:
    """Chain narrowing validation."""

    def test_valid_narrowing(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        parent = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })
        child = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/public'",
            "privateKey": issuer_kp["private_key"],
        })

        result = covenant.validate_chain_narrowing(child, parent)
        assert result["valid"] is True

    def test_invalid_narrowing(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        parent = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })
        child = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit write on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })

        result = covenant.validate_chain_narrowing(child, parent)
        assert result["valid"] is False
        assert len(result["violations"]) > 0


class TestCovenantSerialization:
    """Covenant serialization round-trips."""

    def test_serialize_deserialize_roundtrip(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })

        json_str = covenant.serialize_covenant(doc)
        restored = covenant.deserialize_covenant(json_str)

        assert restored["id"] == doc["id"]
        assert restored["signature"] == doc["signature"]
        assert restored["constraints"] == doc["constraints"]
        assert restored["issuer"]["id"] == doc["issuer"]["id"]

    def test_deserialize_invalid_json(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            covenant.deserialize_covenant("not json {{{")

    def test_deserialize_missing_fields(self):
        with pytest.raises(ValueError, match="Missing"):
            covenant.deserialize_covenant('{"id": "abc"}')

    def test_deserialize_wrong_version(self):
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })
        json_str = covenant.serialize_covenant(doc)
        data = json.loads(json_str)
        data["version"] = "999.0"
        with pytest.raises(ValueError, match="Unsupported protocol version"):
            covenant.deserialize_covenant(json.dumps(data))


# ==========================================================================
# Identity tests
# ==========================================================================

def _make_identity_options():
    """Helper to create identity creation options."""
    kp = crypto.generate_key_pair()
    return {
        "operatorKeyPair": kp,
        "model": {"provider": "anthropic", "modelId": "claude-3"},
        "capabilities": ["read", "write"],
        "deployment": {"runtime": "container"},
    }


class TestIdentityCreation:
    """Identity creation."""

    def test_create_identity(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)

        assert ident["id"]
        assert ident["signature"]
        assert ident["version"] == 1
        assert len(ident["lineage"]) == 1
        assert ident["lineage"][0]["changeType"] == "created"
        assert ident["lineage"][0]["parentHash"] is None
        assert ident["operatorPublicKey"] == options["operatorKeyPair"]["public_key_hex"]
        assert ident["capabilities"] == sorted(options["capabilities"])

    def test_create_identity_missing_model(self):
        options = _make_identity_options()
        del options["model"]
        with pytest.raises(ValueError, match="model"):
            identity.create_identity(options)

    def test_create_identity_missing_capabilities(self):
        options = _make_identity_options()
        del options["capabilities"]
        with pytest.raises(ValueError, match="capabilities"):
            identity.create_identity(options)

    def test_capabilities_are_sorted(self):
        options = _make_identity_options()
        options["capabilities"] = ["write", "admin", "read"]
        ident = identity.create_identity(options)
        assert ident["capabilities"] == ["admin", "read", "write"]


class TestIdentityEvolution:
    """Identity evolution."""

    def test_evolve_identity(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)

        evolved = identity.evolve_identity(ident, {
            "operatorKeyPair": options["operatorKeyPair"],
            "changeType": "capability_change",
            "description": "Added admin capability",
            "updates": {"capabilities": ["read", "write", "admin"]},
        })

        assert evolved["version"] == 2
        assert len(evolved["lineage"]) == 2
        assert evolved["lineage"][1]["changeType"] == "capability_change"
        assert evolved["lineage"][1]["parentHash"] == ident["lineage"][0]["identityHash"]
        assert "admin" in evolved["capabilities"]

    def test_evolve_preserves_created_at(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)

        # Force a different createdAt to guarantee the timestamps differ
        import time
        time.sleep(0.002)  # sleep 2ms to ensure timestamp changes

        evolved = identity.evolve_identity(ident, {
            "operatorKeyPair": options["operatorKeyPair"],
            "changeType": "model_update",
            "description": "Updated model",
            "updates": {"model": {"provider": "anthropic", "modelId": "claude-4"}},
        })

        # createdAt is preserved from the original
        assert evolved["createdAt"] == ident["createdAt"]
        # updatedAt should be set (it might be same or different depending on timing;
        # the key invariant is that createdAt is carried forward)
        assert "updatedAt" in evolved


class TestIdentityVerification:
    """Identity verification."""

    def test_verify_valid_identity(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)
        result = identity.verify_identity(ident)
        assert result["valid"] is True
        for check in result["checks"]:
            assert check["passed"] is True, f"Check {check['name']} failed: {check['message']}"

    def test_verify_evolved_identity(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)

        evolved = identity.evolve_identity(ident, {
            "operatorKeyPair": options["operatorKeyPair"],
            "changeType": "capability_change",
            "description": "Added admin",
            "updates": {"capabilities": ["read", "write", "admin"]},
        })

        result = identity.verify_identity(evolved)
        assert result["valid"] is True

    def test_verify_tampered_id_fails(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)
        ident["id"] = "0" * 64
        result = identity.verify_identity(ident)
        assert result["valid"] is False

    def test_verify_tampered_signature_fails(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)
        sig_bytes = bytearray(crypto.from_hex(ident["signature"]))
        sig_bytes[0] ^= 0xFF
        ident["signature"] = crypto.to_hex(bytes(sig_bytes))
        result = identity.verify_identity(ident)
        assert result["valid"] is False

    def test_verify_version_mismatch_fails(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)
        ident["version"] = 99
        result = identity.verify_identity(ident)
        assert result["valid"] is False
        version_check = next(c for c in result["checks"] if c["name"] == "version_lineage_match")
        assert version_check["passed"] is False

    def test_verify_capability_hash_mismatch_fails(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)
        ident["capabilityManifestHash"] = "0" * 64
        result = identity.verify_identity(ident)
        assert result["valid"] is False


class TestIdentitySerialization:
    """Identity serialization round-trips."""

    def test_serialize_deserialize_roundtrip(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)

        json_str = identity.serialize_identity(ident)
        restored = identity.deserialize_identity(json_str)

        assert restored["id"] == ident["id"]
        assert restored["signature"] == ident["signature"]
        assert restored["operatorPublicKey"] == ident["operatorPublicKey"]
        assert restored["version"] == ident["version"]

    def test_deserialize_invalid_json(self):
        with pytest.raises(ValueError, match="Invalid"):
            identity.deserialize_identity("not json")

    def test_deserialize_missing_field(self):
        with pytest.raises(ValueError, match="missing required field"):
            identity.deserialize_identity('{"id": "test"}')

    def test_deserialize_empty_string(self):
        with pytest.raises(ValueError, match="non-empty"):
            identity.deserialize_identity("")

    def test_compute_identity_hash_deterministic(self):
        options = _make_identity_options()
        ident = identity.create_identity(options)
        rest = {k: v for k, v in ident.items() if k not in ("id", "signature")}
        h1 = identity.compute_identity_hash(rest)
        h2 = identity.compute_identity_hash(rest)
        assert h1 == h2
        assert h1 == ident["id"]


# ==========================================================================
# Store tests
# ==========================================================================

class TestMemoryStore:
    """MemoryStore for covenant storage."""

    def test_put_and_get(self):
        s = store.MemoryStore()
        doc = {"id": "abc123", "data": "test"}
        s.put("abc123", doc)
        result = s.get("abc123")
        assert result is not None
        assert result["data"] == "test"

    def test_get_nonexistent_returns_none(self):
        s = store.MemoryStore()
        assert s.get("nonexistent") is None

    def test_has(self):
        s = store.MemoryStore()
        s.put("abc", {"id": "abc"})
        assert s.has("abc") is True
        assert s.has("xyz") is False

    def test_delete(self):
        s = store.MemoryStore()
        s.put("abc", {"id": "abc"})
        assert s.delete("abc") is True
        assert s.has("abc") is False
        assert s.delete("abc") is False

    def test_list(self):
        s = store.MemoryStore()
        s.put("a", {"id": "a"})
        s.put("b", {"id": "b"})
        docs = s.list()
        assert len(docs) == 2

    def test_count(self):
        s = store.MemoryStore()
        assert s.count() == 0
        s.put("a", {"id": "a"})
        assert s.count() == 1
        s.put("b", {"id": "b"})
        assert s.count() == 2

    def test_defensive_copy_on_put(self):
        s = store.MemoryStore()
        doc = {"id": "abc", "data": "original"}
        s.put("abc", doc)
        doc["data"] = "mutated"
        result = s.get("abc")
        assert result["data"] == "original"

    def test_defensive_copy_on_get(self):
        s = store.MemoryStore()
        s.put("abc", {"id": "abc", "data": "original"})
        result = s.get("abc")
        result["data"] = "mutated"
        result2 = s.get("abc")
        assert result2["data"] == "original"

    def test_put_empty_id_raises(self):
        s = store.MemoryStore()
        with pytest.raises(ValueError, match="non-empty"):
            s.put("", {"id": ""})

    def test_get_empty_id_raises(self):
        s = store.MemoryStore()
        with pytest.raises(ValueError, match="non-empty"):
            s.get("")

    def test_delete_empty_id_raises(self):
        s = store.MemoryStore()
        with pytest.raises(ValueError, match="non-empty"):
            s.delete("")

    def test_put_non_dict_raises(self):
        s = store.MemoryStore()
        with pytest.raises(ValueError, match="dict"):
            s.put("abc", "not a dict")  # type: ignore

    def test_store_with_real_covenant(self):
        """Integration: store a real covenant document."""
        issuer_kp, _, issuer_party, beneficiary_party = _make_parties()
        doc = covenant.build_covenant({
            "issuer": issuer_party,
            "beneficiary": beneficiary_party,
            "constraints": "permit read on '/data/**'",
            "privateKey": issuer_kp["private_key"],
        })

        s = store.MemoryStore()
        s.put(doc["id"], doc)

        retrieved = s.get(doc["id"])
        assert retrieved is not None
        assert retrieved["id"] == doc["id"]

        result = covenant.verify_covenant(retrieved)
        assert result["valid"] is True
