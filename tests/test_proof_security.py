from __future__ import annotations

import hashlib
import hmac

import pytest

from app.proof import ProofEngine

KEY = "cruzx-test-signing-key-with-at-least-32-bytes"


def test_signing_key_is_required() -> None:
    with pytest.raises(ValueError, match="CRUZX_SIGNING_KEY"):
        ProofEngine(signing_key="")


def test_rejects_weak_signing_key() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        ProofEngine(signing_key="short")


def test_signature_uses_hmac_sha256() -> None:
    engine = ProofEngine(signing_key=KEY)
    payload = {"change_id": "hmac-test", "tests_passed": True}
    proof = engine.generate(payload)
    digest = hashlib.sha256(
        __import__("json").dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    expected = hmac.new(KEY.encode(), digest.encode(), hashlib.sha256).hexdigest()
    assert proof["signature"] == expected


def test_proof_does_not_disclose_signing_key() -> None:
    engine = ProofEngine(signing_key=KEY)
    proof = engine.generate({"tests_passed": True})
    assert KEY not in repr(proof)
    assert KEY[:16] not in repr(proof)
    assert "key_id" in proof
    assert "signed_by" not in proof


def test_missing_test_evidence_fails_closed() -> None:
    engine = ProofEngine(signing_key=KEY)
    proof = engine.generate({"change_id": "unknown-evidence"})
    assert proof["status"] == "failed"


def test_verify_rejects_signature_tampering() -> None:
    engine = ProofEngine(signing_key=KEY)
    payload = {"change_id": "verify", "tests_passed": True}
    proof = engine.generate(payload)
    proof["signature"] = "0" * 64
    assert engine.verify(proof, payload) is False
