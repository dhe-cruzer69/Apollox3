"""Unit tests for ProofEngine."""

from app.proof import ProofEngine

KEY = "cruzx-test-signing-key-with-at-least-32-bytes"


def test_generate_produces_required_fields() -> None:
    engine = ProofEngine(signing_key=KEY)
    payload = {"change_id": "abc123", "tests_passed": True, "checks": ["unit"]}
    proof = engine.generate(payload)

    assert "version" in proof
    assert "timestamp" in proof
    assert "payload_sha256" in proof
    assert "signature" in proof
    assert proof["status"] == "verified"


def test_verify_roundtrip() -> None:
    engine = ProofEngine(signing_key=KEY)
    payload = {"change_id": "xyz", "tests_passed": True}
    proof = engine.generate(payload)
    assert engine.verify(proof, payload) is True


def test_verify_detects_tamper() -> None:
    engine = ProofEngine(signing_key=KEY)
    payload = {"change_id": "xyz", "tests_passed": True}
    proof = engine.generate(payload)
    proof["payload_sha256"] = "deadbeef" * 8
    assert engine.verify(proof, payload) is False


def test_failed_status() -> None:
    engine = ProofEngine(signing_key=KEY)
    proof = engine.generate({"tests_passed": False})
    assert proof["status"] == "failed"
