"""HTTP contract tests for the optional proofforge server."""

from typing import Any

from fastapi.testclient import TestClient

from app.main import app, engine


def _client() -> TestClient:
    return TestClient(app)


def test_health_reports_service_identity() -> None:
    response = _client().get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "cruzx-proofforge"}


def test_create_proof_returns_signed_artifact() -> None:
    payload: dict[str, Any] = {
        "change_id": "http-1",
        "tests_passed": True,
        "checks": ["unit"],
    }

    response = _client().post("/proof", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "verified"
    assert body["payload_sha256"]
    assert body["signature"]
    assert body["version"]

    # The artifact must actually verify against the payload that produced it.
    assert engine.verify(body, payload) is True


def test_signed_artifact_does_not_verify_for_tampered_payload() -> None:
    payload: dict[str, Any] = {
        "change_id": "http-2",
        "tests_passed": True,
        "checks": ["unit"],
    }

    body = _client().post("/proof", json=payload).json()

    tampered = {**payload, "tests_passed": False}
    assert engine.verify(body, tampered) is False


def test_create_proof_rejects_non_object_body() -> None:
    response = _client().post("/proof", json=["not", "an", "object"])

    assert response.status_code == 422
