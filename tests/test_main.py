"""HTTP contract tests for the optional proofforge server."""

from typing import Any

from fastapi.testclient import TestClient

from app.main import app


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


def test_create_proof_rejects_non_object_body() -> None:
    response = _client().post("/proof", json=["not", "an", "object"])

    assert response.status_code == 422
