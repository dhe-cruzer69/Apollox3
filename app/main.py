"""Minimal FastAPI surface for proofforge (optional local server)."""

from typing import Any

from fastapi import FastAPI

from app.proof import ProofEngine

app = FastAPI(
    title="cruzx-proofforge",
    description="Don’t merge AI code until it proves itself.",
    version="0.1.0",
)

engine = ProofEngine()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "cruzx-proofforge"}


@app.post("/proof")
def create_proof(payload: dict[str, Any]) -> dict[str, Any]:
    """Accept a change description and return a signed proof skeleton."""
    return engine.generate(payload)
