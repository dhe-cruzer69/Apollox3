"""Minimal FastAPI surface for Proofforge (optional local server)."""

import os
from typing import Any

from fastapi import FastAPI, HTTPException

from app.proof import ProofEngine

app = FastAPI(
    title="cruzx-proofforge",
    description="Generate HMAC-protected proof manifests from supplied change evidence.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "cruzx-proofforge"}


@app.post("/proof")
def create_proof(payload: dict[str, Any]) -> dict[str, Any]:
    """Create a proof manifest only when a strong signing key is configured."""
    signing_key = os.getenv("CRUZX_SIGNING_KEY")
    if not signing_key:
        raise HTTPException(
            status_code=503,
            detail="Proof signing is not configured; set CRUZX_SIGNING_KEY",
        )
    try:
        engine = ProofEngine(signing_key=signing_key)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="Proof signing key is invalid") from exc
    return engine.generate(payload)
