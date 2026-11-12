"""Core proof generation and signing logic."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any


class ProofEngine:
    """Generate signed proof.json artifacts for AI-generated changes."""

    def __init__(self, signing_key: str | None = None) -> None:
        key = signing_key or os.getenv("CRUZX_SIGNING_KEY") or "local-dev-key"
        self.signing_key: str = key

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a proof artifact from a change description."""
        content = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(content.encode()).hexdigest()
        signature = self._sign(digest)

        proof = {
            "version": "1.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "payload_sha256": digest,
            "signature": signature,
            "signed_by": (
                self.signing_key[:16] + "…" if len(self.signing_key) > 16 else self.signing_key
            ),
            "checks": payload.get("checks", ["unit", "integration"]),
            "status": "verified" if payload.get("tests_passed", True) else "failed",
            "policy": payload.get("policy", {}),
        }
        return proof

    def _sign(self, digest: str) -> str:
        """Simple HMAC-style signature for local/dev; CI uses cosign."""
        material = f"{self.signing_key}:{digest}".encode()
        return hashlib.sha256(material).hexdigest()

    def verify(self, proof: dict[str, Any], original_payload: dict[str, Any]) -> bool:
        """Verify a proof against the original payload."""
        content = json.dumps(original_payload, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(content.encode()).hexdigest()
        if proof.get("payload_sha256") != expected:
            return False
        expected_sig = self._sign(expected)
        return proof.get("signature") == expected_sig
