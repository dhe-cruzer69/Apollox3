"""Keyed proof generation and verification for local proof artifacts."""

from __future__ import annotations

from datetime import UTC, datetime

import hashlib
import hmac
import json
import os
from typing import Any


MIN_SIGNING_KEY_BYTES = 32


class ProofEngine:
    """Generate HMAC-SHA256 proof manifests for caller-supplied change evidence.

    A valid signature protects manifest integrity. It does not independently prove
    that the listed tests or checks were executed.
    """

    def __init__(self, signing_key: str | None = None) -> None:
        key = signing_key if signing_key is not None else os.getenv("CRUZX_SIGNING_KEY")
        if not isinstance(key, str) or not key:
            raise ValueError("CRUZX_SIGNING_KEY or an explicit signing_key is required")
        key_bytes = key.encode("utf-8")
        if len(key_bytes) < MIN_SIGNING_KEY_BYTES:
            raise ValueError("signing key must contain at least 32 bytes")
        self._signing_key = key_bytes
        self._key_id = hashlib.sha256(key_bytes).hexdigest()[:16]

    def generate(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a proof artifact from a change description and declared checks."""
        content = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return {
            "version": "1.1",
            "timestamp": datetime.now(UTC).isoformat(),
            "payload_sha256": digest,
            "signature": self._sign(digest),
            "key_id": self._key_id,
            "checks": payload.get("checks", []),
            "status": "verified" if payload.get("tests_passed") is True else "failed",
            "policy": payload.get("policy", {}),
        }

    def _sign(self, digest: str) -> str:
        """Return an HMAC-SHA256 signature over the canonical payload digest."""
        return hmac.new(
            self._signing_key,
            digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, proof: dict[str, Any], original_payload: dict[str, Any]) -> bool:
        """Verify payload digest and HMAC signature without timing-sensitive equality."""
        content = json.dumps(original_payload, sort_keys=True, separators=(",", ":"))
        expected_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(str(proof.get("payload_sha256", "")), expected_digest):
            return False
        expected_signature = self._sign(expected_digest)
        return hmac.compare_digest(str(proof.get("signature", "")), expected_signature)
