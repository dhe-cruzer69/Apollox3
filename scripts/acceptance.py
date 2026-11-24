#!/usr/bin/env python3
"""Local consistency check for the HMAC proof format.

This script uses an ephemeral demonstration key and simulated input. It does not
prove that an external customer's tests were executed or provide durable signature
verification after the process exits.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

# Ensure package is importable.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.proof import ProofEngine


def main() -> int:
    engine = ProofEngine(signing_key=secrets.token_hex(32))
    sample_payload = {
        "change_id": "demo-ai-patch-001",
        "files": ["src/example.py"],
        "tests_passed": True,
        "checks": ["unit", "integration"],
        "policy": {
            "required_checks": ["unit", "integration"],
            "fail_on_regression": True,
            "max_allowed_coverage_drop": 2,
        },
    }

    proof = engine.generate(sample_payload)
    if not engine.verify(proof, sample_payload):
        print("FAIL: proof verification failed")
        return 1

    required = ["version", "timestamp", "payload_sha256", "signature", "key_id", "status"]
    missing = [key for key in required if key not in proof]
    if missing:
        print(f"FAIL: missing fields {missing}")
        return 1

    if proof["status"] != "verified":
        print("FAIL: proof status does not reflect the supplied test assertion")
        return 1

    out = Path("proof.json")
    out.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote locally verifiable demo artifact {out} (ephemeral key; not independently verifiable)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
