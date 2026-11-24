# CruzX ProofForge

![CI](https://github.com/dhe-cruzer69/Apollox3/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

**Proof artifacts for AI-assisted code changes — with explicit evidence boundaries.**

ProofForge is an early-stage Python project that hashes a caller-supplied change payload and creates an HMAC-SHA256 integrity signature. It includes a small FastAPI endpoint and a local proof-format acceptance script.

## Current capability boundary

**Implemented in the inspected source:**
- Canonical JSON serialization and SHA-256 payload digest.
- HMAC-SHA256 signature generation and verification.
- Required strong signing key from `CRUZX_SIGNING_KEY` or an explicit constructor argument.
- Constant-time signature comparison.
- FastAPI `/health` and `/proof` endpoints.

**Not established by this repository's current implementation:**
- Independent execution or validation of the tests listed in a payload.
- GitHub PR checks, comments, merge gates, or GitHub App integration.
- Cosign signatures, SLSA provenance, SBOM publication, or external attestation verification.
- Language-agnostic verification adapters.
- A 90% coverage floor or third-party OpenSSF score.

A valid HMAC proves that the signed manifest has not changed relative to the key holder's assertion. It does **not** prove that the asserted tests ran or passed. The `status` field reflects the caller-supplied `tests_passed` boolean and defaults to `failed` when that evidence is absent.

## Local setup

Requires Python 3.11 or later.

```bash
python -m venv .venv
# Activate the environment using the command for your shell.
python -m pip install -e ".[dev]"
python -m pytest -q
```

Generate a strong signing key and keep it outside source control:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Set the returned value as `CRUZX_SIGNING_KEY` in your process environment or secret manager. Never commit the key or paste it into issues, logs, or examples.

Run the optional API:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The API returns HTTP 503 for proof generation when a valid signing key is not configured.

## Proof verification model

A proof manifest includes:
- `payload_sha256`: SHA-256 of canonicalized JSON input.
- `signature`: HMAC-SHA256 over the payload digest.
- `key_id`: non-secret fingerprint derived from the signing key.
- `status`: a representation of the caller-provided test assertion.

The verifier needs the same signing key. Key rotation and long-term verification-key management are not implemented yet.

## CI and artifact boundary

The GitHub Actions workflow runs lint, strict type checking, tests, secret scanning, dependency audit, Bandit and a local acceptance script. Its artifact-packaging job uploads a placeholder file; this is **not** a provenance attestation. CI does not require OIDC or repository write permissions for that step.

## Security limitations

- The current proof system is a single-key HMAC design, not a public-key signature or third-party attestation.
- No key rotation, revocation, multi-tenant key isolation, external trust store, or durable verification service is implemented.
- The local acceptance script uses an ephemeral demonstration key and simulated input; it is a format check, not evidence of external test execution.
- Treat this repository as a prototype until the remaining trust, API, storage and integration controls are implemented and independently verified.

## License

Apache-2.0
