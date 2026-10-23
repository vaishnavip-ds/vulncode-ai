from __future__ import annotations

import hashlib
import hmac


def verify_github_signature(payload: bytes, signature_header: str | None, secret: str) -> bool:
    """Verify GitHub's X-Hub-Signature-256 value without timing leaks."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def verify_bearer_token(authorization: str | None, expected_token: str) -> bool:
    if not authorization or not authorization.startswith("Bearer "):
        return False
    supplied = authorization.removeprefix("Bearer ").strip()
    return bool(supplied) and hmac.compare_digest(supplied, expected_token)

