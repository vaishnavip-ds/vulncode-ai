from app.core.security import verify_bearer_token, verify_github_signature


def test_github_official_signature_vector() -> None:
    secret = "It's a Secret to Everybody"
    payload = b"Hello, World!"
    signature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
    assert verify_github_signature(payload, signature, secret)


def test_rejects_bad_signature() -> None:
    assert not verify_github_signature(b"payload", "sha256=bad", "secret")
    assert not verify_github_signature(b"payload", None, "secret")


def test_bearer_token_comparison() -> None:
    assert verify_bearer_token("Bearer expected", "expected")
    assert not verify_bearer_token("Bearer wrong", "expected")
    assert not verify_bearer_token(None, "expected")

