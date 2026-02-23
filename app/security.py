import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone

from app.config import Settings

_UNSAFE_SECRETS = {
    "",
    "change-me",
    "your-secret-auth-token",
    "replace_with_strong_secret",
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(f"{data}{padding}")


def get_jwt_secret(settings: Settings) -> str:
    candidate = (settings.jwt_secret_key or "").strip() or (os.environ.get("AUTH_TOKEN") or "").strip()
    if candidate.lower() in _UNSAFE_SECRETS or len(candidate) < 16:
        if (settings.app_env or "").lower() == "development":
            # Keep local development usable when .env still contains placeholders.
            return "dev-only-insecure-jwt-secret-change-in-production"
        raise RuntimeError("JWT secret is not configured. Set JWT_SECRET_KEY (or a strong AUTH_TOKEN).")
    return candidate


def create_access_token(settings: Settings, username: str, user_id: int) -> tuple[str, str]:
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": username,
        "user_id": user_id,
        "type": "access",
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    header = {"alg": "HS256", "typ": "JWT"}

    encoded_header = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    secret = get_jwt_secret(settings).encode("utf-8")
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    encoded_signature = _b64url_encode(signature)

    return f"{encoded_header}.{encoded_payload}.{encoded_signature}", expires_at.isoformat()


def verify_access_token(token: str, settings: Settings) -> dict:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise ValueError("Malformed JWT") from exc

    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    secret = get_jwt_secret(settings).encode("utf-8")
    expected_signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    provided_signature = _b64url_decode(encoded_signature)
    if not hmac.compare_digest(expected_signature, provided_signature):
        raise ValueError("Invalid token signature")

    try:
        header = json.loads(_b64url_decode(encoded_header).decode("utf-8"))
        payload = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid token encoding") from exc

    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise ValueError("Unsupported token header")

    now_ts = int(datetime.now(timezone.utc).timestamp())
    exp = int(payload.get("exp", 0))
    if exp <= now_ts:
        raise ValueError("Token expired")
    if payload.get("type") != "access":
        raise ValueError("Invalid token type")
    if not payload.get("sub"):
        raise ValueError("Missing subject")

    return payload
