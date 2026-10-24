"""JWT Token Verifier and JWKS Rotation Cache.
100% Python Standard Library.
"""

import base64
import json
import hmac
import hashlib
import time
from typing import Dict, Any, Optional


class JWTTokenVerifier:
    """Zero-dependency JWT encoder, decoder, and cryptographic HMAC-SHA256 signature verifier
    with standard RFC 7519 claim validation (exp, nbf, iss, aud)."""

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _base64url_decode(s: str) -> bytes:
        padding = "=" * ((4 - len(s) % 4) % 4)
        return base64.urlsafe_b64decode(s + padding)

    @classmethod
    def encode(
        cls,
        payload: Dict[str, Any],
        secret: str,
        headers: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generates a standard HS256 signed JSON Web Token."""
        header_dict = {"alg": "HS256", "typ": "JWT", **(headers or {})}
        header_bytes = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        encoded_header = cls._base64url_encode(header_bytes)
        encoded_payload = cls._base64url_encode(payload_bytes)

        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        encoded_signature = cls._base64url_encode(signature)

        return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

    @classmethod
    def decode_and_verify(
        cls,
        token: str,
        secret: str,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
        clock_tolerance_seconds: int = 60,
    ) -> Dict[str, Any]:
        """Decodes token, validates HMAC-SHA256 signature, and enforces standard claim constraints."""
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {"valid": False, "error": "MALFORMED_JWT_STRUCTURE", "claims": None}

        encoded_header, encoded_payload, encoded_signature = parts

        # 1. Verify cryptographic signature
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        expected_encoded_sig = cls._base64url_encode(expected_sig)

        if not hmac.compare_digest(encoded_signature, expected_encoded_sig):
            return {"valid": False, "error": "INVALID_SIGNATURE", "claims": None}

        # 2. Parse payload
        try:
            payload_json = cls._base64url_decode(encoded_payload).decode("utf-8")
            claims = json.loads(payload_json)
        except Exception as e:
            return {"valid": False, "error": f"PAYLOAD_DECODE_ERROR: {str(e)}", "claims": None}

        now = time.time()

        # 3. Check expiration (exp)
        if "exp" in claims:
            if now > (claims["exp"] + clock_tolerance_seconds):
                return {"valid": False, "error": "TOKEN_EXPIRED", "claims": claims}

        # 4. Check not before (nbf)
        if "nbf" in claims:
            if (claims["nbf"] - clock_tolerance_seconds) > now:
                return {"valid": False, "error": "TOKEN_NOT_YET_VALID", "claims": claims}

        # 5. Check issuer (iss)
        if expected_issuer and claims.get("iss") != expected_issuer:
            return {"valid": False, "error": "ISSUER_MISMATCH", "claims": claims}

        # 6. Check audience (aud)
        if expected_audience:
            aud = claims.get("aud")
            aud_match = (aud == expected_audience) if isinstance(aud, str) else (expected_audience in (aud or []))
            if not aud_match:
                return {"valid": False, "error": "AUDIENCE_MISMATCH", "claims": claims}

        return {
            "valid": True,
            "error": None,
            "claims": claims,
        }


class JWKSRotationCache:
    """In-memory Key ID (kid) rotation manager for verifying JWTs signed across rotating keys."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self.default_ttl = default_ttl_seconds
        self.keys: Dict[str, Dict[str, Any]] = {}

    def register_key(self, kid: str, secret: str, ttl_seconds: Optional[int] = None):
        """Registers or rotates an active key."""
        ttl = ttl_seconds or self.default_ttl
        now = time.time()
        self.keys[kid] = {
            "secret": secret,
            "expires_at": now + ttl,
        }

    def get_key(self, kid: str) -> Optional[str]:
        """Retrieves an active key by kid if unexpired."""
        entry = self.keys.get(kid)
        if not entry:
            return None
        if time.time() > entry["expires_at"]:
            del self.keys[kid]
            return None
        return entry["secret"]
