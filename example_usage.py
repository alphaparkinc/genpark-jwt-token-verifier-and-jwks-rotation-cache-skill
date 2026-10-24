"""Example usage for JWT Token Verifier and JWKS Rotation Cache."""
import time
from client import JWTTokenVerifier, JWKSRotationCache


def main():
    secret_key = "super_secure_enterprise_secret_key_99182"
    issuer = "https://auth.genpark.ai"
    audience = "https://api.genpark.ai"

    print("=== 1. Generating Valid Signed JWT ===")
    now = int(time.time())
    payload = {
        "sub": "usr_alpha_9001",
        "name": "Alex Mercer",
        "role": "system_admin",
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + 3600,  # 1 hour validity
    }

    token = JWTTokenVerifier.encode(payload, secret_key, headers={"kid": "key_2026_q4"})
    print("Encoded JWT:", token)

    print("\n=== 2. Validating Signed Token ===")
    verify_result = JWTTokenVerifier.decode_and_verify(
        token=token,
        secret=secret_key,
        expected_issuer=issuer,
        expected_audience=audience,
    )
    print("Is Valid:", verify_result["valid"])
    print("Claims Subject:", verify_result["claims"]["sub"])
    print("Claims Role:", verify_result["claims"]["role"])

    print("\n=== 3. Rejecting Tampered Signature ===")
    tampered_result = JWTTokenVerifier.decode_and_verify(
        token=token,
        secret="wrong_secret_key_attacker",
        expected_issuer=issuer,
        expected_audience=audience,
    )
    print("Tampered Verification Valid:", tampered_result["valid"])
    print("Tampered Error:", tampered_result["error"])

    print("\n=== 4. Enforcing Expiration Validation ===")
    expired_payload = dict(payload, exp=now - 120)  # Expired 2 minutes ago
    expired_token = JWTTokenVerifier.encode(expired_payload, secret_key)
    expired_result = JWTTokenVerifier.decode_and_verify(expired_token, secret_key)
    print("Expired Token Valid:", expired_result["valid"])
    print("Expired Error:", expired_result["error"])

    print("\n=== 5. Key Rotation Cache Demonstration ===")
    jwks = JWKSRotationCache(default_ttl_seconds=60)
    jwks.register_key("key_2026_q4", secret_key)
    cached_key = jwks.get_key("key_2026_q4")
    print("Retrieved Active Key ID 'key_2026_q4':", bool(cached_key))


if __name__ == "__main__":
    main()
