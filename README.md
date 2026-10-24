# genpark-jwt-token-verifier-and-jwks-rotation-cache-skill

HMAC JWT token validator, claim expiration auditor, and JWKS public key rotation cache.

100% Python Standard Library implementation with zero external dependencies.

## Key Capabilities

- **Zero-Dependency HMAC-SHA256 Signing & Verification**: Fast Base64URL encoding/decoding and constant-time signature comparison using Python's standard `hmac` and `hashlib`.
- **RFC 7519 Standard Claim Enforcement**: Validates token expiration (`exp`), not-before (`nbf`), issuer (`iss`), and audience (`aud`) with configurable clock skew tolerance.
- **In-Memory Key ID (kid) Rotation Cache**: Caches active signing keys with time-to-live policies to support zero-downtime key rotation.
- **Detailed Tamper & Diagnostic Error Codes**: Distinguishes between signature mismatches, expired tokens, and malformed token formats.

## Architecture

```
[Raw JWT Token String: header.payload.signature]
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│                 JWTTokenVerifier                    │
│  - Base64URL Decoding & Structural Splitter         │
│  - Constant-Time HMAC-SHA256 Signature Validator    │
│  - Standard Claims Auditor (exp, nbf, iss, aud)     │
│  - Clock Drift Tolerance Arbiter                    │
└─────────────────────────────────────────────────────┘
         │                               │
 (Signature / Claims Valid)      (Tampered / Expired)
         ▼                               ▼
[Admit Claims & User Context]   [Reject: Diagnostic Error Code]
```

## MCP Server Integration

Run standard MCP stdio server:
```bash
python mcp_server.py
```

Exposed Tools:
- `jwt_encode`: Generates an HS256 signed JSON Web Token with claims and headers.
- `jwt_verify`: Decodes and cryptographically validates JWT token and claims constraints.

## Quickstart (Python API)

```python
from client import JWTTokenVerifier

token = JWTTokenVerifier.encode({"sub": "usr_42"}, "secret_key")
res = JWTTokenVerifier.decode_and_verify(token, "secret_key")
print("User:", res["claims"]["sub"])
```

---

## GenPark Ecosystem

- **Official Website**: [https://www.genpark.ai](https://www.genpark.ai)
- **LinkedIn Page**: [https://www.linkedin.com/company/92955550](https://www.linkedin.com/company/92955550)
