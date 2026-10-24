"""MCP server for JWT Token Verifier and JWKS Rotation Cache."""
import sys
import json
from client import JWTTokenVerifier, JWKSRotationCache

_jwks = JWKSRotationCache()


def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "jwt_encode",
                    "description": "Generates an HS256 signed JSON Web Token with claims and headers",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "payload": {"type": "object"},
                            "secret": {"type": "string"},
                            "headers": {"type": "object"},
                        },
                        "required": ["payload", "secret"],
                    },
                },
                {
                    "name": "jwt_verify",
                    "description": "Decodes and cryptographically validates JWT token and claims constraints",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "token": {"type": "string"},
                            "secret": {"type": "string"},
                            "expected_issuer": {"type": "string"},
                            "expected_audience": {"type": "string"},
                        },
                        "required": ["token", "secret"],
                    },
                },
            ]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})
        if tool_name == "jwt_encode":
            token = JWTTokenVerifier.encode(
                payload=args.get("payload", {}),
                secret=args.get("secret", ""),
                headers=args.get("headers"),
            )
            return {"content": [{"type": "text", "text": token}]}
        elif tool_name == "jwt_verify":
            res = JWTTokenVerifier.decode_and_verify(
                token=args.get("token", ""),
                secret=args.get("secret", ""),
                expected_issuer=args.get("expected_issuer"),
                expected_audience=args.get("expected_audience"),
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}


if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()
