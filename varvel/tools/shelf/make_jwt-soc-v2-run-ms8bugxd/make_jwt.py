import base64
import hashlib
import hmac
import json
import sys
import time

if len(sys.argv) < 2:
    raise SystemExit("usage: python make_jwt.py <sub> [role] [org]")

sub = sys.argv[1]
role = sys.argv[2] if len(sys.argv) > 2 else "admin"
org = sys.argv[3] if len(sys.argv) > 3 else "org_axiom"
key = b"axiom-auth-hs256-legacy-2019"
now = int(time.time())
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": sub,
    "name": sub.replace("_", " ").title(),
    "role": role,
    "org": org,
    "iss": "axiom-auth",
    "iat": now,
    "exp": now + 3600,
}

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

signing_input = ".".join([
    b64url(json.dumps(header, separators=(",", ":")).encode()),
    b64url(json.dumps(payload, separators=(",", ":")).encode()),
])
print(signing_input + "." + b64url(hmac.new(key, signing_input.encode(), hashlib.sha256).digest()))
