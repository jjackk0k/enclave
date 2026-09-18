import base64
import json
import time

def b64url(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

now = int(time.time())
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "sandbox@axiom.dev", "name": "Sandbox User", "role": "admin", "org": "org_axiom", "iss": "axiom-auth", "iat": now, "exp": now + 3600}
print(b64url(header) + "." + b64url(payload) + ".")
