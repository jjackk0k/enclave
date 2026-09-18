import json, base64, hmac, hashlib, time
key='axiom-auth-hs256-legacy-2019'
now=int(time.time())
header={'alg':'HS256','typ':'JWT'}
payload={'sub':'sandbox@axiom.dev','name':'Sandbox User','role':'admin','org':'org_sandbox','iss':'axiom-auth','iat':now,'exp':now+3600}
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
msg=b64url(json.dumps(header,separators=(',',':')).encode())+'.'+b64url(json.dumps(payload,separators=(',',':')).encode())
sig=base64.urlsafe_b64encode(hmac.new(key.encode(),msg.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
token=msg+'.'+sig
print(token)
