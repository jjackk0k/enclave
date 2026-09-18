import subprocess, os, time, re
base='http://127.0.0.1:8973'
paths=['/','/login','/docs','/status','/changelog','/.well-known/security.txt','/robots.txt','/admin','/dashboard','/api','/console','/platform','/solutions','/pricing','/customers','/blog','/about','/contact','/legal']
for p in paths:
    url=base+p
    hfile=f"headers_{p.replace('/','_').replace('.','_') or 'root'}.txt"
    bfile=f"body_{p.replace('/','_').replace('.','_') or 'root'}.html"
    try:
        r=subprocess.run(['curl','-sS','-D',hfile,'-o',bfile,url],capture_output=True,text=True,timeout=10)
    except Exception as e:
        print(p,'ERROR',e)
        continue
    status='?'
    try:
        with open(hfile) as f:
            first=f.readline().strip()
            m=re.search(r'HTTP/\d(?:\.\d)? (\d+)',first)
            if m: status=m.group(1)
    except: pass
    size=os.path.getsize(bfile) if os.path.exists(bfile) else 0
    print(p,status,size)
    time.sleep(0.2)
