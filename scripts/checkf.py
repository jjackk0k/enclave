#!/usr/bin/env python3
# checkf.py — print target's USER_ACCOUNT_F flags from the offline SAM (via impacket).
import sys, ntpath
from binascii import unhexlify
sys.path.insert(0, '/usr/lib/python3/dist-packages/impacket/examples')
from impacket import winregistry
import secretsdump as sd

SAM = '/tmp/SAM'
samreg = winregistry.get_registry_parser(SAM, False)
ridkey = 'SAM\\Domains\\Account\\Users\\%08X' % 0x3e8
F = samreg.getValue(ntpath.join(ridkey, 'F'))[1]
uaf = sd.USER_ACCOUNT_F(F)
for k in list(uaf.fields.keys()):
    v = uaf.fields[k]
    if isinstance(v, bytes) and len(v) <= 16:
        v = v.hex()
    print('%-40s %s' % (k, v))
