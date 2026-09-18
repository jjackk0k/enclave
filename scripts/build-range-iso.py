# build-range-iso.py — author the range answer-file ISO with pycdlib.
import os
import pycdlib

SRC = r'C:\Users\Jack\Downloads\enclave\deploy\range-iso'
OUT = r'C:\Users\Jack\Documents\Virtual Machines\enclave-target\autounattend.iso'

if os.path.exists(OUT):
    os.remove(OUT)

iso = pycdlib.PyCdlib()
iso.new(joliet=3, interchange_level=4)
for f in sorted(os.listdir(SRC)):
    if f.startswith('.'):
        continue
    p = os.path.join(SRC, f)
    if not os.path.isfile(p):
        continue
    iso.add_file(p, '/' + f.upper() + ';1', joliet_path='/' + f)
iso.write(OUT)
iso.close()
print('ISO written:', OUT, os.path.getsize(OUT), 'bytes')
