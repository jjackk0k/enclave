"""Show why python_for_console() depends on interpreter layout."""
import sys
from pathlib import Path
exe = sys.executable
sib = exe.replace("python.exe", "pythonw.exe")
sib2 = str(Path(exe).with_name("pythonw.exe"))
print("sys.executable      =", exe)
print("ends with python.exe=", exe.lower().endswith("python.exe"))
print("sibling pythonw     =", sib, "exists:", Path(sib2).exists())
# This is exactly what menuops.python_for_console() returns when NOT frozen and
# the sibling does not exist -> it just returns sys.executable as-is.
from spark_code import menuops
print("python_for_console()=", menuops.python_for_console())
