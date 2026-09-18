"""One-command exe build for spark-code:

    python scripts\\build_exe.py

Creates an isolated .build-venv/ (the managed daimon runtime is never
polluted), pip-installs PyInstaller there, and builds two one-file exes
next to this script's parent (the spark-code/ folder):

    spark-menu.exe   the clickable tkinter menu (windowed, no console)
    spark-code.exe   the REPL agent itself (console; the menu's Launch
                     button prefers it when present)

spark-code.bat remains the zero-build fallback path; the exes are additive.
Rebuild after any change to spark_code/ - the exes do not auto-update.
"""

from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
VENV = ROOT / ".build-venv"


def run(cmd, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], check=True, cwd=str(ROOT), **kw)


def main() -> int:
    if not VENV.exists():
        print(f"creating build venv at {VENV} (isolated from the managed runtime)")
        venv.create(VENV, with_pip=True)
    vpy = VENV / "Scripts" / "python.exe"
    if not vpy.exists():
        print(f"! venv python missing at {vpy}")
        return 1
    # PyInstaller bundles what ITS venv can import — customtkinter must be
    # installed here (not only in the runtime) for the menu exe to carry it.
    run([vpy, "-m", "pip", "install", "--quiet", "pyinstaller", "customtkinter"])
    pyi = [vpy, "-m", "PyInstaller", "--onefile", "--clean", "--noconfirm",
           "--paths", str(ROOT), "--distpath", str(ROOT),
           "--workpath", str(BUILD / "work"), "--specpath", str(BUILD)]
    # The ops console's UI is customtkinter — its theme assets (JSON) must be
    # collected into the onefile bundle or the window dies at first widget.
    run(pyi + ["--windowed", "--name", "spark-menu",
               "--collect-all", "customtkinter",
               str(ROOT / "scripts" / "entry_menu.py")])
    run(pyi + ["--console", "--name", "spark-code",
               "--hidden-import", "spark_code.__main__",
               str(ROOT / "scripts" / "entry_repl.py")])
    print(f"\nbuilt: {ROOT / 'spark-menu.exe'} and {ROOT / 'spark-code.exe'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
