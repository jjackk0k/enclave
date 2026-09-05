"""One-shot verification for the frozen-path fix (run with any python)."""
import py_compile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "spark_code"
SCRIPTS = [str(ROOT / "scripts" / n) for n in ("entry_menu.py", "entry_repl.py")]

# 1. byte-compile every module we ship + the two entry points
bad = []
targets = sorted(str(p) for p in PKG.glob("*.py")) + SCRIPTS
for t in targets:
    try:
        py_compile.compile(t, doraise=True)
    except Exception as e:  # noqa: BLE001 - report and keep going
        bad.append((t, str(e)))
print(f"[compile] {len(targets)} files checked")
for t, e in bad:
    print("   FAIL", t, "->", e)
if not bad:
    print("   all OK")

# 2. from-source path resolution must be UNCHANGED (Kimi's tests rely on this)
sys.path.insert(0, str(ROOT))
from spark_code import config, menuops  # noqa: E402
print(f"[source] ROOT        = {config.ROOT}")
print(f"[source] SESSIONS    = {config.SESSIONS_DIR} (exists={config.SESSIONS_DIR.exists()})")
print(f"[source] PLUGINS     = {config.PLUGINS_DIR} (exists={config.PLUGINS_DIR.exists()})")
assert config.ROOT == ROOT, "from-source ROOT must be the spark-code/ dir"
assert config.SESSIONS_DIR == ROOT / "sessions"
assert config.PLUGINS_DIR == ROOT / "plugins"
print("[source] assertions OK (unchanged behavior)")

# 3. simulate a frozen one-file exe: __file__ in temp, sys.executable = real path
import types  # noqa: E402
fake_exe_dir = Path(r"C:\Users\Jack\Downloads\enclave\spark-code")
tempdir = Path(r"C:\Users\Jack\AppData\Local\Temp\_MEI1234567890")
# Re-import config with a fake frozen environment by monkeypatching sys before import.
import importlib  # noqa: E402
for m in ("spark_code", "spark_code.config", "spark_code.menuops"):
    sys.modules.pop(m, None)
sys.frozen = True
cfg_mod_path = PKG / "config.py"
# Build a minimal fake module namespace where __file__ is the temp copy.
import runpy  # noqa: E402
spec_globals = {"__name__": "spark_code.config", "__package__": "spark_code",
                "__loader__": None, "__spec__": None}
spec_globals["__file__"] = str(tempdir / "config.py")
# Provide the parent package stub so relative import of config works.
pkg_stub = types.ModuleType("spark_code")
pkg_stub.__path__ = [str(PKG)]
sys.modules.setdefault("spark_code", pkg_stub)
code = compile(cfg_mod_path.read_text(encoding="utf-8"), str(tempdir / "config.py"), "exec")
# config does `from . import ...`? No - it's self-contained except pathlib/sys. Execute directly.
globals_ = {"__name__": "spark_code.config", "__package__": "spark_code",
            "__file__": str(tempdir / "config.py")}
sys.executable = str(fake_exe_dir / "spark-menu.exe")
exec(code, globals_)  # noqa: S102 - controlled verification
frozen_root = Path(globals_["ROOT"])
frozen_sessions = Path(globals_["SESSIONS_DIR"])
frozen_plugins = Path(globals_["PLUGINS_DIR"])
del sys.frozen
print(f"[frozen] ROOT        = {frozen_root}")
print(f"[frozen] SESSIONS    = {frozen_sessions} (exists={frozen_sessions.exists()})")
print(f"[frozen] PLUGINS     = {frozen_plugins} (exists={frozen_plugins.exists()})")
assert frozen_root == fake_exe_dir, "frozen ROOT must be the exe's real folder"
assert frozen_sessions == fake_exe_dir / "sessions"
assert frozen_plugins == fake_exe_dir / "plugins"
print("[frozen] assertions OK (Launch/sessions/plugins now resolve to the real folder)")

# 4. run Kimi's own menu test-suite against the change
import unittest  # noqa: E402
loader = unittest.TestLoader()
suite = loader.loadTestsFromName("tests.test_menuops")
r = unittest.TextTestRunner(verbosity=1).run(suite)
ok = r.wasSuccessful() and (r.failures == []) 
print(f"[tests] test_menuops: {ok}  ({len(r.testsRun)} run, {len(r.failures)} fail, {len(r.errors)} err)")
sys.exit(0 if ok else 1)
