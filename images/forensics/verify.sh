#!/usr/bin/env bash
# Verify every tool in the forensics enclave image is installed and runnable.
# Runs entirely inside the sealed image with NO network. Usage: bash verify.sh
img="${1:-enclave-forensics:latest}"
echo "── verifying tools inside $img (—network none) ──"
docker run --rm --network none "$img" bash -lc '
  ok(){ printf "  %-14s %s\n" "$1" "$2"; }
  ok volatility3 "$(vol --help 2>/dev/null | grep -im1 volatility || echo "$(python -c "import volatility3;print(volatility3.__version__)" 2>/dev/null && echo present)")"
  ok capa        "$(capa --version 2>&1 | head -1)"
  ok yara-x      "$(yr --version 2>&1 | head -1)"
  ok yara        "$(yara --version 2>&1 | head -1)"
  ok sleuthkit   "$(mmls -V 2>&1 | head -1; fls -V 2>&1 | head -1)"
  ok plaso       "$(log2timeline.py --version 2>&1 | head -1)"
  ok hayabusa    "$(hayabusa --version 2>&1 | head -1)"
  ok chainsaw    "$(chainsaw --version 2>&1 | head -1)"
  ok velociraptor"$(velociraptor version 2>&1 | grep -im1 velociraptor)"
  ok radare2     "$(r2 -v 2>&1 | head -1)"
  ok ghidra      "$([ -x /opt/ghidra/support/analyzeHeadless ] && echo installed: /opt/ghidra $(cat /opt/ghidra/Ghidra/application.properties 2>/dev/null | grep -i application.version | head -1))"
  echo "  --- network is sealed: ---"
  ok net "$(curl -sm3 https://example.com >/dev/null 2>&1 && echo REACHABLE || echo unreachable-good)"
'
