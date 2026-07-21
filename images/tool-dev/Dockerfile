# Enclave — TOOL-DEV / EXPLOIT-DEV enclave image.
#
# The security-tool-development workload: compilers + cross-compilers, debuggers,
# the exploit-dev toolkit, fuzzers, and RE. Gated behind L4 + an exploit-dev/offensive
# cert (see the tool-dev preset). Headless. Run sealed at runtime; build workspace
# mounts at /work. (gcc/objdump/gdb "and tools like that" live here in full.)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC \
    PATH=/opt/venv/bin:/opt/ghidra/support:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    GHIDRA_INSTALL_DIR=/opt/ghidra PYTHONDONTWRITEBYTECODE=1

# robust apt: HTTPS mirrors (dodge transparent-proxy 400s) + retry-with-recovery
RUN set -eu; \
    apt_install() { \
      for i in 1 2 3 4 5 6; do \
        if apt-get update -o Acquire::Retries=6 && apt-get install -y --no-install-recommends -o Acquire::Retries=6 "$@"; then return 0; fi; \
        echo "apt attempt $i failed — recovering"; dpkg --configure -a || true; apt-get -f install -y || true; apt-get clean; sleep 8; \
      done; return 1; \
    }; \
    apt_install ca-certificates apt-transport-https; \
    sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true; \
    apt_install \
      build-essential clang lld llvm gcc-multilib g++-multilib \
      mingw-w64 nasm cmake make pkg-config \
      gdb gdb-multiarch gdbserver lldb valgrind \
      golang-go rustc cargo ruby ruby-dev \
      python3 python3-venv python3-pip python3-dev \
      radare2 binwalk ltrace strace patchelf upx-ucl file xxd yara \
      afl++ qemu-user openjdk-21-jdk-headless \
      git curl wget unzip; \
    rm -rf /var/lib/apt/lists/*

# --- exploit-dev toolkit (Python, isolated venv) ---
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel setuptools \
    && /opt/venv/bin/pip install --no-cache-dir pwntools ROPgadget ropper capstone keystone-engine unicorn
# angr (symbolic execution) is heavy — best-effort so it can't fail the image
RUN /opt/venv/bin/pip install --no-cache-dir angr 2>/dev/null || echo "angr skipped (optional)"

# --- exploit-dev helpers via Ruby gems (one_gadget, seccomp-tools) ---
RUN gem install --no-document one_gadget seccomp-tools 2>/dev/null || echo "gems skipped (optional)"

# --- Ghidra (headless RE) + GEF (gdb enhancer) ---
RUN set -eu; \
    curl -fsSL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip -o /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt && rm /tmp/ghidra.zip && mv /opt/ghidra_* /opt/ghidra; \
    mkdir -p /etc/gdb && curl -fsSL https://raw.githubusercontent.com/hugsy/gef/main/gef.py -o /opt/gef.py 2>/dev/null \
      && echo 'source /opt/gef.py' > /etc/gdb/gdbinit || true

# --- non-root builder; build workspace at /work ---
RUN userdel -r ubuntu 2>/dev/null || true; \
    useradd -m -u 1000 -s /bin/bash hacker && mkdir -p /work && chown hacker:hacker /work
USER hacker
WORKDIR /work

LABEL org.enclave.workload="tool-dev" \
      org.enclave.tools="gcc,clang,mingw-w64,gdb+gef,gdb-multiarch,lldb,valgrind,pwntools,ROPgadget,ropper,one_gadget,seccomp-tools,checksec,afl++,radare2,ghidra,capstone,keystone,unicorn,angr,patchelf,nasm,rust,go"
CMD ["/bin/bash"]
