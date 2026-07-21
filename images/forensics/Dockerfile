# Enclave — IR / forensics enclave image.
# The tools the forensics tool-shelf advertises, BAKED IN so the enclave AI can
# actually run them (Volatility 3, capa, YARA-X, Sleuth Kit, Plaso, Hayabusa,
# Chainsaw, Ghidra headless, Velociraptor, radare2). Linux, run sealed at runtime
# (--network none + the egress broker). Evidence mounts read-only at /case.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/venv/bin:/opt/ghidra/support:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    GHIDRA_INSTALL_DIR=/opt/ghidra

# --- system + native forensics tools (apt) ---
# archive.ubuntu.com over HTTP intermittently returns 400 (transparent-proxy mangling),
# which corrupts apt state. Fix: switch to HTTPS mirrors, and retry-with-recovery so a
# flaky fetch can't leave a half-built image (fail hard only if truly exhausted).
RUN set -eu; \
    apt_install() { \
      for i in 1 2 3 4 5 6; do \
        if apt-get update -o Acquire::Retries=6 && apt-get install -y --no-install-recommends -o Acquire::Retries=6 "$@"; then return 0; fi; \
        echo "apt attempt $i failed — recovering + retrying"; dpkg --configure -a || true; apt-get -f install -y || true; apt-get clean; sleep 8; \
      done; \
      return 1; \
    }; \
    apt_install ca-certificates apt-transport-https; \
    sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true; \
    apt_install python3 python3-venv python3-pip python3-dev build-essential \
      openjdk-21-jdk-headless sleuthkit radare2 yara \
      software-properties-common gnupg \
      curl wget unzip git file libmagic1; \
    rm -rf /var/lib/apt/lists/*

# --- Volatility 3 + capa (Python) in an isolated venv ---
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel setuptools \
    && /opt/venv/bin/pip install --no-cache-dir volatility3 flare-capa pefile yara-python

# --- Plaso (super-timeline) via the official GIFT PPA — its libyal/dfVFS deps don't pip-build ---
RUN set -eu; \
    apt_install() { \
      for i in 1 2 3 4 5 6; do \
        if apt-get update -o Acquire::Retries=6 && apt-get install -y --no-install-recommends -o Acquire::Retries=6 "$@"; then return 0; fi; \
        echo "plaso attempt $i failed — recovering + retrying"; dpkg --configure -a || true; apt-get -f install -y || true; apt-get clean; sleep 8; \
      done; \
      return 1; \
    }; \
    add-apt-repository -y ppa:gift/stable; \
    apt_install plaso-tools; \
    rm -rf /var/lib/apt/lists/*

# --- YARA-X CLI (yr) ---
RUN curl -fsSL https://github.com/VirusTotal/yara-x/releases/download/v1.19.0/yara-x-v1.19.0-x86_64-unknown-linux-gnu.tar.gz -o /tmp/yx.tgz \
    && mkdir -p /tmp/yx && tar -xzf /tmp/yx.tgz -C /tmp/yx \
    && cp "$(find /tmp/yx -type f -name yr | head -1)" /usr/local/bin/yr \
    && chmod +x /usr/local/bin/yr && rm -rf /tmp/yx*

# --- Velociraptor (single Go binary) ---
RUN curl -fsSL https://github.com/Velocidex/velociraptor/releases/download/v0.77.1/velociraptor-v0.77.1-linux-amd64 -o /usr/local/bin/velociraptor \
    && chmod +x /usr/local/bin/velociraptor

# --- Hayabusa (EVTX + Sigma hunting) ---
RUN curl -fsSL https://github.com/Yamato-Security/hayabusa/releases/download/v3.10.0/hayabusa-3.10.0-lin-x64-gnu.zip -o /tmp/h.zip \
    && mkdir -p /opt/hayabusa && unzip -q /tmp/h.zip -d /opt/hayabusa && rm /tmp/h.zip \
    && ln -sf "$(find /opt/hayabusa -maxdepth 2 -type f -name 'hayabusa*' | head -1)" /usr/local/bin/hayabusa \
    && chmod +x /usr/local/bin/hayabusa

# --- Chainsaw (EVTX hunting) ---
RUN curl -fsSL https://github.com/WithSecureLabs/chainsaw/releases/download/v2.16.2/chainsaw_x86_64-unknown-linux-gnu.tar.gz -o /tmp/c.tgz \
    && tar -xzf /tmp/c.tgz -C /opt && rm /tmp/c.tgz \
    && ln -sf "$(find /opt -maxdepth 2 -type f -name chainsaw | head -1)" /usr/local/bin/chainsaw

# --- Ghidra (headless reverse engineering) ---
RUN curl -fsSL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip -o /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt && rm /tmp/ghidra.zip \
    && mv /opt/ghidra_* /opt/ghidra

# --- non-root analyst; evidence mounts at /case ---
ENV PATH=/opt/venv/bin:/opt/ghidra/support:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
RUN userdel -r ubuntu 2>/dev/null || true; \
    useradd -m -u 1000 analyst && mkdir -p /case && chown analyst:analyst /case
USER analyst
WORKDIR /case

LABEL org.enclave.workload="incident-response" \
      org.enclave.tools="volatility3,capa,yara-x,sleuthkit,plaso,hayabusa,chainsaw,ghidra,velociraptor,radare2"
CMD ["/bin/bash"]
