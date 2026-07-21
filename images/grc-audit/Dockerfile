# Enclave — GRC / COMPLIANCE audit enclave image.
# Cloud compliance + host hardening + compliance-as-code, baked in. Headless.
# Run sealed; evidence/config mounts at /audit.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC \
    PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    PYTHONDONTWRITEBYTECODE=1

# robust apt: HTTPS mirrors + retry-with-recovery. Includes native compliance tooling:
# Lynis (host audit), OpenSCAP scanner + the SCAP Security Guide (CIS/STIG baselines).
RUN set -eu; \
    apt_install() { for i in 1 2 3 4 5 6; do if apt-get update -o Acquire::Retries=6 && apt-get install -y --no-install-recommends -o Acquire::Retries=6 "$@"; then return 0; fi; echo "apt retry $i"; dpkg --configure -a||true; apt-get -f install -y||true; apt-get clean; sleep 8; done; return 1; }; \
    apt_install ca-certificates apt-transport-https; \
    sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true; \
    apt_install python3 python3-venv python3-pip python3-dev build-essential \
      ruby ruby-dev git curl wget unzip jq file \
      lynis openscap-scanner ssg-base ssg-debderived; \
    rm -rf /var/lib/apt/lists/*

# --- Prowler (multi-cloud compliance, Python venv) ---
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel setuptools \
    && /opt/venv/bin/pip install --no-cache-dir prowler

# --- Steampipe (cloud posture as SQL) ---
RUN set -eu; \
    curl -fsSL https://github.com/turbot/steampipe/releases/download/v2.4.4/steampipe_linux_amd64.tar.gz | tar -xz -C /usr/local/bin steampipe \
    && chmod +x /usr/local/bin/steampipe

# --- Chef InSpec (compliance-as-code) — heavy gem, best-effort so it can't fail the image ---
RUN gem install --no-document inspec-bin 2>/dev/null && ln -sf "$(ruby -e 'print Gem.bindir')/inspec" /usr/local/bin/inspec 2>/dev/null || echo "inspec skipped (optional; add via gem install inspec-bin)"

# --- non-root auditor; evidence/config mounts at /audit ---
RUN userdel -r ubuntu 2>/dev/null || true; \
    useradd -m -u 1000 -s /bin/bash auditor && mkdir -p /audit && chown auditor:auditor /audit
USER auditor
WORKDIR /audit

LABEL org.enclave.workload="grc-audit" \
      org.enclave.tools="prowler,steampipe,openscap(oscap),ssg-baselines,lynis,inspec"
CMD ["/bin/bash"]
