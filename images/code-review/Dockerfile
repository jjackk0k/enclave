# Enclave — SECURE CODE REVIEW / AppSec enclave image.
# SAST + SCA + secrets + IaC scanning, baked in. The land workload (low egress).
# Headless. Run sealed; source mounts at /review.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC \
    PATH=/opt/venv/bin:/opt/codeql:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    GOBIN=/usr/local/bin GOPATH=/root/go PYTHONDONTWRITEBYTECODE=1

# robust apt: HTTPS mirrors + retry-with-recovery
RUN set -eu; \
    apt_install() { for i in 1 2 3 4 5 6; do if apt-get update -o Acquire::Retries=6 && apt-get install -y --no-install-recommends -o Acquire::Retries=6 "$@"; then return 0; fi; echo "apt retry $i"; dpkg --configure -a||true; apt-get -f install -y||true; apt-get clean; sleep 8; done; return 1; }; \
    apt_install ca-certificates apt-transport-https; \
    sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true; \
    apt_install python3 python3-venv python3-pip python3-dev build-essential \
      openjdk-21-jdk-headless golang-go git curl wget unzip jq file; \
    rm -rf /var/lib/apt/lists/*

# --- SAST / IaC / SCA (Python, venv) ---
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel setuptools \
    && /opt/venv/bin/pip install --no-cache-dir semgrep checkov bandit safety

# --- Trivy + Grype + Syft (Anchore/Aqua official installers, self-updating) ---
RUN set -eu; \
    curl -sfL  https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin; \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin; \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin

# --- Gitleaks (secrets) + OSV-Scanner (deps) ---
RUN set -eu; \
    curl -fsSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks && chmod +x /usr/local/bin/gitleaks; \
    ( go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest 2>/dev/null \
      || go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>/dev/null \
      || echo "osv-scanner skipped (Trivy/Grype cover OSV)" ); \
    rm -rf /root/go/pkg /root/.cache/go-build

# --- CodeQL CLI bundle (semantic SAST) ---
RUN set -eu; \
    curl -fsSL https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.26.1/codeql-bundle-linux64.tar.gz -o /tmp/codeql.tgz \
    && tar -xzf /tmp/codeql.tgz -C /opt && rm /tmp/codeql.tgz \
    && ln -sf /opt/codeql/codeql /usr/local/bin/codeql

# --- non-root reviewer; source mounts at /review ---
RUN userdel -r ubuntu 2>/dev/null || true; \
    useradd -m -u 1000 -s /bin/bash reviewer && mkdir -p /review && chown reviewer:reviewer /review
USER reviewer
WORKDIR /review

LABEL org.enclave.workload="code-review" \
      org.enclave.tools="semgrep,codeql,trivy,grype,syft,gitleaks,checkov,bandit,safety,osv-scanner"
CMD ["/bin/bash"]
