# Enclave — RED-TEAM enclave image (T2 offensive tooling).
#
# Gated behind the enforcement seam: offensive cert (OSCP/OSEP/CRTO…) + a SIGNED
# in-scope target + (for exploitation) human approval + full audit. This image only
# PROVIDES the tools; the seam decides who may fire them, at what, with what sign-off.
#
# Headless + curated: Kali's CLI tools (no GUI dead-weight) plus the current
# best-in-class open-source tools Kali ships stale or not at all (researched + version-
# pinned, 2026-07). Run sealed at runtime: egress via the broker, and
#   --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN   (raw-socket scans need these)
# Engagement workspace mounts at /assessment.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive TZ=UTC \
    GOPATH=/root/go GOBIN=/usr/local/bin \
    PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin \
    PATH=/usr/local/bin:/root/go/bin:/usr/bin:/bin:/usr/sbin:/sbin

# robust apt: HTTPS mirrors (dodge transparent-proxy 400s) + retry-with-recovery,
# Kali Apr-2025 keyring resiliency, and preseed the one interactive prompt (wireshark).
RUN set -eu; \
    apt_install() { \
      for i in 1 2 3 4 5 6; do \
        if apt-get update -o Acquire::Retries=6 && apt-get install -y -o Acquire::Retries=6 "$@"; then return 0; fi; \
        echo "apt attempt $i failed — recovering + retrying"; dpkg --configure -a || true; apt-get -f install -y || true; apt-get clean; sleep 8; \
      done; return 1; \
    }; \
    export -f apt_install 2>/dev/null || true; \
    sed -i 's|http://http.kali.org|https://http.kali.org|g' /etc/apt/sources.list 2>/dev/null || true; \
    ( apt-get update -o Acquire::Retries=6 || ( wget -qO /usr/share/keyrings/kali-archive-keyring.gpg https://archive.kali.org/archive-keyring.gpg && apt-get update ) ); \
    echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections; \
    apt_install \
      golang-go python3 python3-pip python3-venv pipx git curl wget unzip jq ca-certificates \
      libpcap-dev chromium build-essential; \
    rm -rf /var/lib/apt/lists/*

# --- Kali CLI offensive tools (hand-picked, headless — no GUI/Java bloat) ---
RUN set -eu; \
    apt_install() { for i in 1 2 3 4 5 6; do if apt-get update -o Acquire::Retries=6 && apt-get install -y --no-install-recommends -o Acquire::Retries=6 "$@"; then return 0; fi; echo "retry $i"; dpkg --configure -a||true; apt-get -f install -y||true; apt-get clean; sleep 8; done; return 1; }; \
    apt_install \
      nmap masscan dnsrecon dnsenum fierce enum4linux-ng smbmap smbclient recon-ng theharvester whatweb \
      nikto sqlmap gobuster wfuzz dirb commix wpscan \
      metasploit-framework exploitdb \
      hydra medusa ncrack john hashcat crunch cewl hashid wordlists seclists \
      responder proxychains4 ldap-utils snmp tshark \
      powersploit nishang mimikatz; \
    rm -rf /var/lib/apt/lists/*

# --- Recon: ProjectDiscovery suite + friends (Go -> /usr/local/bin via GOBIN) ---
RUN set -eu; \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest; \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest; \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest; \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest; \
    go install -v github.com/ffuf/ffuf/v2@latest; \
    go install -v github.com/sensepost/gowitness@latest; \
    go install -v github.com/bloodhoundad/azurehound/v2@latest; \
    rm -rf /root/go/pkg /root/.cache/go-build; \
    nuclei -update-templates || true

# --- AD / cred / C2 via pipx (isolated venvs; entry-points -> /usr/local/bin) ---
RUN set -eu; \
    pipx install git+https://github.com/Pennyw0rth/NetExec.git; \
    pipx install impacket; \
    pipx install certipy-ad; \
    pipx install bloodhound-ce; \
    pipx install ldapdomaindump

# --- Sliver C2 (default pick): static server+client binaries, assets unpacked ---
RUN set -eu; \
    curl -fsSL -o /usr/local/bin/sliver-server https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-server_linux-amd64; \
    curl -fsSL -o /usr/local/bin/sliver-client https://github.com/BishopFox/sliver/releases/download/v1.7.3/sliver-client_linux-amd64; \
    chmod +x /usr/local/bin/sliver-server /usr/local/bin/sliver-client; \
    /usr/local/bin/sliver-server unpack --force || true

# --- Kerbrute, feroxbuster, amass (release binaries) ---
RUN set -eu; \
    curl -fsSL -o /usr/local/bin/kerbrute https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 && chmod +x /usr/local/bin/kerbrute; \
    curl -fsSL https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.tar.gz | tar -xz -C /usr/local/bin feroxbuster && chmod +x /usr/local/bin/feroxbuster; \
    curl -fsSL https://github.com/owasp-amass/amass/releases/download/v5.1.1/amass_linux_amd64.tar.gz | tar -xz -C /tmp && install -m755 /tmp/amass_linux_amd64/amass /usr/local/bin/amass && rm -rf /tmp/amass_linux_amd64

# --- Windows-host collector staged for upload (not run on Linux) ---
RUN set -eu; mkdir -p /opt/collectors; \
    curl -fsSL -o /opt/collectors/SharpHound_v2.13.0.zip https://github.com/SpecterOps/SharpHound/releases/download/v2.13.0/SharpHound_v2.13.0_windows_x86.zip || true

# --- non-root operator; engagement workspace at /assessment ---
RUN userdel -r ubuntu 2>/dev/null || true; \
    useradd -m -u 1000 -s /bin/bash operator && mkdir -p /assessment && chown operator:operator /assessment
USER operator
WORKDIR /assessment

LABEL org.enclave.workload="red-team" \
      org.enclave.tier="T2-offensive" \
      org.enclave.tools="nmap,masscan,projectdiscovery,metasploit,sliver,netexec,impacket,certipy,kerbrute,bloodhound-ce,responder,hashcat,john,hydra,sqlmap,nuclei,ffuf,feroxbuster,amass,gowitness"
CMD ["/bin/bash"]
