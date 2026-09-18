#!/usr/bin/env bash
# VARVEL post-exploitation proof-of-impact script
# Finding: TLS overly broad wildcard certificate across HubSpot subdomains
# Objective: Demonstrate virtual-host confusion / shared-origin exposure via Host-header probing
# Scope: IPs listed in signed engagement scope ONLY
# Author: VARVEL autonomous operator
# Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)

set -euo pipefail

# Scoped IP samples (from signed scope)
IPS=(
  "104.17.91.187"
  "104.18.33.148"
  "172.64.146.223"
  "104.21.48.60"
)

# Hostnames to test against scoped IPs (covered by wildcard)
HOSTS=(
  "api.hubspot.com"
  "app-na1.hubspot.com"
  "app-na2.hubspot.com"
  "app-eu1.hubspot.com"
  "app-ap1.hubspot.com"
  "admins.hubspot.com"
  "api-na1.hubspot.com"
  "api-na2.hubspot.com"
  "api-eu1.hubspot.com"
  "api-app.hubspot.com"
  "api-ap1.hubspot.com"
  "nonexistent-test-subdomain.hubspot.com"
)

OUTDIR="./postex-evidence"
mkdir -p "$OUTDIR"

echo "[*] Starting wildcard-certificate impact probe"
echo "[*] Output directory: $OUTDIR"

for ip in "${IPS[@]}"; do
  for host in "${HOSTS[@]}"; do
    out="$OUTDIR/${ip}_${host}.txt"
    echo "[*] Probing $ip with Host: $host"
    # TLS handshake + HTTP HEAD via IP with explicit Host header
    # --resolve forces the IP without DNS lookup (stays in scope)
    # --insecure used because IP != hostname in cert SAN check; we want to see if server still responds
    if curl -s -o "$out" --max-time 10 -k \
         --resolve "${host}:443:${ip}" \
         -H "Host: ${host}" \
         -D - \
         "https://${host}/" 2>/dev/null; then
      status=$(head -1 "$out" | awk '{print $2}')
      echo "[+] $ip -> $host responded HTTP $status"
    else
      echo "[-] $ip -> $host no response / connection refused"
      echo "CONNECTION_FAILED" > "$out"
    fi
  done
done

# Summarize findings
echo "[*] Summary:"
grep -h "^HTTP" "$OUTDIR"/*.txt 2>/dev/null | sort | uniq -c | sort -rn || true

echo "[*] Evidence files saved to $OUTDIR"
echo "[*] Done."
