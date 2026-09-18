#!/bin/bash
# Validation probe script for localizejs engagement
# Targets: localizestaging.com, api.localizestaging.com, cdn.localizestaging.com, app.localizestaging.com

HOSTS=("localizestaging.com" "api.localizestaging.com" "cdn.localizestaging.com" "app.localizestaging.com")

# High-severity artifact probes
echo "=== SVN metadata probes ==="
for h in "${HOSTS[@]}"; do
  for path in "/.svn/entries" "/.svn/wc.db" "/.svn/all-wcprops"; do
    echo "--- $h$path ---"
    curl -sS -D- -o /tmp/body -w "\nHTTP_CODE:%{http_code}\nSIZE:%{size_download}\nCT:%{content_type}\n" "https://${h}${path}" -L --max-time 15
    head -c 200 /tmp/body
    echo
  done
done

echo "=== Backup archive probes ==="
for h in "${HOSTS[@]}"; do
  for path in "/backup.tar.gz" "/backup.zip" "/www.tar.gz" "/backups/backup.tar.gz" "/site.tar.gz" "/archive.tar.gz" "/backup/" "/db.sql" "/dump.sql"; do
    echo "--- $h$path ---"
    curl -sS -D- -o /tmp/body -w "\nHTTP_CODE:%{http_code}\nSIZE:%{size_download}\nCT:%{content_type}\n" "https://${h}${path}" -L --max-time 15
    file /tmp/body
    head -c 100 /tmp/body | xxd | head -5
    echo
  done
done

echo "=== Server status probes ==="
for h in "${HOSTS[@]}"; do
  for path in "/server-status" "/status" "/server-info"; do
    echo "--- $h$path ---"
    curl -sS -D- -o /tmp/body -w "\nHTTP_CODE:%{http_code}\nSIZE:%{size_download}\nCT:%{content_type}\n" "https://${h}${path}" -L --max-time 15
    head -c 300 /tmp/body
    echo
  done
done

echo "=== CORS preflight probes ==="
for h in "${HOSTS[@]}"; do
  echo "--- $h /api ---"
  curl -sS -D- -o /dev/null -w "\nHTTP_CODE:%{http_code}\n" "https://${h}/api" -H "Origin: https://evil.com" -X OPTIONS --max-time 10
  curl -sS -D- -o /dev/null -w "\nHTTP_CODE:%{http_code}\n" "https://${h}/api" -H "Origin: https://evil.com" --max-time 10
done
