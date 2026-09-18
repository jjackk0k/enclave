#!/usr/bin/env python3
"""
Validation probe script for localizejs engagement.
Run this inside the sealed workload once Bash is available.
"""
import subprocess
import sys

HOSTS = [
    "localizestaging.com",
    "api.localizestaging.com",
    "cdn.localizestaging.com",
    "app.localizestaging.com"
]

SVN_PATHS = ["/.svn/entries", "/.svn/wc.db", "/.svn/all-wcprops"]
BACKUP_PATHS = ["/backup.tar.gz", "/backup.zip", "/www.tar.gz",
                "/backups/backup.tar.gz", "/site.tar.gz", "/archive.tar.gz",
                "/backup/", "/db.sql", "/dump.sql"]
STATUS_PATHS = ["/server-status", "/status", "/server-info"]

def curl_probe(url):
    cmd = [
        "curl", "-sS", "-D-", "-o", "/tmp/resp_body",
        "-w", "\\nHTTP_CODE:%{http_code}\\nSIZE:%{size_download}\\nCT:%{content_type}\\n",
        "-L", "--max-time", "15", url
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return result.stdout, result.stderr
    except Exception as e:
        return "", str(e)

for host in HOSTS:
    print(f"\n{'='*60}\nHOST: {host}\n{'='*60}")
    for path in SVN_PATHS + BACKUP_PATHS + STATUS_PATHS:
        url = f"https://{host}{path}"
        stdout, stderr = curl_probe(url)
        print(f"\n--- {url} ---")
        print(stdout)
        if stderr:
            print("ERR:", stderr)
