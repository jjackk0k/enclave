#!/usr/bin/env python3
# Enclave RANGE — a DELIBERATELY VULNERABLE practice target. Isolated lab box only;
# never a real service. It exists so operators can safely fire tools/exploits at
# something inside the sealed range instead of a live system.
#
# Planted weaknesses (for training):
#   * identifiable banner/version (so `nmap -sV` fingerprints it)
#   * GET /ping?host=<x>  -> command injection (host is passed to a shell unsanitised)
import http.server, subprocess, urllib.parse

BANNER = "AcmeCorp Diagnostics Portal 1.2"

class H(http.server.BaseHTTPRequestHandler):
    server_version = "AcmeDiag/1.2"
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _send(self, body, code=200):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/":
            self._send(BANNER + "\n\nEndpoints:\n  GET /ping?host=<host>   network diagnostics\n")
        elif u.path == "/ping":
            q = urllib.parse.parse_qs(u.query)
            host = q.get("host", ["127.0.0.1"])[0]
            # ** VULNERABLE ** — user input flows straight into a shell command.
            out = subprocess.run("ping -c1 " + host, shell=True, capture_output=True, text=True, timeout=8)
            self._send("diagnostics for " + host + ":\n" + out.stdout + out.stderr)
        else:
            self._send("not found\n", 404)

if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()
