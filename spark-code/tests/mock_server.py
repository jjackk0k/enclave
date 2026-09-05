"""In-process mock of the llama-server OpenAI-compatible endpoint.

Serves /v1/models, /props, and streaming /v1/chat/completions (SSE with
stream_options include_usage, exactly like llama.cpp). Tests push scripts
onto `server.scripts`; each POST pops one.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _maybe_abort(self) -> bool:
        """Simulate a WiFi flap / tunnel restart: close without answering."""
        server = self.server  # type: ignore[assignment]
        if getattr(server, "abort_next", 0) > 0:
            server.abort_next -= 1
            self.close_connection = True
            return True
        return False

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self._maybe_abort():
            return
        if self.path == "/v1/models":
            self._json({"object": "list",
                        "data": [{"id": "mock-heretic-27b", "object": "model"}]})
        elif self.path == "/props":
            # llama.cpp reports the PER-SLOT n_ctx here (verified live against
            # the real server: -c 262144 -np 2 -> /props n_ctx = 131072).
            self._json({"default_generation_settings": {"n_ctx": 131072},
                        "total_slots": 2})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self._json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)
        if self._maybe_abort():
            return
        server = self.server  # type: ignore[assignment]
        try:
            server.requests.append(json.loads(raw_body))
        except Exception:
            pass
        script = server.scripts.pop(0) if server.scripts else server.default_script
        if script.get("error_code"):  # e.g. the vision probe on a text-only model
            self._json({"error": script.get("error", {"message": "bad request"})},
                       script["error_code"])
            return
        if "raw_json" in script:  # a plain non-streaming completion
            self._json(script["raw_json"])
            return
        deltas, usage = script["deltas"], script.get("usage")
        # "events" allows interleaved reasoning/content; "reasoning" is a
        # shorthand for reasoning deltas streamed before the content deltas
        events = script.get("events")
        if events is None:
            events = ([{"reasoning_content": r} for r in script.get("reasoning", [])]
                      + [{"content": d} for d in deltas])

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for i, ev in enumerate(events):
            chunk = {"choices": [{"index": 0, "delta": ev,
                                  "finish_reason": None}]}
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
            self.wfile.flush()
            if i == 0 and getattr(server, "inject_raw", None):
                self.wfile.write(server.inject_raw)  # garbled frame mid-stream
                self.wfile.flush()
            if server.chunk_delay:
                time.sleep(server.chunk_delay)
        final = {"choices": [{"index": 0, "delta": {},
                              "finish_reason": script.get("finish", "stop")}]}
        if usage:
            final["usage"] = usage
        self.wfile.write(b"data: " + json.dumps(final).encode() + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


class MockSparkServer:
    def __init__(self, chunk_delay: float = 0.01):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.scripts = []
        self.httpd.requests = []  # parsed request bodies, for assertions
        self.httpd.chunk_delay = chunk_delay
        self.httpd.abort_next = 0    # N next requests get their connection dropped
        self.httpd.inject_raw = None  # raw bytes injected after the first chunk
        # aborted sockets would otherwise spew handler tracebacks into test output
        self.httpd.handle_error = lambda *a, **k: None
        self.httpd.default_script = {
            "deltas": ["Hello", " from", " mock!"],
            "usage": {"prompt_tokens": 123, "completion_tokens": 3,
                      "total_tokens": 126},
        }
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    @property
    def scripts(self) -> list:
        return self.httpd.scripts

    @property
    def requests(self) -> list:
        return self.httpd.requests

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
