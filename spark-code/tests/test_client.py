"""Client tests against the in-process mock server: models, per-slot
context probing, streaming deltas, real usage counts, client-side tok/s,
usage-missing fallback, and tunnel-down error mapping. No live dependency.
"""

import unittest

from spark_code import config
from spark_code.client import SparkClient, TunnelDownError

from tests.mock_server import MockSparkServer


def closed_port_url() -> str:
    """A localhost port guaranteed to refuse connections (fails fast)."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


class TestClient(unittest.TestCase):
    def test_list_models(self):
        with MockSparkServer() as srv:
            client = SparkClient(base_url=srv.base_url)
            self.assertEqual(client.list_models(), ["mock-heretic-27b"])

    def test_probe_context_per_slot(self):
        with MockSparkServer() as srv:
            client = SparkClient(base_url=srv.base_url)
            limit, total, source = client.probe_context_limit()
            # /props n_ctx is already the per-slot value - never divide again
            self.assertEqual(limit, 131072)
            self.assertEqual(total, 262144)  # 131072 x 2 slots, for display
            self.assertIn("/props", source)

    def test_thinking_off_sends_template_kwarg(self):
        with MockSparkServer() as srv:
            client = SparkClient(base_url=srv.base_url, model="m")
            list(client.chat_stream([{"role": "user", "content": "hi"}],
                                    max_tokens=10, thinking=False))
            self.assertEqual(srv.requests[-1].get("chat_template_kwargs"),
                             {"enable_thinking": False})
            list(client.chat_stream([{"role": "user", "content": "hi"}],
                                    max_tokens=10, thinking=True))
            self.assertNotIn("chat_template_kwargs", srv.requests[-1])

    def test_stream_with_real_usage(self):
        with MockSparkServer(chunk_delay=0.02) as srv:
            client = SparkClient(base_url=srv.base_url, model="mock-heretic-27b")
            text = "".join(client.chat_stream([{"role": "user", "content": "hi"}],
                                              max_tokens=100))
            self.assertEqual(text, "Hello from mock!")
            r = client.last_result
            self.assertEqual(r.prompt_tokens, 123)
            self.assertEqual(r.completion_tokens, 3)
            self.assertFalse(r.tokens_estimated)
            self.assertEqual(r.finish_reason, "stop")
            self.assertGreater(r.tok_per_s, 0)  # measured from chunk arrival times

    def test_stream_without_usage_estimates_honestly(self):
        with MockSparkServer() as srv:
            srv.scripts.append({"deltas": ["abcdefghij"], "usage": None})
            client = SparkClient(base_url=srv.base_url)
            text = "".join(client.chat_stream([{"role": "user", "content": "hi"}],
                                              max_tokens=100))
            self.assertEqual(text, "abcdefghij")
            r = client.last_result
            self.assertTrue(r.tokens_estimated)
            self.assertEqual(r.completion_tokens, 10 // 4)

    def test_tunnel_down_maps_to_clear_error(self):
        client = SparkClient(base_url=closed_port_url(), read_timeout=2)
        client.retry_backoff = ()  # retry timing is covered in TestRetries
        with self.assertRaises(TunnelDownError) as ctx:
            client.list_models()
        self.assertIn("SSH tunnel", str(ctx.exception))
        self.assertIn("gx10-d094.local", str(ctx.exception))

    def test_tunnel_down_on_stream(self):
        client = SparkClient(base_url=closed_port_url(), read_timeout=2)
        client.retry_backoff = ()
        with self.assertRaises(TunnelDownError):
            list(client.chat_stream([{"role": "user", "content": "hi"}], max_tokens=10))


class TestRetries(unittest.TestCase):
    """WiFi-flap tolerance: transient failures before the first streamed
    token are retried with backoff (3 retries), then surface honestly."""

    def fast_client(self, url):
        client = SparkClient(base_url=url)
        client.retry_backoff = (0.01, 0.01, 0.01)
        return client

    def test_dropped_connection_then_success_on_get(self):
        with MockSparkServer() as srv:
            srv.httpd.abort_next = 1
            client = self.fast_client(srv.base_url)
            seen = []
            client.on_retry = lambda attempt, wait, exc: seen.append(attempt)
            self.assertEqual(client.list_models(), ["mock-heretic-27b"])
            self.assertEqual(seen, [1])  # one retry before success

    def test_dropped_connection_then_success_on_stream(self):
        with MockSparkServer() as srv:
            srv.httpd.abort_next = 1
            client = self.fast_client(srv.base_url)
            client.model = "mock-heretic-27b"
            seen = []
            client.on_retry = lambda attempt, wait, exc: seen.append(attempt)
            text = "".join(client.chat_stream([{"role": "user", "content": "hi"}],
                                              max_tokens=10))
            self.assertEqual(text, "Hello from mock!")
            self.assertEqual(seen, [1])

    def test_retries_exhausted_then_honest_error(self):
        import unittest.mock as mock
        import urllib.error
        client = self.fast_client("http://127.0.0.1:9")
        seen = []
        client.on_retry = lambda attempt, wait, exc: seen.append(attempt)
        # patch out the transport: refused connects cost ~2s on this box
        with mock.patch("urllib.request.urlopen",
                        side_effect=urllib.error.URLError("refused")) as m:
            with self.assertRaises(TunnelDownError):
                client.list_models()
        self.assertEqual(m.call_count, 4)      # 1 + 3 retries
        self.assertEqual(seen, [1, 2, 3])

    def test_garbled_frame_skipped_stream_continues(self):
        with MockSparkServer() as srv:
            srv.httpd.inject_raw = b'data: {"choices": \xff\xfe\n\n'  # invalid UTF-8
            client = self.fast_client(srv.base_url)
            text = "".join(client.chat_stream([{"role": "user", "content": "hi"}],
                                              max_tokens=10))
            self.assertEqual(text, "Hello from mock!")


class TestAbort(unittest.TestCase):
    """client.abort() (the Esc watcher's callback) breaks even a blocked
    readline by closing the response socket, and raises StreamAborted -
    never a TunnelDownError, never a retry, never a usage record."""

    def test_abort_mid_stream_breaks_blocked_readline(self):
        import threading
        from spark_code.client import StreamAborted
        with MockSparkServer(chunk_delay=0.25) as srv:
            client = SparkClient(base_url=srv.base_url, model="m")
            gen = client.chat_stream([{"role": "user", "content": "hi"}],
                                     max_tokens=10)
            self.assertEqual(next(gen), "Hello")
            threading.Timer(0.05, client.abort).start()
            with self.assertRaises(StreamAborted):
                list(gen)

    def test_stale_abort_does_not_poison_the_next_stream(self):
        with MockSparkServer() as srv:
            client = SparkClient(base_url=srv.base_url, model="m")
            client.abort()  # fired with no stream active (e.g. buffered Esc)
            text = "".join(client.chat_stream([{"role": "user", "content": "hi"}],
                                              max_tokens=10))
            self.assertEqual(text, "Hello from mock!")

    def test_abort_with_no_stream_is_harmless(self):
        SparkClient(base_url="http://127.0.0.1:9").abort()  # must not raise


if __name__ == "__main__":
    unittest.main()
