"""Stdlib-only client for the llama-server OpenAI-compatible endpoint.

Streaming uses `stream_options: {"include_usage": true}`, which llama.cpp
supports, giving real prompt/completion token counts on the final chunk.
Tokens/second is computed client-side from chunk arrival times (first
content delta -> last content delta), i.e. pure decode speed.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Generator, Iterator, List, Optional

from . import config


class TunnelDownError(Exception):
    """The local endpoint is unreachable - the SSH tunnel is down."""

    def __init__(self, message: Optional[str] = None) -> None:
        super().__init__(message or config.TUNNEL_HELP)


class ServerError(Exception):
    """The server answered with an HTTP error or a malformed payload."""


class StreamAborted(Exception):
    """The user pressed Esc during an in-flight stream. The watcher thread
    (lineedit.EscWatcher) calls client.abort(), which closes the HTTP
    response to break a blocked readline; the read loop then raises this.
    Never retried, never counted in usage - the agent treats it like the
    Ctrl-C path."""


class _PreStreamFailure(Exception):
    """A transient failure before any content token was streamed.

    Only failures raised in this wrapper are retried: nothing was displayed
    or fed to the tool parser yet, so restarting the request is safe."""

    def __init__(self, exc: Exception) -> None:
        super().__init__(str(exc))
        self.exc = exc


@dataclass
class StreamResult:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tok_per_s: float = 0.0
    elapsed_s: float = 0.0
    finish_reason: str = ""
    tokens_estimated: bool = False


class SparkClient:
    def __init__(self, base_url: str = config.BASE_URL, model: Optional[str] = None,
                 read_timeout: int = 300, on_retry=None) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.read_timeout = read_timeout
        self.last_result = StreamResult()
        # fn(attempt, wait_s, exc) called before each retry; None = silent
        self.on_retry = on_retry
        self.retry_backoff = config.RETRY_BACKOFF_S
        # Esc-abort: abort() bumps the generation and closes the in-flight
        # response so a blocked readline wakes up. Each stream attempt
        # captures the generation at entry, so an abort that fired before
        # the request started (stale) never poisons a later stream.
        self._abort_gen = 0
        self._active_resp = None
        self._vision: Optional[bool] = None  # supports_vision() caches here

    def abort(self) -> None:
        """Abort the in-flight stream (Esc). Safe to call any time."""
        self._abort_gen += 1
        resp = self._active_resp
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass

    def _aborted(self, gen: int) -> bool:
        return self._abort_gen != gen

    # -- retry helper ---------------------------------------------------------
    def _notify_retry(self, attempt: int, exc: Exception) -> None:
        wait = self.retry_backoff[attempt]
        if self.on_retry:
            self.on_retry(attempt + 1, wait, exc)
        time.sleep(wait)

    # -- plain JSON endpoints ------------------------------------------------
    def _get_json(self, path: str, timeout: float = 5.0):
        for attempt in range(len(self.retry_backoff) + 1):
            req = urllib.request.Request(self.base_url + path)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return json.loads(resp.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError as exc:
                err: Exception = ServerError(
                    f"GET {path} -> HTTP {exc.code}: {exc.read()[:300]!r}")
                retryable = exc.code in config.RETRY_HTTP_CODES
            except (urllib.error.URLError, ConnectionError, socket.timeout, OSError) as exc:
                err = TunnelDownError()
                retryable = True
            if retryable and attempt < len(self.retry_backoff):
                self._notify_retry(attempt, err)
                continue
            raise err

    def list_models(self) -> List[str]:
        data = self._get_json("/v1/models")
        try:
            return [m["id"] for m in data.get("data", [])]
        except (TypeError, KeyError) as exc:
            raise ServerError(f"/v1/models returned an unexpected payload: {data!r}") from exc

    # -- vision capability (read_image) -----------------------------------------
    # 1x1 transparent PNG - the smallest honest probe image
    _PROBE_PNG = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
                  "AAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

    def supports_vision(self) -> bool:
        """Detected once per session, then cached. A modalities flag on
        /v1/models wins if the server exposes one; otherwise a 1x1-png probe:
        llama.cpp rejects image input with an HTTP error on a text-only
        model. Any failure means False - the tool then refuses honestly
        instead of dumping base64 into a model that can't see."""
        if self._vision is None:
            self._vision = self._detect_vision()
        return self._vision

    def _detect_vision(self) -> bool:
        try:
            for m in self._get_json("/v1/models").get("data", []):
                mods = m.get("modalities")
                if isinstance(mods, dict) and "image" in (mods.get("input") or []):
                    return True
                if isinstance(mods, list) and "image" in mods:
                    return True
        except Exception:
            pass
        body = {"model": self.model, "max_tokens": 1, "stream": False,
                "messages": [{"role": "user", "content": [
                    {"type": "image_url",
                     "image_url": {"url": "data:image/png;base64," + self._PROBE_PNG}},
                    {"type": "text", "text": "ok"}]}]}
        req = urllib.request.Request(
            self.base_url + "/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()
            return True
        except Exception:
            return False

    def probe_context_limit(self) -> "tuple[int, int, str]":
        """Return (per_slot_context, server_total_context, source).

        Verified live: llama.cpp's /props reports the PER-SLOT n_ctx
        (-c 524288 -np 2 -> /props n_ctx = 262144), so never divide by
        total_slots again. Server total = per-slot x slots, for display.
        """
        try:
            props = self._get_json("/props", timeout=5.0)
        except (TunnelDownError, ServerError):
            raise
        except Exception:
            return config.FALLBACK_PER_SLOT_CTX, config.FALLBACK_PER_SLOT_CTX, "fallback"
        settings = (
            props.get("default_generation_settings")
            or props.get("default_settings")
            or {}
        )
        n_ctx = settings.get("n_ctx")
        slots = props.get("total_slots") or settings.get("n_parallel") or 1
        if isinstance(n_ctx, int) and n_ctx > 0:
            total = n_ctx * max(1, int(slots))
            return n_ctx, total, f"/props (per-slot n_ctx={n_ctx}, slots={slots})"
        return (config.FALLBACK_PER_SLOT_CTX, config.FALLBACK_PER_SLOT_CTX,
                "fallback (honest per-slot cap)")

    # -- streaming chat ------------------------------------------------------
    def chat_stream(self, messages: list, max_tokens: int,
                    temperature: float = config.DEFAULT_TEMPERATURE,
                    repeat_penalty: float = config.DEFAULT_REPEAT_PENALTY,
                    model: Optional[str] = None,
                    thinking: bool = True,
                    on_reasoning=None) -> Iterator[str]:
        """Yield visible content deltas as they arrive.

        Reasoning deltas (the model emits `reasoning_content` before the
        answer) are routed to the optional on_reasoning callback instead;
        they never enter the tool-call parser or session history, but they
        DO count toward decode-time measurement because completion_tokens
        includes them.

        thinking=False sends chat_template_kwargs.enable_thinking=false,
        which this server's chat template honors (verified live): the model
        then answers directly with no reasoning stream.

        Transient failures (connection refused/reset - WiFi flap, tunnel
        restart - or HTTP 429/5xx) are retried up to len(retry_backoff)
        times, but ONLY before the first content token has streamed; once
        text is flowing, failures surface honestly instead of duplicating
        output. A full read_timeout stall is never retried (busy slot).

        After the generator is exhausted, `self.last_result` holds real
        token counts (from include_usage) and client-measured tok/s.
        """
        body = {
            "model": model or self.model,
            "messages": messages,
            "stream": True,
            "stream_options": {"include_usage": True},
            "max_tokens": max_tokens,
            "temperature": temperature,
            "repeat_penalty": repeat_penalty,  # llama.cpp's native key (same one the cockpit proxy uses)
        }
        if not thinking:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        for attempt in range(len(self.retry_backoff) + 1):
            try:
                yield from self._stream_attempt(body, on_reasoning)
                return
            except _PreStreamFailure as wrap:
                if attempt >= len(self.retry_backoff):
                    raise wrap.exc
                self._notify_retry(attempt, wrap.exc)

    def _stream_attempt(self, body: dict, on_reasoning=None) -> Iterator[str]:
        gen = self._abort_gen  # an abort predating this attempt is stale; ignore
        req = urllib.request.Request(
            self.base_url + "/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=self.read_timeout)
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:500].decode("utf-8", "replace")
            err: Exception = ServerError(f"POST /v1/chat/completions -> HTTP {exc.code}: {detail}")
            if exc.code in config.RETRY_HTTP_CODES:
                raise _PreStreamFailure(err) from exc
            raise err
        except (urllib.error.URLError, ConnectionError, socket.timeout, OSError) as exc:
            if self._aborted(gen):
                raise StreamAborted("stream aborted (Esc)") from exc
            raise _PreStreamFailure(TunnelDownError()) from exc

        self._active_resp = resp
        if self._aborted(gen):
            # Esc landed during connect/prefill setup: closing the fresh
            # response makes the first readline below return immediately
            try:
                resp.close()
            except Exception:
                pass

        result = StreamResult()
        usage = None
        first_delta_at: Optional[float] = None
        last_delta_at: Optional[float] = None
        streamed_chars = 0
        started = time.perf_counter()
        try:
            while True:
                try:
                    line = resp.readline()
                except AttributeError:
                    # Race with abort(): HTTPResponse.close() (called by
                    # client.abort() from the Esc-watcher thread) sets
                    # self.fp = None. If that lands mid-readline, the
                    # generic io.IOBase.readline() implementation calls
                    # self.peek() -> self.fp.peek() on the now-None fp,
                    # raising a bare AttributeError instead of anything
                    # this loop already handles. Route it through the same
                    # abort/dropped-connection decision as every other
                    # read failure below, instead of letting it escape
                    # unhandled up to the REPL's catch-all.
                    if self._aborted(gen):
                        raise StreamAborted("stream aborted (Esc)")
                    raise TunnelDownError(
                        "The connection to the model dropped mid-stream.\n"
                        + config.TUNNEL_HELP)
                if not line:
                    break
                line = line.strip()
                if not line or not line.startswith(b"data:"):
                    continue
                data = line[5:].strip()
                if data == b"[DONE]":
                    break
                try:
                    obj = json.loads(data)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue  # ignore keep-alives / partial or garbled frames
                if obj.get("usage"):
                    usage = obj["usage"]
                if obj.get("error"):
                    raise ServerError(f"server error mid-stream: {obj['error']}")
                for choice in obj.get("choices", []) or []:
                    if choice.get("finish_reason"):
                        result.finish_reason = choice["finish_reason"]
                    delta = choice.get("delta") or {}
                    content = delta.get("content")
                    reasoning = delta.get("reasoning_content")
                    if content or reasoning:
                        now = time.perf_counter()
                        if first_delta_at is None:
                            first_delta_at = now
                        last_delta_at = now
                    if reasoning and on_reasoning is not None:
                        on_reasoning(reasoning)
                    if content:
                        streamed_chars += len(content)
                        yield content
        except (socket.timeout, TimeoutError):
            if self._aborted(gen):
                raise StreamAborted("stream aborted (Esc)")
            raise ServerError(
                f"no data from the model for {self.read_timeout}s - the slot may be "
                "busy (another client holds the other slot) or the server stalled."
            )
        except (urllib.error.URLError, ConnectionError, http.client.HTTPException,
                OSError) as exc:
            if self._aborted(gen):
                # our own resp.close() broke the read - this is the Esc path,
                # not a tunnel failure
                raise StreamAborted("stream aborted (Esc)") from exc
            err = TunnelDownError(
                "The connection to the model dropped mid-stream.\n" + config.TUNNEL_HELP
            )
            if first_delta_at is None:
                # nothing streamed yet: safe to retry the whole request
                raise _PreStreamFailure(TunnelDownError()) from exc
            raise err from exc
        finally:
            if self._active_resp is resp:
                self._active_resp = None
            resp.close()

        if self._aborted(gen):
            # abort landed between chunks / at EOF: raise before touching
            # last_result, so usage from a cancelled stream is never recorded
            raise StreamAborted("stream aborted (Esc)")

        result.elapsed_s = time.perf_counter() - started
        if usage:
            result.prompt_tokens = int(usage.get("prompt_tokens") or 0)
            result.completion_tokens = int(usage.get("completion_tokens") or 0)
            result.tokens_estimated = False
        else:
            # Server omitted usage; estimate completion tokens (~4 chars/tok).
            result.completion_tokens = max(1, streamed_chars // 4)
            result.tokens_estimated = True
        if result.completion_tokens and first_delta_at and last_delta_at:
            decode_s = last_delta_at - first_delta_at
            if decode_s > 0:
                result.tok_per_s = result.completion_tokens / decode_s
        self.last_result = result
