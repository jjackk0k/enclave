#!/usr/bin/env python3
# VARVEL ndmint -- the nodriver cf_clearance MINT sidecar (second, stronger mint engine).
#
# Why it exists: three Patchright+real-Chrome mints failed the honest proof gate against a
# Cloudflare managed-challenge zone (2026-08-05, manhuaus -- authorized): cf_clearance was
# issued but the zone re-challenged, and the zone served interactive ticks to a HUMAN
# session but never to the automation window. The challenge-flavor differential IS the
# detection. nodriver drives the SAME real Chrome over a raw CDP WebSocket -- a
# structurally different control plane than Playwright/Patchright -- and 2026 independent
# benchmarks found it the ONLY zero-blocked automation tool.
#
# LICENSE: nodriver is AGPL-3.0 (UltrafunkAmsterdam). It is NEVER linked or bundled into
# VARVEL: it lives in its own venv (tools/clearance/py/.venv) and runs ONLY as this
# isolated subprocess, spawned by tools/clearance/broker.mjs. Communication is exactly ONE
# JSON object on stdout -- the AGPL boundary stays at the process line.
#
# CONTRACT (mirrors the Node broker):
#   - Prints EXACTLY ONE JSON object to stdout, even on failure:
#       { ok, solved, engine: 'nodriver', cookies, ua, proofStatus, proofHeaders,
#         proofBody, tick?, reason? }
#     ok:false = the sidecar itself failed (launch/crash/hard timeout). ok:true +
#     solved:false = the flow ran but the challenge never resolved. RAW FACTS ONLY --
#     challenge classification and the mint/no-mint decision happen on the Node side.
#     tick (2026-08-11) reports the tick-path provenance: path auto-os-click |
#     operator-manual | not-required | unattended-headless | unresolved, plus
#     attempts/clicks -- the Node broker surfaces it verbatim (detectability accounting).
#   - NEVER hangs past its timeout: the whole flow is wrapped in a hard asyncio budget of
#     --timeout-s + 45s grace, and the browser is ALWAYS closed (finally: browser.stop()).
#   - The poll is PASSIVE (read-only evaluates/cookie reads). Headed is the default and is
#     doctrine: the operator clicks interactive ticks in the VISIBLE window, which must
#     stay open through the interactive flow up to --timeout-s. --headless exists for
#     smoke tests and is measurably weaker against 2026 bot gates.
#   - Flash-close doctrine (same as the Node broker's 2026-08-05 fix): a BLANK/loading
#     document (about:blank, redirect interstitial, <40 chars of text) counts as STILL
#     CHALLENGED -- never resolve on an empty DOM.
#   - --proxy (2026-08-10): the mint rides the SAME egress the ghost-governed tools ride.
#     cf_clearance is IP-bound to the MINT egress, so a direct-minted cookie was challenged
#     on every chain-ridden probe (the manhuaus rematch burned 24/24 this way). The broker
#     passes the ghost chain's canonical single-hop URL and it is applied to Chrome as
#     --proxy-server. KNOWN GAPS (live validation pending): (a) Chrome over socks5://
#     resolves DNS at the proxy by default -- verify no local-DNS leak on the live chain;
#     (b) Chrome does not support SOCKS5 auth -- credentialed hops are untested (Mullvad
#     in-tunnel has no auth); (c) exactly ONE hop is expressible -- the Node side refuses
#     multi-hop chains fail-closed before the sidecar is ever spawned.
#
# Verified against the installed nodriver 0.50.3 (tools/clearance/py/.venv/Lib/
# site-packages/nodriver): uc.start(user_data_dir, headless, browser_executable_path)
# (core/util.py:33); browser.get(url) -> Tab (core/browser.py:182); tab.evaluate(expr)
# -> deep-serialized value (core/tab.py:873); tab.get_content() (core/tab.py:1108);
# tab.url via Tab.__getattr__ -> target.url (core/tab.py:2047); browser.cookies.get_all()
# -> [cdp.network.Cookie] (core/browser.py:656); tab.add_handler(cdp.network.
# ResponseReceived, sync_cb(event)) (core/connection.py:168, dispatch at :511-528);
# tab.send(cdp.network.enable()/get_response_body(id)) (cdp/network.py:3531/:3651);
# browser.stop() (core/browser.py:589).
#
# INSTALL NOTE (2026-08-05): EVERY current nodriver release (verified 0.48.1, 0.50.2,
# 0.50.3) ships a generated cdp/network.py containing a lone latin-1 0xB1 byte in the
# cookie-expires comment ("(±Inf)") with no PEP-263 coding declaration -- `import
# nodriver` raises SyntaxError on Python 3.14 (upstream issue
# https://github.com/ultrafunkamsterdam/nodriver/issues/35, unfixed on main). The
# upstream-blessed workaround is applied to this venv: convert that ONE comment byte to
# UTF-8 (0xC2 0xB1). If the venv is ever rebuilt, re-apply it:
#   <venv>/Scripts/python -c "p=r'<venv>/Lib/site-packages/nodriver/cdp/network.py'; d=open(p,'rb').read(); open(p,'wb').write(d.replace(b'(\xb1Inf)', '(\u00b1Inf)'.encode('utf-8')))"
# (or re-run the broker's detectNodriver probe, which reports the import failure honestly).

import argparse
import asyncio
import base64
import ctypes
import json
import os
import random
import re
import sys
import time

import nodriver as uc

# Managed-challenge markers, same family as engine/challenge.mjs: the JS interstitial,
# the challenge-platform bundle, cf-chl cookies/scripts, and the Turnstile iframe.
CHALLENGE_MARKERS = re.compile(
    r"just a moment|challenge-platform|cf-chl|cf_chl_|challenges\.cloudflare\.com/turnstile"
    r"|cf-turnstile|checking your browser|verify you are human",
    re.IGNORECASE,
)
BLANK_URL = re.compile(r"^about:(blank|srcdoc)", re.IGNORECASE)
TAGS_AND_SPACE = re.compile(r"<[^>]+>|\s+")
POLL_S = 1.0
PROOF_BODY_CHARS = 4096
HARD_GRACE_S = 45  # hard-kill budget beyond --timeout-s; the process never lives past it
# Render-mode caps (the Node side reports the truncated flags -- a cap is a boundary,
# never a silent loss). A marker the operator asserts on should live well under these.
RENDER_DOM_CHARS = 512 * 1024   # wire body + rendered DOM
RENDER_TEXT_CHARS = 128 * 1024  # visible text


def strip_text(html):
    return TAGS_AND_SPACE.sub("", html)


def serialize_cookies(raw):
    out = []
    for c in raw or []:
        try:
            out.append({
                "name": str(getattr(c, "name", "") or ""),
                "value": str(getattr(c, "value", "") or ""),
                "domain": str(getattr(c, "domain", "") or ""),
                "path": str(getattr(c, "path", "") or "/"),
                "secure": bool(getattr(c, "secure", False)),
                "httpOnly": bool(getattr(c, "http_only", False)),
                "expires": float(getattr(c, "expires", 0) or 0),
            })
        except Exception:
            continue
    return out


async def collect_cookies(browser):
    try:
        return serialize_cookies(await browser.cookies.get_all())
    except Exception:
        return []


async def poll_resolved(tab, browser, deadline, ticker=None):
    """Passive poll until the document no longer looks like a challenge. cf_clearance is
    TRACKED but never decides resolution -- it can arrive a tick EARLY, while the
    challenge page is still up (2026-08-10 manhuaus rematch, operator-observed).
    Returns (resolved, saw_clearance, last_kind). A page mid-navigation
    (evaluate throws) and a blank/loading DOM both count as STILL challenged -- a
    navigation artifact is never called 'resolved' (the flash-close doctrine).
    ticker: an optional AutoTicker stepped once per iteration while the page is
    still challenged (2026-08-11 OS-level auto-tick) -- the poll itself stays
    passive and the deadline is never extended by tick attempts."""
    saw_clearance = False
    last_kind = "unknown"
    while time.monotonic() < deadline:
        try:
            cookies = await browser.cookies.get_all()
            saw_clearance = any(
                getattr(c, "name", "") == "cf_clearance" for c in (cookies or [])
            )
        except Exception:
            pass
        html = None
        page_url = ""
        try:
            page_url = str(tab.url or "")
            probe = await tab.evaluate(
                "document.title + '\\n' + (document.documentElement ? document.documentElement.innerHTML : '')"
            )
            if isinstance(probe, str):
                html = probe
        except Exception:
            html = None  # navigation in flight -> still challenged
        if html is None:
            last_kind = "navigation-in-flight"
        else:
            blank = bool(BLANK_URL.match(page_url)) or len(strip_text(html)) < 40
            if blank:
                last_kind = "document-loading"
            elif CHALLENGE_MARKERS.search(html):
                last_kind = "challenge-markers"
            else:
                return True, saw_clearance, "clean"
        # 2026-08-10 (Jack's catch, manhuaus rematch): cf_clearance can arrive a tick
        # EARLY -- the cookie appears while the challenge page is still up (a second tick
        # pending). The old early-return here declared 'resolved' on the cookie alone, so
        # the proof navigation ran against a still-challenged session (403) and the
        # window closed under the operator's mouse. Resolution is decided by the PAGE
        # STATE alone; the cookie is merely tracked.
        if ticker is not None:
            try:
                await ticker.step()
            except Exception:
                pass  # a tick hiccup never breaks the poll (and never extends it)
        await asyncio.sleep(min(POLL_S, max(0.05, deadline - time.monotonic())))
    return False, saw_clearance, last_kind


async def proof_navigation(tab, origin, budget_s):
    """ONE confirmation navigation of the zone root in the SAME tab. Captures the raw
    facts the Node proof gate needs: {status, headers-as-dict, first 4KB of body} of the
    Document response (wire body when Network.getResponseBody can still reach it, else the
    post-navigation DOM -- either way it is the REAL response the zone gave us)."""
    captured = {}

    def on_response(event):
        try:
            if event.type_ == uc.cdp.network.ResourceType.DOCUMENT:
                captured["request_id"] = event.request_id
                captured["status"] = int(event.response.status)
                captured["headers"] = {
                    str(k): str(v) for k, v in dict(event.response.headers).items()
                }
        except Exception:
            pass

    status, headers, body = 0, {}, ""
    try:
        await tab.send(uc.cdp.network.enable())
    except Exception:
        pass
    try:
        tab.add_handler(uc.cdp.network.ResponseReceived, on_response)
    except Exception:
        pass
    try:
        await tab.get(origin + "/")
    except Exception:
        pass  # a rejected navigate is not fatal: the event poll below is the arbiter
    wait_until = time.monotonic() + max(1.0, budget_s)
    while time.monotonic() < wait_until and "request_id" not in captured:
        await asyncio.sleep(0.1)
    if "request_id" in captured:
        status = captured.get("status", 0)
        headers = captured.get("headers", {})
        try:
            raw_body, was_b64 = await tab.send(
                uc.cdp.network.get_response_body(captured["request_id"])
            )
            body = (
                base64.b64decode(raw_body).decode("utf-8", "replace")
                if was_b64
                else str(raw_body)
            )
        except Exception:
            body = ""
    if not body:
        try:
            content = await tab.get_content()
            body = content if isinstance(content, str) else ""
        except Exception:
            body = ""
    return status, headers, body[:PROOF_BODY_CHARS]


# ---------------------------------------------------------------------------
# AUTO-TICK (2026-08-11): OS-LEVEL Turnstile checkbox tick -- NO CDP-synthesized
# click. Cloudflare catches CDP-dispatched clicks near-deterministically via a
# screenX/screenY coordinate differential inside the cross-domain iframe (this
# burns nodriver/patchright/playwright/selenium alike), so the click here is a
# real OS input event on the VISIBLE window: ctypes user32 SetCursorPos +
# mouse_event from THIS process -- indistinguishable from a human at the input
# layer. Humanization: a short cursor drift into the target, then a random
# 300-900ms dwell, then down/up. The checkbox is DOM-located (the nodriver
# verify_cf approach minus the opencv template dependency): it lives inside the
# cross-domain challenges.cloudflare.com iframe, ~30px from its left edge,
# vertically centered; page->screen conversion uses the window's screenX/screenY
# + the outer/inner frame delta, physical-ized via devicePixelRatio.
# OPERATOR OVERRIDE PRESERVED: --manual-tick (VARVEL_CF_MANUAL_TICK=1), headless
# mode, a non-Windows host, or 3 failed attempts (initial + 2 retries, fresh
# locate each) all fall back to the passive operator-tick wait below -- the
# overall --timeout-s budget is NEVER extended by tick attempts. The JSON verdict
# carries facts.tick.path = auto-os-click | operator-manual | not-required |
# unattended-headless | unresolved -- provenance matters for detectability
# accounting, and the Node broker surfaces it verbatim.
# ---------------------------------------------------------------------------
TICK_MAX_ATTEMPTS = 3  # initial attempt + up to 2 retries, fresh locate each time
TICK_DWELL_S = (0.3, 0.9)  # humanization: pre-click dwell, uniform random
TICK_DRIFT_STEPS = (3, 7)  # humanization: intermediate cursor moves before the target
TICK_SETTLE_S = 5.0  # after a click, give CF this long to consume it before re-locating
TICK_CHECKBOX_OFFSET_X = 30  # the checkbox sits ~30px from the widget iframe's left edge

# One evaluate: find the VISIBLE challenges.cloudflare.com iframe, aim at the
# checkbox inside it, and convert page coords to screen coords (DIPs) with the
# devicePixelRatio alongside for physical-ization on scaled displays.
LOCATE_CHECKBOX_JS = (
    "(function () {"
    "  var cand = document.querySelectorAll('iframe[src*=\"challenges.cloudflare.com\"]');"
    "  var ifr = null;"
    "  for (var i = 0; i < cand.length; i++) {"
    "    var r = cand[i].getBoundingClientRect();"
    "    if (r.width > 40 && r.height > 30 && r.bottom > 0 && r.right > 0"
    "        && r.top < window.innerHeight && r.left < window.innerWidth) { ifr = cand[i]; break; }"
    "  }"
    "  if (!ifr) return null;"
    "  var r = ifr.getBoundingClientRect();"
    "  return {"
    "    x: window.screenX + (window.outerWidth - window.innerWidth) / 2 + r.left + " + str(TICK_CHECKBOX_OFFSET_X) + ","
    "    y: window.screenY + window.outerHeight - window.innerHeight + r.top + r.height / 2,"
    "    dpr: window.devicePixelRatio || 1"
    "  };"
    "})()"
)


def _user32():
    """The Windows input subsystem, or None anywhere else (auto-tick is a
    Windows-only path; every other platform keeps the operator-tick wait)."""
    if os.name != "nt":
        return None
    try:
        return ctypes.windll.user32
    except Exception:
        return None


def foreground_browser_window(pid, user32=None):
    """Best-effort: find the visible top-level window owned by the browser process
    and pull it to the foreground, so the OS click lands on the checkbox and not
    on whatever window is occluding it. Returns True when a window was found and
    SetForegroundWindow succeeded. Never raises."""
    if user32 is None:
        user32 = _user32()
    if user32 is None or not pid:
        return False
    try:
        hwnds = []

        enum_proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def cb(hwnd, _lparam):
            try:
                if user32.IsWindowVisible(hwnd):
                    wpid = ctypes.c_ulong(0)
                    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
                    if wpid.value == pid and not user32.GetWindow(hwnd, 4):  # 4 = GW_OWNER
                        hwnds.append(hwnd)
            except Exception:
                pass
            return True

        user32.EnumWindows(enum_proc(cb), 0)
        if not hwnds:
            return False
        hwnd = hwnds[0]
        if user32.IsIconic(hwnd):
            user32.ShowWindow(hwnd, 9)  # 9 = SW_RESTORE
        try:
            # last-input trick: a token ALT press makes this process eligible to
            # steal the foreground (SetForegroundWindow silently no-ops otherwise)
            user32.keybd_event(0x12, 0, 0, 0, 0)
            user32.keybd_event(0x12, 0, 2, 0, 0)  # 2 = KEYEVENTF_KEYUP
        except Exception:
            pass
        return bool(user32.SetForegroundWindow(hwnd))
    except Exception:
        return False


def os_click(x, y, user32=None, sleep=None, uniform=None):
    """OS-LEVEL left click at physical screen coords (x, y): drift the cursor in
    from its current position through a few jittered intermediate points, dwell
    300-900ms like a human settling on the target, then mouse_event down/up.
    This is NOT a CDP-synthesized event -- it enters the same OS input path a
    hardware mouse does. sleep/uniform/user32 are injectable (tests). Returns
    True when the final positioning and both button events were issued."""
    if sleep is None:
        sleep = time.sleep
    if uniform is None:
        uniform = random.uniform
    if user32 is None:
        user32 = _user32()
    if user32 is None:
        return False
    try:
        x = int(round(x))
        y = int(round(y))
        # DPI honesty: report physical pixels so scaled displays don't misaim.
        try:
            user32.SetProcessDpiAwarenessContext(-4)  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        except Exception:
            try:
                user32.SetProcessDPIAware()
            except Exception:
                pass

        class POINT(ctypes.Structure):
            _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]

        sx, sy = x, y
        try:
            pt = POINT(0, 0)
            if user32.GetCursorPos(ctypes.byref(pt)):
                sx, sy = pt.x, pt.y
        except Exception:
            pass
        # cursor drift: a few jittered intermediate moves, never a teleport-click
        steps = max(1, int(uniform(TICK_DRIFT_STEPS[0], TICK_DRIFT_STEPS[1] + 1)))
        for i in range(1, steps + 1):
            t = i / float(steps + 1)
            cx = sx + (x - sx) * t + uniform(-6.0, 6.0)
            cy = sy + (y - sy) * t + uniform(-6.0, 6.0)
            user32.SetCursorPos(int(round(cx)), int(round(cy)))
            sleep(uniform(0.01, 0.05))
        if user32.SetCursorPos(x, y) == 0:
            return False
        sleep(uniform(TICK_DWELL_S[0], TICK_DWELL_S[1]))  # the humanization dwell
        user32.mouse_event(0x0002, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTDOWN
        sleep(uniform(0.06, 0.14))  # human press duration
        user32.mouse_event(0x0004, 0, 0, 0, 0)  # MOUSEEVENTF_LEFTUP
        return True
    except Exception:
        return False


async def locate_checkbox_point(tab):
    """Fresh DOM-locate of the Turnstile checkbox -> physical screen coords, or
    None when no visible challenges.cloudflare.com iframe is on screen."""
    try:
        v = await tab.evaluate(LOCATE_CHECKBOX_JS)
    except Exception:
        return None
    if not isinstance(v, dict):
        return None
    try:
        dpr = float(v.get("dpr") or 1) or 1.0
        return float(v["x"]) * dpr, float(v["y"]) * dpr
    except Exception:
        return None


class AutoTicker:
    """The auto-tick attempt budget, driven one step() per poll-loop iteration.
    Every step does a FRESH locate (the widget re-renders); a located checkbox
    with attempts left triggers bring-to-front + one OS click, then a settle
    window before the next attempt. TICK_MAX_ATTEMPTS caps the whole phase
    (initial + 2 retries); once exhausted, or when auto-tick is disabled, the
    poll simply continues as today's passive operator-tick wait. provenance()
    reports honestly which path passed the challenge. Never raises."""

    def __init__(self, tab, browser, enabled, headed=True, click=None, locate=None, monotonic=None):
        self.tab = tab
        self.browser = browser
        self.enabled = bool(enabled)
        self.headed = bool(headed)
        self.attempts = 0
        self.clicks = 0
        self.saw_checkbox = False
        self.exhausted = False
        self._next_attempt_at = 0.0
        self._click = click or os_click
        self._locate = locate or locate_checkbox_point
        self._monotonic = monotonic or time.monotonic

    async def step(self):
        point = None
        try:
            point = await self._locate(self.tab)
        except Exception:
            point = None
        if point:
            self.saw_checkbox = True
        if not self.enabled or self.exhausted or not point:
            return
        now = self._monotonic()
        if now < self._next_attempt_at:
            return
        if self.attempts >= TICK_MAX_ATTEMPTS:
            self.exhausted = True  # auto gave up: the operator-tick wait carries on
            return
        self.attempts += 1
        try:
            await self.tab.bring_to_front()
        except Exception:
            pass
        try:
            foreground_browser_window(getattr(self.browser, "_process_pid", None))
        except Exception:
            pass
        try:
            if self._click(point[0], point[1]):
                self.clicks += 1
        except Exception:
            pass
        self._next_attempt_at = self._monotonic() + TICK_SETTLE_S

    def provenance(self, resolved):
        if not resolved:
            return "unresolved"
        if self.clicks > 0 and not self.exhausted:
            return "auto-os-click"
        if not self.saw_checkbox:
            return "not-required"  # the challenge solved passively, no interactive tick ever appeared
        if not self.headed:
            return "unattended-headless"
        return "operator-manual"  # auto disabled or exhausted: a human ticked the visible window


def origin_of(url):
    m = re.match(r"^(https?)://([^/?#]+)", url or "", re.IGNORECASE)
    if not m:
        raise ValueError("ndmint needs an absolute http(s) URL -- got %r" % (url,))
    return m.group(1).lower() + "://" + m.group(2)


# ---------------------------------------------------------------------------
# RENDER MODE (--render): the one-shot headless navigate + screenshot + DOM dump
# for tools/rendercheck.mjs (2026-08-11). ADDITIVE to the mint flow -- nothing above
# is touched. The rendercheck lesson: the AI proved a change server-side while the
# operator's CACHED browser showed nothing -- this mode renders the page the way a
# real visitor's browser would (same real Chrome, same raw-CDP control plane) so the
# AI can SEE its own target-side change. Doctrine carried over from the mint flow:
#   - EXACTLY ONE JSON object on stdout, RAW FACTS ONLY -- challenge classification
#     and all verdicts happen on the Node side.
#   - HEADLESS, always (the visible-window sibling is cfbrowser; a render needs no
#     human in the loop -- it rides an ALREADY-vaulted clearance).
#   - Cookies are seeded BEFORE navigation from a JSON FILE (--cookies) -- live
#     credentials never ride argv/process lists.
#   - --proxy is applied to Chrome as --proxy-server at LAUNCH (before any window/
#     tab opens), the same egress-parity mechanism as the mint leg.
#   - The screenshot is written to --shot-out DIRECTLY (path + byte size in the JSON
#     verdict; image bytes never ride stdout).
# ---------------------------------------------------------------------------

def cookie_params(raw):
    """JSON cookie objects -> cdp CookieParams, tolerant per-entry (a bad entry is
    skipped, not fatal). Accepts the vault/jar shape: {name, value, domain?, path?,
    secure?, httpOnly?, expires?}."""
    out = []
    for c in raw or []:
        try:
            kw = {"name": str(c["name"]), "value": str(c["value"])}
            if c.get("domain"):
                kw["domain"] = str(c["domain"])
            if c.get("path"):
                kw["path"] = str(c["path"])
            if c.get("secure") is not None:
                kw["secure"] = bool(c["secure"])
            if c.get("httpOnly") is not None:
                kw["http_only"] = bool(c["httpOnly"])
            exp = c.get("expires")
            if isinstance(exp, (int, float)) and exp > 0:
                kw["expires"] = uc.cdp.network.TimeSinceEpoch(float(exp))
            out.append(uc.cdp.network.CookieParam(**kw))
        except Exception:
            continue
    return out


async def settle_readable(tab, deadline):
    """Passive poll until the document is READABLE (evaluate works + >=40 chars of
    text) or the deadline. Returns (readable, last_kind). The blank-document doctrine,
    verbatim: a page mid-navigation and an about:blank/loading DOM are LOADING states,
    never classification inputs. RAW FACTS ONLY -- no challenge markers here; the Node
    side classifies."""
    last_kind = "unknown"
    while time.monotonic() < deadline:
        html = None
        page_url = ""
        try:
            page_url = str(tab.url or "")
            probe = await tab.evaluate(
                "document.title + '\\n' + (document.documentElement ? document.documentElement.innerHTML : '')"
            )
            if isinstance(probe, str):
                html = probe
        except Exception:
            html = None  # navigation in flight -> still loading
        if html is None:
            last_kind = "navigation-in-flight"
        else:
            blank = bool(BLANK_URL.match(page_url)) or len(strip_text(html)) < 40
            if blank:
                last_kind = "document-loading"
            else:
                return True, "readable"
        await asyncio.sleep(min(POLL_S, max(0.05, deadline - time.monotonic())))
    return False, last_kind


async def run_render(args):
    """One-shot render: seed cookies, navigate the (already cache-busted by the Node
    side) URL, settle, then dump the wire body + rendered DOM + visible text + every
    Document response's status/headers (cf-cache-status et al. -- the cache-cloak
    evidence) + a viewport PNG screenshot. Never hangs past --timeout-s + grace; the
    browser is ALWAYS closed."""
    if not re.match(r"^https?://", args.url or "", re.IGNORECASE):
        raise ValueError("render mode needs an absolute http(s) URL -- got %r" % (args.url,))
    browser_args = [
        "--disable-background-networking",
        "--disable-component-update",
    ]
    if args.proxy:
        # Egress parity (the mint-leg doctrine): the render rides the SAME ghost chain
        # the clearance is bound to, applied to Chrome BEFORE any window opens.
        browser_args.append("--proxy-server=" + args.proxy)
    browser = await uc.start(
        user_data_dir=args.profile,
        headless=True,  # render mode is the headless one-shot; headed is cfbrowser's tier
        browser_executable_path=args.chrome,
        browser_args=browser_args,
    )
    try:
        # Seed the session BEFORE navigation. A cookie file we cannot read plainly is a
        # refusal, never a silent cookieless render (the sessride jar doctrine).
        seeded = 0
        if args.cookies:
            try:
                with open(args.cookies, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
                params = cookie_params(raw if isinstance(raw, list) else [])
                if params:
                    await browser.cookies.set_all(params)
                    seeded = len(params)
            except Exception as e:
                return {
                    "ok": False,
                    "engine": "nodriver",
                    "mode": "render",
                    "reason": (
                        "could not seed cookies from %s (%s: %s) -- refusing to render "
                        "WITHOUT the session the caller believes is riding"
                        % (args.cookies, type(e).__name__, e)
                    ),
                }

        # Capture EVERY Document response (redirect hops included): the LAST one is the
        # final page; its headers carry the cache evidence (cf-cache-status/age/cf-ray).
        captured = []

        def on_response(event):
            try:
                if event.type_ == uc.cdp.network.ResourceType.DOCUMENT:
                    captured.append({
                        "request_id": event.request_id,
                        "url": str(event.response.url),
                        "status": int(event.response.status),
                        "headers": {
                            str(k): str(v) for k, v in dict(event.response.headers).items()
                        },
                    })
            except Exception:
                pass

        tab = await browser.get("about:blank")
        try:
            await tab.send(uc.cdp.network.enable())
        except Exception:
            pass
        try:
            tab.add_handler(uc.cdp.network.ResponseReceived, on_response)
        except Exception:
            pass
        try:
            await tab.get(args.url)
        except Exception:
            pass  # a rejected navigate is not fatal: the settle poll below is the arbiter

        deadline = time.monotonic() + max(1.0, float(args.settle_s))
        readable, last_kind = await settle_readable(tab, deadline)

        final_url = ""
        try:
            final_url = str(tab.url or "")
        except Exception:
            final_url = ""
        title = ""
        try:
            t = await tab.evaluate("document.title")
            title = t if isinstance(t, str) else ""
        except Exception:
            title = ""
        dom = ""
        try:
            content = await tab.get_content()
            dom = content if isinstance(content, str) else ""
        except Exception:
            dom = ""
        text = ""
        try:
            tx = await tab.evaluate("document.body ? document.body.innerText : ''")
            text = tx if isinstance(tx, str) else ""
        except Exception:
            text = ""

        doc = captured[-1] if captured else {}
        status = doc.get("status", 0)
        headers = doc.get("headers", {})
        wire = ""
        if doc.get("request_id"):
            try:
                raw_body, was_b64 = await tab.send(
                    uc.cdp.network.get_response_body(doc["request_id"])
                )
                wire = (
                    base64.b64decode(raw_body).decode("utf-8", "replace")
                    if was_b64
                    else str(raw_body)
                )
            except Exception:
                wire = ""  # the wire body may already be evicted; the DOM dump stands in

        screenshot = None
        if args.shot_out:
            try:
                spath = await tab.save_screenshot(args.shot_out, format="png")
                screenshot = {"path": str(spath), "bytes": os.path.getsize(spath)}
            except Exception as e:
                screenshot = {"error": "screenshot failed (%s: %s)" % (type(e).__name__, e)}

        return {
            "ok": True,
            "engine": "nodriver",
            "mode": "render",
            "requestedUrl": args.url,
            "finalUrl": final_url,
            "title": title,
            "status": status,
            "headers": headers,
            "documentResponses": [
                {"url": c["url"], "status": c["status"]} for c in captured
            ],
            "wireHtml": wire[:RENDER_DOM_CHARS],
            "domHtml": dom[:RENDER_DOM_CHARS],
            "visibleText": text[:RENDER_TEXT_CHARS],
            "truncated": {
                "wire": len(wire) > RENDER_DOM_CHARS,
                "dom": len(dom) > RENDER_DOM_CHARS,
                "text": len(text) > RENDER_TEXT_CHARS,
            },
            "settle": {"readable": readable, "lastKind": last_kind},
            "cookiesSeeded": seeded,
            "screenshot": screenshot,
        }
    finally:
        try:
            browser.stop()
        except Exception:
            pass


async def run(args):
    origin = origin_of(args.url)
    browser_args = [
        # opsec: keep the mint window from chattering to Google in the background
        "--disable-background-networking",
        "--disable-component-update",
    ]
    if args.proxy:
        # The mint rides the ghost chain (2026-08-10): cf_clearance binds to the MINT
        # egress IP, so the browser must exit where the governed tools exit.
        browser_args.append("--proxy-server=" + args.proxy)
    browser = await uc.start(
        user_data_dir=args.profile,
        headless=args.headless,
        browser_executable_path=args.chrome,
        browser_args=browser_args,
    )
    try:
        tab = await browser.get(args.url)
        deadline = time.monotonic() + args.timeout_s
        # Auto-tick decision (2026-08-11): the OS-level tick runs only on a VISIBLE
        # window on Windows with the input subsystem reachable, and NEVER when the
        # operator asked for the manual path. Every other case is today's passive
        # operator-tick wait, unchanged, inside the SAME deadline.
        manual_tick = bool(getattr(args, "manual_tick", False)) or os.environ.get(
            "VARVEL_CF_MANUAL_TICK", ""
        ).strip().lower() in ("1", "true")
        auto_tick = (not manual_tick) and (not args.headless) and (_user32() is not None)
        ticker = AutoTicker(tab, browser, enabled=auto_tick, headed=not args.headless)
        resolved, saw_clearance, last_kind = await poll_resolved(tab, browser, deadline, ticker)
        tick_facts = {
            "path": ticker.provenance(resolved),
            "attempts": ticker.attempts,
            "clicks": ticker.clicks,
            "sawCheckbox": ticker.saw_checkbox,
            "auto": auto_tick,
            "manual": manual_tick,
        }
        ua = None
        try:
            probe = await tab.evaluate("navigator.userAgent")
            ua = probe if isinstance(probe, str) and probe else None
        except Exception:
            ua = None
        cookies = await collect_cookies(browser)
        if not resolved:
            return {
                "ok": True,
                "solved": False,
                "engine": "nodriver",
                "cookies": cookies,
                "ua": ua,
                "proofStatus": 0,
                "proofHeaders": {},
                "proofBody": "",
                "tick": tick_facts,
                "reason": (
                    "managed challenge did not resolve before the time budget ran out "
                    "(last DOM classification: %s; %s; tick: %s, %d attempt(s), %d OS click(s))"
                    % (
                        last_kind,
                        "cf_clearance appeared but the page still looks challenged"
                        if saw_clearance
                        else "no cf_clearance observed",
                        tick_facts["path"],
                        tick_facts["attempts"],
                        tick_facts["clicks"],
                    )
                ),
            }
        remaining = max(1.0, deadline - time.monotonic())
        status, headers, body = await proof_navigation(tab, origin, min(remaining, 30.0))
        return {
            "ok": True,
            "solved": True,
            "engine": "nodriver",
            "cookies": cookies,
            "ua": ua,
            "proofStatus": status,
            "proofHeaders": headers,
            "proofBody": body,
            "tick": tick_facts,
        }
    finally:
        try:
            browser.stop()
        except Exception:
            pass


def main():
    p = argparse.ArgumentParser(
        description="VARVEL nodriver cf_clearance mint sidecar -- ONE JSON object to stdout, raw facts only."
    )
    p.add_argument("url", help="absolute http(s) URL of the challenged zone page")
    p.add_argument("--chrome", required=True, help="path to the REAL Chrome binary")
    p.add_argument("--profile", required=True, help="persistent Chrome profile dir")
    p.add_argument("--timeout-s", type=int, default=150,
                   help="interactive budget in seconds (default 150); headed mode holds the window open this long for operator ticks")
    p.add_argument("--headless", action="store_true",
                   help="headless mode (default HEADED -- a visible window is doctrine; interactive ticks need a human)")
    p.add_argument("--manual-tick", action="store_true",
                   help="disable the OS-level auto-tick (also honored: env VARVEL_CF_MANUAL_TICK=1) -- the operator ticks interactive checkboxes in the VISIBLE window, exactly as before the auto-tick existed")
    p.add_argument("--proxy", default=None,
                   help="single-hop proxy URL the mint rides (e.g. socks5://10.64.0.1:1080 -- the ghost chain), applied to Chrome as --proxy-server so cf_clearance binds to the chain exit the governed tools use")
    p.add_argument("--render", action="store_true",
                   help="one-shot RENDER mode (tools/rendercheck.mjs): headless navigate + settle + wire/DOM/text dump + viewport PNG screenshot. Raw facts only; all classification and verdicts happen on the Node side.")
    p.add_argument("--shot-out", default=None,
                   help="render mode: PNG screenshot output path (viewport capture; bytes go to the FILE, never stdout)")
    p.add_argument("--cookies", default=None,
                   help="render mode: path to a JSON array of cookie objects to seed BEFORE navigation (a FILE -- live credentials never ride argv/process lists)")
    p.add_argument("--settle-s", type=float, default=10.0,
                   help="render mode: max seconds to wait for a readable document (default 10)")
    args = p.parse_args()
    try:
        facts = asyncio.run(asyncio.wait_for(run_render(args) if args.render else run(args), timeout=args.timeout_s + HARD_GRACE_S))
    except asyncio.TimeoutError:
        facts = {
            "ok": False,
            "engine": "nodriver",
            "reason": "sidecar hard timeout (--timeout-s %d + %ds grace) exceeded -- browser force-closed, honestly reported"
                      % (args.timeout_s, HARD_GRACE_S),
        }
    except Exception as e:
        facts = {
            "ok": False,
            "engine": "nodriver",
            "reason": "sidecar crashed: %s: %s" % (type(e).__name__, e),
        }
    sys.stdout.write(json.dumps(facts) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
