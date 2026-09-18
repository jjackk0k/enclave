#!/usr/bin/env python3
# VARVEL ndtick -- hermetic unit tests for the OS-level auto-tick in ndmint.py
# (2026-08-11). NO real browser, NO real input events, NO network: user32, the
# clock, sleep, and the RNG are all injected fakes. Run with the sidecar venv
# python (ndmint imports nodriver):
#   tools/clearance/py/.venv/Scripts/python tools/clearance/py/test_ndtick.py
# The Node suite (test/nodriver.test.mjs) shells out to this file when the venv
# is present and skips it otherwise.

import asyncio
import types
import unittest
from unittest import mock

import ndmint


class FakeUser32:
    """Records every input-subsystem call; GetCursorPos declines (os_click then
    drifts from the target itself -- harmless for the pins below)."""

    def __init__(self, set_cursor_ok=1):
        self.calls = []  # [(name, args...)]
        self.set_cursor_ok = set_cursor_ok

    def SetProcessDpiAwarenessContext(self, ctx):
        self.calls.append(("SetProcessDpiAwarenessContext", ctx))
        return 1

    def SetProcessDPIAware(self):
        self.calls.append(("SetProcessDPIAware",))
        return 1

    def GetCursorPos(self, ref):
        self.calls.append(("GetCursorPos",))
        return 0  # falsy: os_click keeps the target as the drift origin

    def SetCursorPos(self, x, y):
        self.calls.append(("SetCursorPos", x, y))
        return self.set_cursor_ok

    def mouse_event(self, flags, dx, dy, data, extra):
        self.calls.append(("mouse_event", flags, dx, dy, data, extra))
        return None


class FakeTab:
    def __init__(self, located=None, raise_on_evaluate=False):
        self.located = located
        self.raise_on_evaluate = raise_on_evaluate
        self.brought_to_front = 0
        self.evaluates = 0

    async def bring_to_front(self):
        self.brought_to_front += 1

    async def evaluate(self, expr):
        self.evaluates += 1
        if self.raise_on_evaluate:
            raise RuntimeError("navigation in flight")
        return self.located


def midpoint(a, b):
    return (a + b) / 2.0


class OsClickTests(unittest.TestCase):
    def test_click_shape_drift_dwell_press_release(self):
        u32 = FakeUser32()
        sleeps = []
        ok = ndmint.os_click(500, 300, user32=u32, sleep=sleeps.append, uniform=midpoint)
        self.assertTrue(ok)
        pos_calls = [c for c in u32.calls if c[0] == "SetCursorPos"]
        # drift steps + the final landing; midpoint uniform -> int((3+8)/2) = 5 drift steps
        self.assertEqual(len(pos_calls), 5 + 1)
        self.assertEqual(pos_calls[-1], ("SetCursorPos", 500, 300))  # lands exactly on target
        events = [c for c in u32.calls if c[0] == "mouse_event"]
        self.assertEqual([c[1] for c in events], [0x0002, 0x0004])  # LEFTDOWN then LEFTUP
        self.assertEqual(pos_calls[-1][0], "SetCursorPos")
        # order: every SetCursorPos precedes both button events (drift/dwell BEFORE the click)
        first_event_idx = next(i for i, c in enumerate(u32.calls) if c[0] == "mouse_event")
        self.assertTrue(all(c[0] != "mouse_event" for c in u32.calls[:first_event_idx]))
        # sleeps: 5 drift pauses, then the dwell, then the press hold
        self.assertEqual(len(sleeps), 5 + 2)
        self.assertAlmostEqual(sleeps[-2], 0.6)  # dwell midpoint of [0.3, 0.9]
        self.assertAlmostEqual(sleeps[-1], 0.1)  # press-hold midpoint of [0.06, 0.14]

    def test_dwell_bounds_are_300_to_900ms(self):
        for bound, expect in ((lambda a, b: a, 0.3), (lambda a, b: b, 0.9)):
            sleeps = []
            ok = ndmint.os_click(10, 10, user32=FakeUser32(), sleep=sleeps.append, uniform=bound)
            self.assertTrue(ok)
            self.assertAlmostEqual(sleeps[-2], expect)  # the dwell sits right before the press hold

    def test_dpi_awareness_is_set_before_clicking(self):
        u32 = FakeUser32()
        ndmint.os_click(1, 1, user32=u32, sleep=lambda s: None, uniform=midpoint)
        self.assertEqual(u32.calls[0][0], "SetProcessDpiAwarenessContext")

    def test_no_user32_is_an_honest_false(self):
        # user32=None resolves the REAL input subsystem; simulate a non-Windows host
        # (or one where windll is unreachable) by patching the resolver to None.
        with mock.patch.object(ndmint, "_user32", return_value=None):
            self.assertFalse(ndmint.os_click(1, 1, sleep=lambda s: None))

    def test_final_positioning_failure_is_an_honest_false_no_button_events(self):
        u32 = FakeUser32(set_cursor_ok=0)
        ok = ndmint.os_click(5, 5, user32=u32, sleep=lambda s: None, uniform=midpoint)
        self.assertFalse(ok)
        self.assertFalse(any(c[0] == "mouse_event" for c in u32.calls))


class LocateTests(unittest.TestCase):
    def test_locate_physicalizes_by_device_pixel_ratio(self):
        tab = FakeTab(located={"x": 100.0, "y": 50.0, "dpr": 1.5})
        point = asyncio.run(ndmint.locate_checkbox_point(tab))
        self.assertEqual(point, (150.0, 75.0))

    def test_locate_none_when_widget_absent_or_page_mid_navigation(self):
        self.assertIsNone(asyncio.run(ndmint.locate_checkbox_point(FakeTab(located=None))))
        self.assertIsNone(asyncio.run(ndmint.locate_checkbox_point(FakeTab(raise_on_evaluate=True))))
        self.assertIsNone(asyncio.run(ndmint.locate_checkbox_point(FakeTab(located={"x": "bad"}))))


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


class AutoTickerTests(unittest.IsolatedAsyncioTestCase):
    def make_ticker(self, located=(500, 300), enabled=True, headed=True, clicks=None):
        clock = Clock()
        click_calls = []

        def click(x, y):
            click_calls.append((x, y))
            return True

        tab = FakeTab()
        browser = types.SimpleNamespace(_process_pid=999999)
        locate_calls = []

        async def locate(_tab):
            locate_calls.append(1)
            return located

        ticker = ndmint.AutoTicker(
            tab, browser, enabled=enabled, headed=headed,
            click=click, locate=locate, monotonic=clock,
        )
        return ticker, clock, click_calls, locate_calls, tab

    async def test_auto_path_chosen_when_checkbox_found(self):
        ticker, clock, click_calls, locate_calls, tab = self.make_ticker()
        with mock.patch.object(ndmint, "foreground_browser_window", return_value=True) as fg:
            await ticker.step()
        self.assertEqual(ticker.attempts, 1)
        self.assertEqual(ticker.clicks, 1)
        self.assertEqual(click_calls, [(500, 300)])  # the OS click lands on the located point
        self.assertEqual(tab.brought_to_front, 1)    # window pulled forward first
        fg.assert_called_once_with(999999)           # ...at the OS level too
        self.assertEqual(ticker.provenance(True), "auto-os-click")

    async def test_disabled_ticker_never_clicks_but_still_sees_the_checkbox(self):
        ticker, clock, click_calls, locate_calls, tab = self.make_ticker(enabled=False)
        await ticker.step()
        self.assertEqual((ticker.attempts, ticker.clicks, click_calls), (0, 0, []))
        self.assertTrue(ticker.saw_checkbox)
        self.assertEqual(ticker.provenance(True), "operator-manual")

    async def test_retry_cap_initial_plus_two_retries_then_operator_fallback(self):
        ticker, clock, click_calls, locate_calls, tab = self.make_ticker()
        self.assertEqual(ndmint.TICK_MAX_ATTEMPTS, 3)  # the mission pin: initial + 2 retries
        with mock.patch.object(ndmint, "foreground_browser_window", return_value=True):
            for _ in range(12):  # far more iterations than attempts; the cap must hold
                clock.t += ndmint.TICK_SETTLE_S + 1.0  # past the settle window each time
                await ticker.step()
        self.assertEqual(ticker.attempts, 3)
        self.assertEqual(ticker.clicks, 3)
        self.assertEqual(len(click_calls), 3)
        self.assertTrue(ticker.exhausted)
        self.assertGreaterEqual(len(locate_calls), 3)  # every attempt used a FRESH locate
        # exhausted + later resolved => the OPERATOR passed it, honestly reported
        self.assertEqual(ticker.provenance(True), "operator-manual")
        self.assertEqual(ticker.provenance(False), "unresolved")

    async def test_settle_window_suppresses_immediate_retry(self):
        ticker, clock, click_calls, locate_calls, tab = self.make_ticker()
        with mock.patch.object(ndmint, "foreground_browser_window", return_value=True):
            await ticker.step()
            clock.t += 1.0  # inside the 5s settle window
            await ticker.step()
        self.assertEqual(ticker.attempts, 1)  # CF gets time to consume the click
        clock.t += ndmint.TICK_SETTLE_S + 1.0
        with mock.patch.object(ndmint, "foreground_browser_window", return_value=True):
            await ticker.step()
        self.assertEqual(ticker.attempts, 2)

    async def test_failed_click_consumes_an_attempt_but_not_a_click(self):
        clock = Clock()

        def bad_click(x, y):
            return False  # e.g. SetCursorPos failed -- auto-tick unavailable mid-flight

        async def locate(_tab):
            return (1, 1)

        ticker = ndmint.AutoTicker(
            FakeTab(), types.SimpleNamespace(_process_pid=None), enabled=True,
            click=bad_click, locate=locate, monotonic=clock,
        )
        with mock.patch.object(ndmint, "foreground_browser_window", return_value=False):
            for _ in range(6):
                clock.t += ndmint.TICK_SETTLE_S + 1.0
                await ticker.step()
        self.assertEqual((ticker.attempts, ticker.clicks), (3, 0))
        self.assertTrue(ticker.exhausted)
        self.assertEqual(ticker.provenance(True), "operator-manual")  # fallback after auto failure

    async def test_provenance_matrix(self):
        # passive solve: no interactive checkbox ever appeared
        t0, *_ = self.make_ticker(located=None)
        await t0.step()
        self.assertEqual(t0.provenance(True), "not-required")
        # headless + checkbox seen + resolved without clicks
        t1, *_ = self.make_ticker(enabled=False, headed=False)
        await t1.step()
        self.assertEqual(t1.provenance(True), "unattended-headless")


if __name__ == "__main__":
    unittest.main(verbosity=2)
