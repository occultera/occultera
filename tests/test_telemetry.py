# SPDX-License-Identifier: AGPL-3.0-only
"""Telemetry sends structured data only; public demo and TELEMETRY=off send nothing."""
import asyncio
import json
import logging

import httpx
import pytest

from app.telemetry import Telemetry, TelemetryHandler, error_event, level
from app.telemetry.schema import check, usage_event


def _boom():
    raise ValueError("secret.example.com 10.1.2.3 user=ayse password=hunter2")


def test_error_event_carries_no_message():
    try:
        _boom()
    except ValueError as e:
        ev = error_event(e, "wdt.test")
    text = json.dumps(ev)
    for leak in ("secret.example.com", "10.1.2.3", "ayse", "hunter2", "/home", "\\\\"):
        assert leak not in text
    assert ev["exception"] == "ValueError" and ev["category"] == "internal" and len(ev["fingerprint"]) == 16
    assert all(":" in f and f.startswith("tests.") is False for f in ev["frames"])
    check(ev)


def test_unexpected_key_is_refused():
    ev = usage_event({"mcp": True}, 2, ["4.14.10"], "openai")
    assert ev["llm"] == "openai" and ev["wazuh"] == ["4.14.10"]
    with pytest.raises(ValueError):
        check({**ev, "message": "x"})
    assert usage_event({}, 1, [], "deepseek-v4-pro")["llm"] == "other"     # model names never leave


def test_levels(monkeypatch):
    monkeypatch.delenv("TELEMETRY", raising=False)
    assert level() == "errors+usage"
    monkeypatch.setenv("TELEMETRY", "OFF")
    assert level() == "off"
    monkeypatch.setenv("TELEMETRY", "nonsense")
    assert level() == "off"
    monkeypatch.setenv("TELEMETRY", "errors")
    monkeypatch.setenv("WDT_PUBLIC_DEMO", "true")
    monkeypatch.setenv("WDT_DEMO", "true")
    assert level() == "off"


async def test_handler_sends_once_per_fingerprint(monkeypatch):
    monkeypatch.setenv("TELEMETRY", "errors")
    monkeypatch.delenv("WDT_PUBLIC_DEMO", raising=False)
    got = []

    def h(req):
        got.append(json.loads(req.content))
        return httpx.Response(204)
    tel = Telemetry(url="https://telemetry.invalid/v1/events", transport=httpx.MockTransport(h))
    tel.start()
    lg = logging.getLogger("wdt.test.telemetry_case")
    hd = TelemetryHandler(tel)
    lg.addHandler(hd)
    try:
        for _ in range(3):
            try:
                _boom()
            except ValueError:
                lg.exception("failed with a message that must not be sent")
        lg.error("an error without an exception is not a crash report")
        for _ in range(50):
            if got:
                break
            await asyncio.sleep(0.02)
    finally:
        lg.removeHandler(hd)
        await tel.close()
    assert len(got) == 1 and got[0]["kind"] == "error" and "must not be sent" not in json.dumps(got[0])


async def test_off_sends_nothing(monkeypatch):
    monkeypatch.setenv("TELEMETRY", "off")
    tel = Telemetry(transport=httpx.MockTransport(lambda r: pytest.fail("sent while off")))
    tel.start()
    try:
        _boom()
    except ValueError as e:
        assert tel.report_error(e) is False
