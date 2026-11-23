# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Sending: a small in-memory queue, best effort, never blocks or fails the application."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import httpx

from .schema import check, error_event, features_of, level, usage_event

log = logging.getLogger("wdt.telemetry")
URL = "https://telemetry.occultera.dev/v1/events"
ERROR_DEDUP_S = 24 * 3600
MAX_ERRORS_PER_DAY = 20
USAGE_EVERY_S = 7 * 24 * 3600


class Telemetry:
    def __init__(self, rt: Any = None, url: str | None = None, transport: Any = None):
        self.rt = rt
        self.url = url or os.environ.get("TELEMETRY_URL", URL)
        self.transport = transport
        self.q: asyncio.Queue[dict] | None = None
        self.seen: dict[str, float] = {}
        self.day: tuple[int, int] = (0, 0)          # (day number, errors sent that day)
        self._task: asyncio.Task | None = None
        self.sent: list[dict] = []                  # last events, for the About page and tests

    # ------------------------------------------------------------------ public
    def start(self) -> None:
        if level() == "off" or self._task:
            return
        self.q = asyncio.Queue(maxsize=50)
        self._task = asyncio.create_task(self._loop())
        log.info("telemetry: %s → %s (TELEMETRY=off switches it off)", level(), self.url)

    async def close(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None

    def report_error(self, exc: BaseException, where: str = "") -> bool:
        """Queue a crash report (deduplicated by fingerprint, capped per day). Safe from any thread or context."""
        if level() == "off" or self.q is None:
            return False
        try:
            ev = check(error_event(exc, where))
        except Exception:  # noqa: BLE001
            return False
        now = time.time()
        if now - self.seen.get(ev["fingerprint"], 0) < ERROR_DEDUP_S:
            return False
        d = int(now // 86400)
        n = self.day[1] if self.day[0] == d else 0
        if n >= MAX_ERRORS_PER_DAY:
            return False
        self.seen[ev["fingerprint"]], self.day = now, (d, n + 1)
        try:
            self.q.put_nowait(ev)
        except asyncio.QueueFull:
            return False
        return True

    async def usage_now(self) -> dict | None:
        if level() != "errors+usage" or self.rt is None:
            return None
        feats, n = features_of(self.rt)
        wz = []
        for er in getattr(self.rt, "envs", {}).values():
            try:
                if er.api:
                    wz.append((await er.api.info()).get("api_version"))
            except Exception:  # noqa: BLE001
                pass
        return check(usage_event(feats, n, wz, str(self.rt.settings.llm.provider)))

    # ------------------------------------------------------------------ internals
    async def _post(self, ev: dict) -> None:
        try:
            async with httpx.AsyncClient(timeout=5, transport=self.transport) as c:
                r = await c.post(self.url, json=ev, headers={"User-Agent": f"occultera/{ev.get('app')}"})
            log.debug("telemetry %s → %s", ev["kind"], r.status_code)
        except Exception as e:  # noqa: BLE001 - offline / blocked egress is normal
            log.debug("telemetry not sent: %s", type(e).__name__)
        self.sent = (self.sent + [ev])[-10:]

    async def _loop(self) -> None:
        next_usage = time.monotonic() + 300          # first usage ping five minutes after start
        while True:
            try:
                timeout = max(1.0, next_usage - time.monotonic())
                try:
                    ev = await asyncio.wait_for(self.q.get(), timeout)   # type: ignore[union-attr]
                    await self._post(ev)
                except TimeoutError:
                    u = await self.usage_now()
                    if u:
                        await self._post(u)
                    next_usage = time.monotonic() + USAGE_EVERY_S
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                await asyncio.sleep(60)


class TelemetryHandler(logging.Handler):
    """Every ERROR record that carries an exception becomes a crash report (the record's text is never sent)."""

    def __init__(self, tel: Telemetry):
        super().__init__(level=logging.ERROR)
        self.tel = tel

    def emit(self, record: logging.LogRecord) -> None:
        if record.exc_info and record.exc_info[1] is not None and not record.name.startswith("wdt.telemetry"):
            self.tel.report_error(record.exc_info[1], record.name)
