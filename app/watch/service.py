# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The watch in the runtime: scan, sort out, announce, store, and apply the AI round's verdicts."""
from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from ..collector import _parse, iso
from ..i18n import t
from ..notify import plain_message
from ..notify import send as notify_send
from ..observability import metrics
from ..store import now_iso
from .scan import Scanner
from .util import MAX_WINDOW_MINUTES, PENDING, channels_for, event_line, known_noise, muted, quiet_now

if TYPE_CHECKING:
    from ..services import EnvRuntime
log = logging.getLogger("wdt.watch")


class WatchMixin:
    """Scheduler tick, persistence, notification and the hand-over to the AI round."""

    async def watch_state(self, rt: EnvRuntime) -> dict:
        return await rt.repo.get_state("watch") or {}

    async def watch_scan(self, env_id: str, transport=None, now: datetime | None = None) -> dict:
        """One scan. Returns a summary; safe to call by hand ("scan now")."""
        rt = self.get(env_id)
        st = await self.env_settings(rt)
        cfg = st.watch
        if not cfg.enabled:
            return {"enabled": False}
        lang = self.lang(rt.env)
        now = now or datetime.now(UTC)
        state = await self.watch_state(rt)
        try:
            frm = _parse(state["cursor"])
        except (KeyError, ValueError):
            frm = now - timedelta(minutes=cfg.interval_minutes)
        gap = None
        if (now - frm).total_seconds() > MAX_WINDOW_MINUTES * 60:
            gap = {"from": iso(frm), "to": iso(now - timedelta(minutes=MAX_WINDOW_MINUTES))}
            frm = now - timedelta(minutes=MAX_WINDOW_MINUTES)
        if frm >= now:
            return {"enabled": True, "events": 0, "skipped": "clock"}
        known = set(state["disconnected"]) if isinstance(state.get("disconnected"), list) else None
        from ..services import clusters_of
        sc = Scanner(rt.env, rt.ix, rt.api, cfg, lang, clusters=clusters_of(getattr(rt, "sources", None)))
        found, disconnected = await sc.scan(frm, now, known)

        baseline = {str(r) for k in await rt.repo.list_knowledge(kinds=["baseline"], status="active")
                    for r in k.get("rule_ids") or []}
        recent = {e["key"]: e for e in reversed(await rt.repo.list_events(300))}
        cutoff = now - timedelta(hours=cfg.repeat_hours)
        fresh: list[dict] = []
        for ev in found:
            old = recent.get(ev["key"])
            if old and _parse(old["created_at"]) >= cutoff:        # same thing again: count it, stay silent
                old["count"] = int(old.get("count") or 1) + int(ev.get("count") or 1)
                old["last_seen"] = ev.get("last_seen") or now_iso()
                old["repeats"] = int(old.get("repeats") or 0) + 1
                await rt.repo.save_event(old)
                continue
            if muted(ev, cfg.mute):
                ev["status"], ev["why_silent"] = "muted", "mute"
            elif known_noise(ev, baseline):
                ev["status"], ev["why_silent"] = "muted", "baseline"
            elif ev.get("still_firing"):
                ev["status"], ev["why_silent"] = "muted", "still_firing"
            elif ev.get("recurring"):
                ev["status"], ev["why_silent"] = "muted", "recurring_egress" if ev["trigger"] == "egress" else "recurring"
            fresh.append(ev)

        quiet = quiet_now(cfg, now.astimezone(self.tz))
        to_send = [e for e in fresh if e["status"] == "new"
                   and not (quiet and not (cfg.quiet.allow_critical and e["severity"] == "critical"))]
        for e in fresh:
            if e["status"] == "new" and e not in to_send:
                e["status"] = "held"
        held_before = [] if quiet else await rt.repo.list_events(100, status="held")
        result = None
        if to_send or held_before:
            result = await self._watch_notify(rt, to_send, held_before, lang, transport)
            stamp = now_iso()
            for e in to_send + held_before:
                e["status"], e["notified_at"], e["notify_result"] = "notified", stamp, result
        for e in fresh + held_before:
            await rt.repo.save_event(e)
        new_state = {"cursor": iso(now), "disconnected": sorted(disconnected) if disconnected is not None else None,
                     "last_scan": {"at": iso(now), "from": iso(frm), "found": len(found), "new": len(fresh),
                                   "sent": len(to_send) + len(held_before), "quiet": quiet,
                                   "errors": sc.errors, "gap": gap}}
        await rt.repo.put_state("watch", new_state)
        metrics.inc("wdt_watch_scans_total", env=env_id)
        if fresh:
            metrics.inc("wdt_watch_events_total", float(len(fresh)), env=env_id)
            log.info("%s watch: %d new event(s), %d announced%s", env_id, len(fresh), len(to_send),
                     " (quiet hours)" if quiet else "")
        return {"enabled": True, "events": len(fresh), "sent": len(to_send) + len(held_before), "quiet": quiet,
                "errors": sc.errors, "notify": result}

    async def _watch_notify(self, rt: EnvRuntime, events: list[dict], held: list[dict], lang: str, transport) -> dict:
        st = await self.env_settings(rt)
        ncfg = channels_for(self.settings.notify_for(rt.env), st.watch.channels)
        if not ncfg.enabled or not ncfg.channels:
            return {}
        sev = {"critical": 0, "high": 1}
        events = sorted(events, key=lambda e: sev.get(e["severity"], 2))
        lines = [event_line(e, lang) for e in events[:20]]
        if len(events) > 20:
            lines.append(t(lang, "watch.more", n=len(events) - 20))
        if held:
            lines.append(t(lang, "watch.held", n=len(held)))
            lines += [event_line(e, lang) for e in held[:15]]
        lines.append(t(lang, "watch.not_ai"))
        crit = any(e["severity"] == "critical" for e in events + held)
        link = f"{ncfg.ui_url.rstrip('/')}/e/{rt.env.id}/watch" if ncfg.ui_url else ""
        msg = plain_message(t(lang, "watch.title_critical" if crit else "watch.title", env=rt.env.name), lines, link)
        msg["link_title"] = t(lang, "watch.open")
        try:
            return await notify_send(ncfg, msg, transport=transport)
        except Exception:  # noqa: BLE001 - a notification problem must never stop the watch
            log.exception("%s: watch notification failed", rt.env.id)
            return {}

    async def _watch_tick(self):
        loop_now = asyncio.get_running_loop().time()
        for env_id, rt in self.envs.items():
            if env_id in self._watch_busy:
                continue
            try:
                cfg = (await self.env_settings(rt)).watch
            except Exception as e:  # noqa: BLE001 - the indexer may be down; liveness reports that
                log.debug("%s: settings unavailable for the watch: %s", env_id, e)
                continue
            if not cfg.enabled or loop_now - self._watch_last.get(env_id, -1e9) < cfg.interval_minutes * 60:
                continue
            self._watch_last[env_id] = loop_now
            self._watch_busy.add(env_id)

            async def go(eid=env_id):
                try:
                    await self.watch_scan(eid, transport=self.notify_transport)
                except Exception:  # noqa: BLE001
                    log.exception("watch scan failed: %s", eid)
                finally:
                    self._watch_busy.discard(eid)
            task = asyncio.create_task(go())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    # -------------------------------------------------------- AI round hand-over
    async def watch_pending(self, rt: EnvRuntime, limit: int = 60) -> list[dict]:
        """Events without a verdict, most severe first — handed to the next AI round in one go."""
        rows = [e for e in await rt.repo.list_events(400, status=list(PENDING)) if not e.get("verdict")]
        sev = {"critical": 0, "high": 1}
        rows.sort(key=lambda e: (sev.get(e["severity"], 2), e["status"] == "muted", e["created_at"]))
        return rows[:limit]

    async def watch_apply_verdicts(self, rt: EnvRuntime, verdicts: list[dict], run_id: str) -> int:
        n = 0
        for v in verdicts:
            ev = await rt.repo.get_event(v["event_id"])
            if not ev:
                continue
            ev.update(verdict=v["verdict"], reason=v["reason"], status="judged", judged_at=now_iso(),
                      judged_run=run_id)
            if v.get("suggestion"):
                ev["suggestion"] = {**v["suggestion"], "state": "open"}
            await rt.repo.save_event(ev)
            n += 1
        return n

    async def watch_suggestion(self, env_id: str, event_id: str, action: str, by: str) -> dict:
        """An administrator accepts or dismisses the model's tuning suggestion. Nothing is applied without this."""
        rt = self.get(env_id)
        ev = await rt.repo.get_event(event_id)
        sug = (ev or {}).get("suggestion")
        if not ev or not sug or sug.get("state") != "open":
            raise ValueError("no open suggestion on this event")
        if action == "apply":
            st = await self.env_settings(rt)
            watch = st.watch.model_dump()
            if sug["type"] == "mute":
                watch["mute"] = sorted(set(watch["mute"]) | {ev["key"]})
            else:
                kind = type(watch[sug["param"]])
                watch[sug["param"]] = kind(sug["value"])
            await self.save_settings(env_id, {"watch": watch}, by)
        elif action != "dismiss":
            raise ValueError("action must be apply or dismiss")
        sug.update(state="applied" if action == "apply" else "dismissed", by=by, at=now_iso())
        await rt.repo.save_event(ev)
        return ev
