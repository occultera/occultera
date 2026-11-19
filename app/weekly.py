# SPDX-License-Identifier: AGPL-3.0-only
"""Weekly summary for managers and the measured effect of deployed rule drafts. Deterministic — no AI.

* ``rule_effects`` compares, for every rule draft deployed or promoted in the last 60 days, the alerts of the rule
  family (the draft's parents and its own rules) in the days before and after the change: did approving the
  recommendation actually reduce the noise?
* ``weekly_summary`` sends one message a week (``notify.on_weekly``): alert volume against the week before, AI
  rounds, findings, recommendations waiting, rule changes with their measured effect.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from . import rules as rulemod
from .collector import _parse, iso
from .i18n import t
from .notify import plain_message
from .notify import send as notify_send
from .store import now_iso

log = logging.getLogger("wdt")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
EFFECT_MAX_DAYS = 7          # compare at most a week before with a week after
EFFECT_LOOKBACK_DAYS = 60    # drafts changed earlier than this are not measured again


def pct(before: float, after: float) -> str:
    if not before:
        return "new" if after else "±0 %"
    v = round(100 * (after - before) / before)
    return ("+" if v > 0 else "−" if v < 0 else "±") + f"{abs(v)} %"


class WeeklyMixin:
    # ------------------------------------------------------------ rule effect
    async def _count(self, rt, ids: list[str], start: datetime, end: datetime, min_level: int | None = None) -> int:
        if not ids:
            return 0
        f = [{"terms": {"rule.id": ids}}, {"range": {"timestamp": {"gte": iso(start), "lt": iso(end)}}}]
        if min_level is not None:
            f.append({"range": {"rule.level": {"gte": min_level}}})
        return await rt.ix.count(rt.env.alerts_index, {"bool": {"filter": f}})

    async def rule_effects(self, env_id: str) -> list[dict]:
        """Before/after alert counts for recently deployed or promoted rule drafts; stored on each draft."""
        rt = self.get(env_id)
        now = datetime.now(UTC)
        out = []
        rows = await rt.repo.list_knowledge(kinds=["rule_draft"], status=["active", "closed"], size=500)
        for d in rows:
            dep, prom = d.get("deploy") or {}, d.get("promoted") or {}
            since = dep.get("at") if dep.get("state") == "deployed" else prom.get("at")
            if not since:
                continue
            s = _parse(since)
            age = now - s
            if age < timedelta(days=1) or age > timedelta(days=EFFECT_LOOKBACK_DAYS):
                continue
            parsed = rulemod.parse(rulemod.extract_xml(d))[0]
            ids = [r["id"] for r in parsed if r.get("id")]
            parents = sorted({p for r in parsed for p in r.get("parents") or []} - set(ids))
            if not ids:
                continue
            days = min(EFFECT_MAX_DAYS, age.days)
            w = timedelta(days=days)
            fam = parents + ids
            lvl = rt.env.high_level
            e = {"checked_at": iso(now), "since": since, "days": days, "ids": ids, "parents": parents, "level": lvl,
                 "parent_before": await self._count(rt, parents, s - w, s) / days,
                 "parent_after": await self._count(rt, parents, s, s + w) / days,
                 "child_after": await self._count(rt, ids, s, s + w) / days,
                 "high_before": await self._count(rt, fam, s - w, s, lvl) / days,
                 "high_after": await self._count(rt, fam, s, s + w, lvl) / days}
            e = {k: (round(v, 1) if isinstance(v, float) else v) for k, v in e.items()}
            e["change"] = pct(e["high_before"], e["high_after"])
            await rt.repo.update_knowledge(d["id"], effect=e)
            out.append({"id": d["id"], "title": d.get("title", ""), **e})
        return out

    # ------------------------------------------------------------ weekly summary
    async def weekly_summary(self, env_id: str, transport=None, force: bool = False) -> dict:
        rt = self.get(env_id)
        cfg = self.settings.notify_for(rt.env)
        if not (cfg.enabled and cfg.channels and (cfg.on_weekly or force)):
            return {}
        lang = self.lang(rt.env)
        now = datetime.now(UTC)
        wk, prev = now - timedelta(days=7), now - timedelta(days=14)
        lvl = rt.env.high_level

        async def cnt(a, b, level=None):
            f = [{"range": {"timestamp": {"gte": iso(a), "lt": iso(b)}}}]
            if level is not None:
                f.append({"range": {"rule.level": {"gte": level}}})
            return await rt.ix.count(rt.env.alerts_index, {"bool": {"filter": f}})

        lines = []
        try:
            tot, tot0 = await cnt(wk, now), await cnt(prev, wk)
            hi, hi0 = await cnt(wk, now, lvl), await cnt(prev, wk, lvl)
            lines.append(t(lang, "wk.alerts", total=f"{tot:,}", tp=pct(tot0, tot), high=f"{hi:,}", l=lvl,
                           hp=pct(hi0, hi)))
        except Exception as e:  # noqa: BLE001 — the rest of the summary is still useful
            lines.append(t(lang, "wk.no_counts", e=type(e).__name__))
        runs = [r for r in await rt.repo.list_runs(30, light=True)
                if r.get("status") == "done" and (r.get("started_at") or "") >= iso(wk)]
        hc = {h: sum(1 for r in runs if r.get("health") == h) for h in ("ok", "warn", "critical")}
        lines.append(t(lang, "wk.runs", n=len(runs), ok=hc["ok"], w=hc["warn"], c=hc["critical"]))
        labels = [f.get("label") for r in runs for f in r.get("findings") or []]
        lines.append(t(lang, "wk.findings", real=labels.count("real_incident"), inv=labels.count("investigate"),
                       gap=labels.count("detection_gap")))
        inbox = await self.inbox(env_id)
        old = await self.pending_items(env_id, cfg.pending_days)
        lines.append(t(lang, "wk.inbox", n=len(inbox), old=len(old), d=cfg.pending_days))
        effects = await self.rule_effects(env_id)
        changed = [e for e in effects if (e.get("since") or "") >= iso(wk)]
        lines.append(t(lang, "wk.rules", n=len(changed)) if changed else t(lang, "wk.rules_none"))
        for e in sorted(effects, key=lambda x: x.get("since") or "", reverse=True)[:5]:
            lines.append(t(lang, "wk.rule_line", title=str(e["title"])[:80], l=e["level"], before=e["high_before"],
                           after=e["high_after"], pct=e["change"], d=e["days"]))
        base = cfg.ui_url.rstrip("/")
        msg = plain_message(t(lang, "wk.title", env=rt.env.name, a=f"{wk:%d.%m}", b=f"{now:%d.%m}"), lines,
                            f"{base}/?env={env_id}&period=7d" if base else "")
        msg["link_title"] = t(lang, "wk.open")
        res = await notify_send(cfg, msg, transport=transport)
        log.info("%s: weekly summary sent: %s", env_id, res)
        return {"lines": lines, "result": res}

    async def _weekly_tick(self):
        now = datetime.now(self.tz)
        for env_id, rt in self.envs.items():
            cfg = self.settings.notify_for(rt.env)
            if not (cfg.enabled and cfg.channels and cfg.on_weekly):
                continue
            if DAYS[now.weekday()] != cfg.weekly_day or now.strftime("%H:%M") < cfg.weekly_time:
                continue
            day = f"{now:%Y-%m-%d}"
            marker = f"_weekly_{env_id}"
            try:   # once a week, also across restarts and pods
                prev = await rt.store.get("knowledge", marker)
                if prev and prev.get("day") == day:
                    continue
                await rt.store.put("knowledge", marker, {"id": marker, "env": "__meta__", "kind": "weekly_marker",
                                                         "status": "closed", "title": env_id, "day": day,
                                                         "created_at": now_iso(), "updated_at": now_iso()})
                await self.weekly_summary(env_id, transport=self.notify_transport)
            except Exception:  # noqa: BLE001 — a summary must never stop the scheduler
                log.exception("%s: weekly summary failed", env_id)
