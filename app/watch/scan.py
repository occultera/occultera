# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The local rules of the watch: one ``Scanner`` per environment and scan (overview: ``app.watch``)."""
from __future__ import annotations

import asyncio
import fnmatch
import logging
import math
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from ..collector import _b, _parse, iso, rng
from ..i18n import t
from ..settingsdoc import WatchSettings
from ..wazuh.schema import S, bind
from .util import (
    AUTH_FAIL,
    AUTH_OK,
    MAX_HITS,
    NAME_OK,
    POD_SUFFIX,
    PROM_FRESH,
    WORKLOAD_RX,
    _agg_ts,
    _event,
    _get,
    _level,
    _num,
    _rx,
    classify,
    fields,
    fmt_bytes,
)

if TYPE_CHECKING:
    pass
log = logging.getLogger("wdt.watch")


class Scanner:
    """The local rules. Stateless except for what the caller passes in; never writes anything."""

    def __init__(self, env, ix, api, cfg: WatchSettings, lang: str = "en", prom=None, clusters: dict | None = None):
        self.env, self.ix, self.api, self.cfg, self.lang, self.prom = env, ix, api, cfg, lang, prom
        self.clusters = clusters or ({"default": prom} if prom is not None else {})
        self.rules = {str(x) for x in (cfg.rules if cfg.rules is not None else env.watch_rules)}
        self.groups = {str(x) for x in (cfg.groups if cfg.groups is not None else env.watch_groups)}
        self.errors: list[str] = []

    async def _safe(self, name: str, coro, default):
        try:
            return await coro
        except Exception as e:  # noqa: BLE001 - one broken trigger must not blind the others
            self.errors.append(f"{name}: {type(e).__name__}")
            log.warning("%s: watch trigger %s failed: %s", self.env.id, name, e)
            return default

    async def scan(self, frm: datetime, to: datetime, known_disconnected: set[str] | None) -> tuple[list[dict], set[str] | None]:
        bind(self.env)
        a, b, c, d, e = await asyncio.gather(
            self._safe("alerts", self.alerts(frm, to), []),
            self._safe("brute_force", self.brute_force(frm, to), []),
            self._safe("spike", self.spike(frm, to), []),
            self._safe("agents", self.agents(to, known_disconnected), ([], known_disconnected)),
            self._safe("egress", self.egress(frm, to), []))
        f = await self._safe("prom_alerts", self.prom_alerts(to), [])
        return a + b + c + d[0] + e + f, d[1]

    # -------------------------------------------------------- the clusters' own Prometheus alerts
    async def prom_alerts(self, now: datetime) -> list[dict]:
        """An alert of a selected severity that the cluster's Prometheus fires; new ones are announced.

        One event per cluster, alert name and severity (``promalert:<cluster>:<alert>:<severity>``), so the repeat
        window keeps a long-running alert to one message; an alert active for more than ``PROM_FRESH`` when it is
        first seen (for example when the trigger is switched on) is recorded silently as *still firing*.
        """
        from ..clusteralerts import collect
        cfg = self.cfg
        if not cfg.on("prom_alerts") or not self.clusters:
            return []
        out: list[dict] = []
        for name, res in (await collect(self.clusters)).items():
            if "error" in res:
                self.errors.append(f"prom_alerts[{name}]: {res['error'][:80]}")
                continue
            for g in res["groups"]:
                if g["severity"] not in cfg.prom_alert_severities:
                    continue
                since = _parse(g["since"]) if g.get("since") else now
                ns = ", ".join(g["namespaces"][:4]) + ("…" if len(g["namespaces"]) > 4 else "")
                title = t(self.lang, "watch.ev.promalert", cluster=name, alert=g["name"], sev=g["severity"],
                          n=g["count"], ns=ns or "—", summary=g.get("summary") or "")
                ev = _event(self.env.id, f"promalert:{name}:{g['name']}:{g['severity']}", "prom_alerts",
                            "critical" if g["severity"] == "critical" else "high", rule_ids=[], agents=[], srcips=[],
                            cluster=name, alert=g["name"], alert_severity=g["severity"], namespaces=g["namespaces"],
                            targets=g["targets"], count=g["count"], first_seen=iso(since), last_seen=iso(now),
                            title=title.strip())
                if (now - since).total_seconds() > PROM_FRESH:
                    ev["still_firing"] = True
                out.append(ev)
        return out

    # -------------------------------------------------------- level / rules / groups / active response
    async def alerts(self, frm: datetime, to: datetime) -> list[dict]:
        cfg = self.cfg
        should: list[dict] = []
        if cfg.on("level"):
            should.append(S.level_gte(cfg.critical_level))
        if cfg.on("rules") and self.rules:
            should.append({"terms": {S.RULE_ID: sorted(self.rules)}})
        if cfg.on("groups") and self.groups:
            should.append({"bool": {"filter": [{"terms": {S.RULE_GROUPS: sorted(self.groups)}},
                                               S.level_gte(cfg.group_min_level)]}})
        if cfg.on("active_response"):
            should.append({"term": {S.RULE_GROUPS: "active_response"}})
        if not should:
            return []
        r = await self.ix.search(self.env.alerts_index, {
            "size": MAX_HITS, "sort": [{S.TS: "desc"}], "_source": fields(),
            "query": {"bool": {"filter": [rng(frm, to)], "should": should, "minimum_should_match": 1}}})
        by_key: dict[str, dict] = {}
        for h in r["hits"]["hits"]:
            src = h["_source"]
            cl = classify(src, cfg, self.rules, self.groups)
            if not cl:
                continue
            trig, sev = cl
            rid, agent = str(_get(src, S.RULE_ID) or ""), str(_get(src, S.AGENT_NAME) or "")
            key = f"{trig}:{rid}:{agent}"
            ev = by_key.get(key)
            if ev is None:
                ev = by_key[key] = _event(
                    self.env.id, key, trig, sev, rule_ids=[rid], agents=[agent] if agent else [],
                    level=_level(src), title=str(_get(src, S.RULE_DESC) or "")[:200], srcips=[],
                    first_seen=src.get(S.TS), last_seen=src.get(S.TS), count=0,
                    sample=str(src.get(S.FULL_LOG) or "")[:400])
            ev["count"] += 1
            ev["first_seen"] = src.get(S.TS) or ev["first_seen"]          # hits are newest first
            ip = _get(src, S.SRCIP)
            if ip and ip not in ev["srcips"] and len(ev["srcips"]) < 5:
                ev["srcips"].append(ip)
            if sev == "critical":
                ev["severity"] = "critical"
        total = r["hits"]["total"]["value"]
        out = list(by_key.values())
        if total > MAX_HITS and out:
            out[0]["truncated"] = total
        return out

    # -------------------------------------------------------- failed logins, then a success
    async def brute_force(self, frm: datetime, to: datetime) -> list[dict]:
        cfg = self.cfg
        if not cfg.on("brute_force"):
            return []
        ok = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [rng(frm, to), {"terms": {S.RULE_GROUPS: AUTH_OK}},
                                                     {"exists": {"field": S.SRCIP}}]}},
            "aggs": {"ip": {"terms": {"field": S.SRCIP, "size": 200},
                            "aggs": {"last": {"max": {"field": S.TS}},
                                     "agent": {"terms": {"field": S.AGENT_NAME, "size": 3}},
                                     "user": {"terms": {"field": S.DSTUSER, "size": 3}}}}}})
        winners = {str(x["key"]): x for x in _b(ok["aggregations"]["ip"])}
        if not winners:
            return []
        start = frm - timedelta(minutes=cfg.brute_window_minutes)
        fails = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [rng(start, to), {"terms": {S.RULE_GROUPS: AUTH_FAIL}},
                                                     {"terms": {S.SRCIP: sorted(winners)}}]}},
            "aggs": {"ip": {"terms": {"field": S.SRCIP, "size": 200},
                            "aggs": {"first": {"min": {"field": S.TS}}}}}})
        out = []
        for bk in _b(fails["aggregations"]["ip"]):
            ip, n = str(bk["key"]), int(bk["doc_count"])
            if n < cfg.brute_failures:
                continue
            w = winners[ip]
            first, last = _agg_ts(bk.get("first")), _agg_ts(w.get("last"))
            if first and last and first >= last:      # the failures came after the success: not this pattern
                continue
            agents = [str(x["key"]) for x in _b(w.get("agent") or {})]
            users = [str(x["key"]) for x in _b(w.get("user") or {})]
            out.append(_event(self.env.id, f"brute_force:{ip}", "brute_force", "critical", rule_ids=[],
                              agents=agents, srcips=[ip], users=users, count=n, successes=int(w["doc_count"]),
                              first_seen=iso(first) if first else None, last_seen=iso(last) if last else None,
                              title=t(self.lang, "watch.ev.brute_force", ip=ip, n=n,
                                      m=cfg.brute_window_minutes, agents=", ".join(agents) or "?")))
        return out

    # -------------------------------------------------------- volume
    def _spike_query(self, frm: datetime, to: datetime, rule_ids: list[str] | None = None) -> dict:
        cfg = self.cfg
        flt: list[dict] = [rng(frm, to)]
        if cfg.spike_min_level > 0:
            flt.append(S.level_gte(cfg.spike_min_level))
        if rule_ids:
            flt.append({"terms": {S.RULE_ID: rule_ids}})
        excl = cfg.spike_excluded()
        return {"bool": {"filter": flt, "must_not": [{"terms": {S.RULE_GROUPS: excl}}] if excl else []}}

    async def spike(self, frm: datetime, to: datetime) -> list[dict]:
        """A burst of alerts that matter, named by the rules behind it.

        Only alerts at ``spike_min_level`` and above count, and the scan groups (syscheck, SCA, vulnerability
        detector, rootcheck, …) are left out: their scheduled batches are bursts by design and say nothing about
        an attack. The window is compared with the 7-day average of the same filter. The event names the rules
        that make up the burst; when those rules already produced a burst of the same size in the last 7 days
        the event is marked *recurring* and kept silent (it still shows on the watch page).
        """
        cfg = self.cfg
        if not cfg.on("spike"):
            return []
        span = (to - frm).total_seconds()
        if span <= 0:
            return []
        idx = self.env.alerts_index
        cur = await self.ix.count(idx, self._spike_query(frm, to))
        if cur < cfg.spike_min:
            return []
        week_from = frm - timedelta(days=7)
        week = await self.ix.count(idx, self._spike_query(week_from, frm))
        avg = week * span / (7 * 86400)
        if avg > 0 and cur < cfg.spike_factor * avg:
            return []
        r = await self.ix.search(idx, {"size": 0, "query": self._spike_query(frm, to), "aggs": {
            "r": {"terms": {"field": S.RULE_ID, "size": 5}, "aggs": {
                "a": {"terms": {"field": S.AGENT_NAME, "size": 3}},
                "d": {"top_hits": {"size": 1, "_source": [S.RULE_DESC, S.RULE_LEVEL]}}}}}})
        contrib: list[dict] = []
        for b in _b(r.get("aggregations", {}).get("r") or {}):
            hits = (b.get("d") or {}).get("hits", {}).get("hits") or [{}]
            src = hits[0].get("_source") or {}
            contrib.append({"rule": str(b["key"]), "count": int(b["doc_count"]),
                            "agents": [str(a["key"]) for a in _b(b.get("a") or {})],
                            "description": str(_get(src, S.RULE_DESC) or "")[:120],
                            "level": _level(src)})
        if not contrib:
            return []
        # the rules that make up most of the burst (at least 80 %, at most three)
        main: list[dict] = []
        for c in contrib:
            main.append(c)
            if sum(x["count"] for x in main) >= 0.8 * cur or len(main) == 3:
                break
        # has each of them already done this in the last 7 days? (largest window of the same length)
        minutes = max(5, math.ceil(span / 60))
        h = await self.ix.search(idx, {"size": 0, "query": self._spike_query(week_from, frm, [c["rule"] for c in main]),
                                       "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": len(main)}, "aggs": {
                                           "h": {"date_histogram": {"field": S.TS, "fixed_interval": f"{minutes}m",
                                                                    "min_doc_count": 1}}}}}})
        peak = {str(b["key"]): max((int(x["doc_count"]) for x in _b(b.get("h") or {})), default=0)
                for b in _b(h.get("aggregations", {}).get("r") or {})}
        for c in main:
            c["peak_7d"] = peak.get(c["rule"], 0)
        recurring = all(c["peak_7d"] >= 0.5 * c["count"] for c in main)
        top = main[0]
        agents = list(dict.fromkeys(a for c in main for a in c["agents"]))[:5]
        names = "; ".join(f"{c['rule']} “{c['description']}” ×{c['count']:,}" for c in main)
        m = round(span / 60)
        lvl = cfg.spike_min_level
        if avg > 0:
            x = cur / avg
            title = t(self.lang, "watch.ev.spike", n=f"{cur:,}", m=m, lvl=lvl,
                      x=">100" if x > 100 else (f"{x:.0f}" if x >= 10 else f"{x:.1f}"),
                      avg="<1" if avg < 1 else (f"{avg:.1f}" if avg < 10 else f"{round(avg):,}"), rules=names)
        else:
            title = t(self.lang, "watch.ev.spike_new", n=f"{cur:,}", m=m, lvl=lvl, rules=names)
        ev = _event(self.env.id, f"spike:{top['rule']}", "spike", "high", rule_ids=[c["rule"] for c in main],
                    level=top["level"], agents=agents, srcips=[], count=cur, first_seen=iso(frm),
                    last_seen=iso(to), baseline=round(avg, 2), factor=round(cur / avg, 1) if avg > 0 else None,
                    contributors=main, title=title)
        if recurring:
            ev["recurring"] = True
        return [ev]

    # -------------------------------------------------------- egress (possible data leak)
    def _egress_sel(self, extra: str = "") -> str:
        excl = "|".join(_rx(n) for n in self.cfg.egress_excluded())
        parts = ['pod!=""'] + ([f'namespace!~"{excl}"'] if excl else []) + ([extra] if extra else [])
        return "container_network_transmit_bytes_total{" + ",".join(parts) + "}"

    async def _egress_one(self, expr: str, at: datetime) -> float:
        r = await self.prom.query(expr, iso(at))
        vals = [_num(x.get("value")) for x in r.get("series") or []]
        return sum(v for v in vals if v is not None)

    async def egress(self, frm: datetime, to: datetime) -> list[dict]:
        """Workloads that send far more than usual out of their pods: a possible data leak.

        Read from Prometheus (cAdvisor's ``container_network_transmit_bytes_total``), summed per namespace and
        workload — the pod name without its ReplicaSet/DaemonSet suffix, so a rollout keeps its history. A workload
        counts when it sent at least ``egress_min_mb`` in the window and ``egress_factor`` × its 7-day average for a
        window of the same length. The counter is the pod's whole interface, so traffic to other pods counts too
        (databases, object storage, backups); cluster plumbing namespaces are left out (``egress_exclude_namespaces``)
        and a transfer the same workload already made in the last 7 days is kept silent as *recurring*.
        Volume only, never content: the event says what to check, the AI round and a human decide.
        """
        if not self.cfg.on("egress") or not self.clusters:
            return []
        many = len(self.clusters) > 1
        out: list[dict] = []
        for name, prom in self.clusters.items():
            self.prom = prom
            try:
                evs = await self._egress_cluster(frm, to)
            except Exception as e:  # noqa: BLE001 - one unreachable cluster must not hide the others
                self.errors.append(f"egress[{name}]: {type(e).__name__}")
                log.warning("%s: egress on cluster %s failed: %s", self.env.id, name, e)
                continue
            for ev in evs:
                if many:
                    ev["cluster"] = name
                    ev["key"] = f"egress:{name}:{ev['workload']}"
                    ev["title"] = f"[{name}] {ev['title']}"
                out.append(ev)
        return out

    async def _egress_cluster(self, frm: datetime, to: datetime) -> list[dict]:
        cfg = self.cfg
        span = (to - frm).total_seconds()
        if span <= 0:
            return []
        m = max(5, math.ceil(span / 60))
        floor = cfg.egress_min_mb * 1_000_000
        per_pod = f"sum by (namespace, pod) (increase({self._egress_sel()}[{m}m]))"
        wl = f'label_replace(label_replace({per_pod}, "workload", "$1", "pod", "(.+)"), ' \
             f'"workload", "$1", "pod", "{WORKLOAD_RX}")'
        r = await self.prom.query(f"topk(5, sum by (namespace, workload) ({wl}) > {floor})", iso(to))
        out: list[dict] = []
        for row in r.get("series") or []:
            lab = row.get("labels") or {}
            ns, name, cur = str(lab.get("namespace") or ""), str(lab.get("workload") or ""), _num(row.get("value"))
            if not ns or not name or cur is None or cur < floor or not NAME_OK.fullmatch(ns + "/" + name):
                continue
            sel = self._egress_sel(f'namespace="{ns}",pod=~"{_rx(name)}|{_rx(name)}{POD_SUFFIX}"')
            week = await self._egress_one(f"sum(increase({sel}[7d] offset {m}m))", to)
            avg = week * m / (7 * 24 * 60)
            if avg > 0 and cur < cfg.egress_factor * avg:
                continue
            peak = await self._egress_one(f"max_over_time(sum(increase({sel}[{m}m]))[7d:{m}m] offset {m}m)", to)
            wname = f"{ns}/{name}"
            if avg > 0:
                x = cur / avg
                title = t(self.lang, "watch.ev.egress", wl=wname, size=fmt_bytes(cur), m=m, avg=fmt_bytes(avg),
                          x=">100" if x > 100 else (f"{x:.0f}" if x >= 10 else f"{x:.1f}"))
            else:
                title = t(self.lang, "watch.ev.egress_new", wl=wname, size=fmt_bytes(cur), m=m)
            ev = _event(self.env.id, f"egress:{wname}", "egress", "high", rule_ids=[], agents=[], srcips=[],
                        workload=wname, bytes=int(cur), baseline_bytes=int(avg), peak_7d_bytes=int(peak),
                        factor=round(cur / avg, 1) if avg > 0 else None, first_seen=iso(frm), last_seen=iso(to),
                        title=title)
            if peak >= 0.5 * cur:
                ev["recurring"] = True
            out.append(ev)
        return out

    # -------------------------------------------------------- agents
    async def agents(self, now: datetime, known: set[str] | None) -> tuple[list[dict], set[str] | None]:
        cfg = self.cfg
        if not cfg.on("agents") or not self.api:
            return [], known
        rows = await self.api.agents(status="disconnected", limit=500)
        lost: dict[str, str] = {}
        for a in rows or []:
            name = str(a.get("name") or a.get("id") or "")
            if not name or any(fnmatch.fnmatch(name, p) for p in self.env.ignore_agents):
                continue
            try:
                since = _parse(str(a.get("lastKeepAlive") or ""))
            except ValueError:
                continue
            if (now - since).total_seconds() >= cfg.agent_minutes * 60:
                lost[name] = iso(since)
        current = set(lost)
        if known is None:                      # first scan after a start: learn the state, announce nothing
            return [], current
        new = sorted(current - known)
        if not new:
            return [], current
        many = len(new) >= 5
        ev = _event(self.env.id, "agents:" + ",".join(new)[:150], "agents", "critical" if many else "high",
                    rule_ids=[], agents=new[:50], srcips=[], count=len(new), first_seen=min(lost[n] for n in new),
                    last_seen=iso(now), title=t(self.lang, "watch.ev.agents", n=len(new),
                                                names=", ".join(new[:8]) + ("…" if len(new) > 8 else ""),
                                                m=cfg.agent_minutes))
        return [ev], current


# a pod name without the ReplicaSet hash and pod suffix (Deployment, DaemonSet); StatefulSet pods keep their ordinal
