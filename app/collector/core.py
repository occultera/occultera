# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The collector: runs every section in parallel and turns the result into health flags."""
from __future__ import annotations

import asyncio
import fnmatch
from datetime import datetime, timedelta
from typing import Any

from ..config import Environment
from ..i18n import t
from ..wazuh.api import WazuhAPI
from ..wazuh.indexer import Indexer
from ..wazuh.schema import S, bind
from .extras import ExtrasMixin
from .health import HealthMixin
from .util import _b, accept_flags, iso, rng


class Collector(HealthMixin, ExtrasMixin):
    def __init__(self, env: Environment, indexer: Indexer, api: WazuhAPI | None, lang: str = "en",
                 inventory: list[str] | None = None):
        self.env = env
        self.inventory = inventory or []
        self.lang = lang
        self.ix = indexer
        self.api = api
        self.errors: list[str] = []

    async def _safe(self, name: str, coro):
        try:
            return await coro
        except Exception as e:  # noqa: BLE001 — sections are independent
            self.errors.append(f"{name}: {e}")
            return None

    async def collect(self, frm: datetime, to: datetime) -> dict[str, Any]:
        bind(self.env)
        hours = max(1, round((to - frm).total_seconds() / 3600))
        prev_frm = frm - (to - frm)
        tasks = {
            "health": self._health(to),
            "volume": self._volume(frm, to, hours),
            "top_rules": self._top_rules(frm, to, prev_frm),
            "high_level": self._high_level(frm, to),
            "agents": self._agents_alerts(frm, to, prev_frm),
            "new_rules": self._new_rules(frm, to),
            "groups": self._groups(frm, to),
            "srcips": self._srcips(frm, to),
            "watch": self._watch(frm, to),
            "vulnerabilities": self._vulns(to),
        }
        if self.env.mail:
            tasks["mail_pressure"] = self._mail_pressure(frm, to)
        if self.env.anomaly:
            tasks["anomalies"] = self._anomalies(frm, to)
        if self.api:
            tasks["coverage"] = self._coverage(to)
        pv = self.env.privacy
        if pv.detect and pv.detect_sample:
            tasks["personal_data"] = self._personal_data(frm, to, pv.detect_sample)
        res = await asyncio.gather(*(self._safe(k, v) for k, v in tasks.items()))
        out = dict(zip(tasks.keys(), res, strict=True))
        out["window"] = {"from": iso(frm), "to": iso(to), "hours": hours}
        out["env"] = {"id": self.env.id, "name": self.env.name, "high_level": self.env.high_level}
        out["flags"] = self._flags(out)
        out["errors"] = self.errors
        return out

    # ------------------------------------------------------------------ health
    async def _volume(self, frm, to, hours) -> dict:
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": rng(frm, to),
            "aggs": {
                "levels": {"terms": {"field": S.RULE_LEVEL, "size": 20, "order": {"_key": "desc"}}},
                "hourly": {"date_histogram": {"field": S.TS, "fixed_interval": "1h", "min_doc_count": 0,
                                              "extended_bounds": {"min": iso(frm), "max": iso(to - timedelta(seconds=1))}}},
                "managers": {"terms": {"field": S.MANAGER, "size": 10}},
            },
        })
        total = r["hits"]["total"]["value"]
        levels = {str(b["key"]): b["doc_count"] for b in _b(r["aggregations"]["levels"])}
        hourly = [{"t": b["key_as_string"], "n": b["doc_count"]} for b in _b(r["aggregations"]["hourly"])]
        high = sum(v for k, v in levels.items() if int(k) >= self.env.high_level)
        empty = [h["t"] for h in hourly if h["n"] == 0]
        return {
            "total": total, "levels": levels, "high_level_total": high,
            "high_level_ratio_permille": round(high * 1000 / total, 2) if total else 0,
            "hourly": hourly, "empty_hours": empty,
            "per_manager": {b["key"]: b["doc_count"] for b in _b(r["aggregations"]["managers"])},
        }

    # ------------------------------------------------------------------ rules
    async def _top_rules(self, frm, to, prev_frm) -> list[dict]:
        aggs = {"r": {"terms": {"field": S.RULE_ID, "size": 40},
                      "aggs": {"d": {"terms": {"field": S.RULE_DESC, "size": 1}},
                               "l": {"max": {"field": S.RULE_LEVEL}},
                               "a": {"terms": {"field": S.AGENT_NAME, "size": 4}}}}}
        cur, prev = await asyncio.gather(
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to), "aggs": aggs}),
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(prev_frm, frm),
                                                  "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": 500}}}}),
        )
        prevm = {b["key"]: b["doc_count"] for b in _b(prev["aggregations"]["r"])}
        out = []
        for b in _b(cur["aggregations"]["r"]):
            d = _b(b["d"])
            out.append({
                "id": b["key"], "count": b["doc_count"], "prev": prevm.get(b["key"], 0),
                "level": int(b["l"]["value"] or 0), "desc": d[0]["key"] if d else "",
                "agents": {a["key"]: a["doc_count"] for a in _b(b["a"])},
            })
        return out

    async def _high_level(self, frm, to) -> list[dict]:
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0,
            "query": {"bool": {"filter": [rng(frm, to), S.level_gte(self.env.high_level)]}},
            "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": 60},
                           "aggs": {
                               "d": {"terms": {"field": S.RULE_DESC, "size": 1}},
                               "l": {"max": {"field": S.RULE_LEVEL}},
                               "a": {"terms": {"field": S.AGENT_NAME, "size": 8},
                                     "aggs": {"first": {"min": {"field": S.TS}}, "last": {"max": {"field": S.TS}}}},
                               "ip": {"terms": {"field": S.SRCIP, "size": 5}},
                               "s": {"top_hits": {"size": 1, "sort": [{S.TS: "desc"}],
                                                  "_source": [S.FULL_LOG, S.URL, S.SRCIP, S.SRCUSER,
                                                              S.DSTUSER, S.FIM_PATH, S.VERB,
                                                              S.K8S_OBJECT, S.USERNAME,
                                                              S.ALERT_CVE, S.LOCATION]}},
                           }}},
        })
        out = []
        for b in _b(r["aggregations"]["r"]):
            d = _b(b["d"])
            hit = b["s"]["hits"]["hits"]
            sample = hit[0]["_source"] if hit else {}
            if S.FULL_LOG in sample:
                sample[S.FULL_LOG] = sample[S.FULL_LOG][:400]
            out.append({
                "id": b["key"], "count": b["doc_count"], "level": int(b["l"]["value"] or 0),
                "desc": d[0]["key"] if d else "",
                "agents": [{"name": a["key"], "n": a["doc_count"],
                            "first": a["first"].get("value_as_string"), "last": a["last"].get("value_as_string")}
                           for a in _b(b["a"])],
                "srcips": {i["key"]: i["doc_count"] for i in _b(b["ip"])},
                "sample": sample,
            })
        return out

    async def _agents_alerts(self, frm, to, prev_frm) -> list[dict]:
        a = {"a": {"terms": {"field": S.AGENT_NAME, "size": 60},
                   "aggs": {"hi": {"filter": S.level_gte(self.env.high_level)}}}}
        cur, prev = await asyncio.gather(
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to), "aggs": a}),
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(prev_frm, frm),
                                                  "aggs": {"a": {"terms": {"field": S.AGENT_NAME, "size": 200}}}}),
        )
        pm = {b["key"]: b["doc_count"] for b in _b(prev["aggregations"]["a"])}
        return [{"agent": b["key"], "count": b["doc_count"], "prev": pm.get(b["key"], 0),
                 "high": b["hi"]["doc_count"]} for b in _b(cur["aggregations"]["a"])]

    async def _new_rules(self, frm, to) -> list[dict]:
        """Rule IDs seen in the window but not in the preceding 14 days."""
        cur, hist = await asyncio.gather(
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to),
                           "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": 2000},
                                          "aggs": {"d": {"terms": {"field": S.RULE_DESC, "size": 1}},
                                                   "l": {"max": {"field": S.RULE_LEVEL}}}}}}),
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm - timedelta(days=14), frm),
                           "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": 5000}}}}),
        )
        seen = {b["key"] for b in _b(hist["aggregations"]["r"])}
        out = []
        for b in _b(cur["aggregations"]["r"]):
            if b["key"] not in seen:
                d = _b(b["d"])
                out.append({"id": b["key"], "count": b["doc_count"], "level": int(b["l"]["value"] or 0),
                            "desc": d[0]["key"] if d else ""})
        return sorted(out, key=lambda x: (-x["level"], -x["count"]))[:40]

    async def _groups(self, frm, to) -> dict:
        r = await self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to),
                                 "aggs": {"g": {"terms": {"field": S.RULE_GROUPS, "size": 50}}}})
        g = {b["key"]: b["doc_count"] for b in _b(r["aggregations"]["g"])}
        if self.env.watch_groups:
            g = {"top": g, "watched": {k: g.get(k, 0) for k in self.env.watch_groups}}
        return g

    async def _srcips(self, frm, to) -> list[dict]:
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [rng(frm, to), {"exists": {"field": S.SRCIP}}]}},
            "aggs": {"ip": {"terms": {"field": S.SRCIP, "size": 15},
                            "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": 3}},
                                     "l": {"max": {"field": S.RULE_LEVEL}}}}}})
        return [{"ip": b["key"], "count": b["doc_count"], "max_level": int(b["l"]["value"] or 0),
                 "rules": {x["key"]: x["doc_count"] for x in _b(b["r"])}}
                for b in _b(r["aggregations"]["ip"])]

    async def _watch(self, frm, to) -> dict:
        if not self.env.watch_rules:
            return {}
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"bool": {"filter": [rng(frm, to), {"terms": {S.RULE_ID: self.env.watch_rules}}]}},
            "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": len(self.env.watch_rules)}}}})
        got = {b["key"]: b["doc_count"] for b in _b(r["aggregations"]["r"])}
        return {rid: got.get(rid, 0) for rid in self.env.watch_rules}

    def _flags(self, d: dict) -> list[dict]:
        """Deterministic health flags (independent of the LLM)."""
        f: list[dict] = []
        h = d.get("health") or {}
        v = d.get("volume") or {}
        L = self.lang

        def add(sev, code, **kw):
            f.append({"severity": sev, "code": code, "message": t(L, f"flag.{code}", **kw)})

        sil = h.get("silence_minutes")
        if h.get("last_alert") is None and "last_alert" in h:
            add("critical", "no_alerts_7d")
        elif sil is not None and sil > self.env.max_silence_minutes:
            add("critical", "silence", m=sil, t=self.env.max_silence_minutes)
        if v.get("empty_hours"):
            add("warn", "empty_hours", n=len(v["empty_hours"]))
        ix = h.get("indexer") or {}
        if ix.get("status") and ix["status"] != "green":
            add("critical" if ix["status"] == "red" else "warn", "indexer_status", s=ix["status"])
        for disk in h.get("indexer_disk") or []:
            p = disk.get("percent")
            if p is not None and p >= self.env.disk_warn_percent:
                add("critical" if p >= 90 else "warn", "indexer_disk", node=disk["node"], p=p)
        if h.get("daemons_not_running"):
            add("critical", "daemons", d=", ".join(h["daemons_not_running"]))
        bad = [a for a in h.get("agents_not_active") or []
               if not any(fnmatch.fnmatchcase(str(a.get("name") or ""), pat) for pat in self.env.ignore_agents)]
        if bad:
            add("warn", "agents", n=len(bad), a=", ".join(a["name"] for a in bad[:8]))
        cl = h.get("cluster")
        if cl and cl.get("enabled") == "yes" and cl.get("running") != "yes":
            add("critical", "cluster")
        if d.get("new_rules"):
            hi = [r for r in d["new_rules"] if r["level"] >= self.env.high_level]
            if hi:
                add("warn", "new_high_rules", n=len(hi), l=self.env.high_level)
        mp = d.get("mail_pressure") or {}
        if mp.get("saturated_hours"):
            add("warn", "mail_saturated", n=len(mp["saturated_hours"]), m=mp["max_per_hour"],
                b=len(mp.get("possibly_unmailed") or []))
        cov = d.get("coverage") or {}
        if (cov.get("inventory") or {}).get("missing"):
            miss = cov["inventory"]["missing"]
            add("warn", "inventory_missing", n=len(miss), a=", ".join(miss[:8]))
        if cov.get("version_drift"):
            add("info", "version_drift", n=len(cov["version_drift"]), v=cov.get("manager_version"))
        sla = (d.get("vulnerabilities") or {}).get("sla") or {}
        over = {k: v["overdue"] for k, v in sla.items() if isinstance(v, dict) and v.get("overdue")}
        if over:
            add("warn" if over.get("Critical") else "info", "vuln_overdue",
                s=", ".join(f"{k} {n}" for k, n in over.items()))
        pd = d.get("personal_data") or {}
        if pd.get("affected_alerts"):
            from ..privacy import SENSITIVE
            kinds = pd.get("kinds") or {}
            sens = any(k in SENSITIVE for k in kinds)
            add("warn" if sens else "info", "personal_data", n=pd["affected_alerts"], s=pd.get("sampled", 0),
                k=", ".join(f"{k} {n}" for k, n in sorted(kinds.items(), key=lambda x: -x[1])),
                src=", ".join(f"{x['location'] or x['agent']} (rule {x['rule_id']})" for x in pd["sources"][:3]))
        if self.errors:
            add("warn", "collector_errors", n=len(self.errors))
        return accept_flags(f, self.env.health_accept)
