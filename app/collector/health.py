# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Collector sections about the stack itself: health, liveness, vulnerabilities, agent coverage."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ..i18n import t
from ..wazuh import indexer_health as IH
from ..wazuh.schema import S
from .util import _b, _int, _parse, iso


class HealthMixin:
    """Indexer and manager health, liveness, vulnerabilities and agent coverage."""

    async def _health(self, now: datetime) -> dict:
        h: dict[str, Any] = {}
        ch = await self._safe("indexer_health", self.ix.cluster_health())
        if ch:
            h["indexer"] = {k: ch.get(k) for k in ("status", "number_of_nodes", "active_shards",
                                                     "unassigned_shards", "active_shards_percent_as_number")}
        alloc = await self._safe("indexer_disk", self.ix.allocation())
        if alloc:
            h["indexer_disk"] = [
                {"node": a.get("node"), "percent": _int(a.get("disk.percent")),
                 "shards": _int(a.get("shards"))} for a in alloc if a.get("node")
            ]
        ns = await self._safe("indexer_nodes", self.ix.node_stats())
        if ns:
            h["indexer_nodes"] = IH.nodes(ns, alloc)
        if ch and (ch.get("unassigned_shards") or ch.get("initializing_shards")):
            rows = await self._safe("indexer_shards", self.ix.shards())
            if rows is not None:
                h["indexer_shards"] = IH.shard_summary(rows)
        if ch:
            h["indexer"].update({k: ch.get(k) for k in ("initializing_shards", "number_of_data_nodes")})
        last = await self._safe("last_alert", self.ix.search(self.env.alerts_index, {
            "size": 1, "sort": [{S.TS: "desc"}], "_source": [S.TS, S.MANAGER, S.AGENT_NAME],
            "query": {"range": {S.TS: {"gte": "now-7d", "lte": "now+5m"}}},
        }))
        if last is not None:
            hits = last["hits"]["hits"]
            if hits:
                ts = hits[0]["_source"][S.TS]
                h["last_alert"] = ts
                h["silence_minutes"] = round((now - _parse(ts)).total_seconds() / 60)
            else:
                h["last_alert"] = None
                h["silence_minutes"] = None
        # which manager nodes produced alerts recently
        mgr = await self._safe("alert_managers", self.ix.search(self.env.alerts_index, {
            "size": 0, "query": {"range": {S.TS: {"gte": "now-2h"}}},
            "aggs": {"m": {"terms": {"field": S.MANAGER, "size": 10},
                           "aggs": {"last": {"max": {"field": S.TS}}}}},
        }))
        if mgr:
            h["managers_last_2h"] = [{"manager": b["key"], "count": b["doc_count"],
                                      "last": b["last"].get("value_as_string")}
                                     for b in _b(mgr["aggregations"]["m"])]
        if self.api:
            info = await self._safe("api_info", self.api.info())
            if info:
                h["api_version"] = info.get("api_version")
            cl = await self._safe("cluster", self.api.cluster_health())
            if cl:
                h["cluster"] = cl
            ms = await self._safe("manager_status", self.api.manager_status())
            if ms:
                h["daemons_not_running"] = sorted(k for k in self.env.required_daemons if ms.get(k, "running") != "running")
                h["daemons_stopped_optional"] = sorted(k for k, v in ms.items()
                                                       if v != "running" and k not in self.env.required_daemons)
            sm = await self._safe("agents_summary", self.api.agents_summary())
            if sm:
                h["agents_summary"] = sm.get("connection", sm)
            bad = await self._safe("agents_bad", self.api.agents(status="disconnected,never_connected,pending"))
            if bad is not None:
                h["agents_not_active"] = [
                    {"id": a.get("id"), "name": a.get("name"), "status": a.get("status"),
                     "lastKeepAlive": a.get("lastKeepAlive"), "version": a.get("version")}
                    for a in bad if a.get("id") != "000"
                ]
            errs = await self._safe("manager_errors", self.api.manager_errors(limit=40))
            if errs is not None:
                # group identical messages
                agg: dict[str, dict] = {}
                for e in errs:
                    key = (e.get("tag", ""), (e.get("description") or "")[:160])
                    d = agg.setdefault("|".join(key), {"tag": key[0], "msg": key[1], "count": 0,
                                                        "last": e.get("timestamp")})
                    d["count"] += 1
                h["manager_errors"] = list(agg.values())[:15]
        return h

    # ------------------------------------------------------------------ liveness (every few minutes)

    async def liveness(self, now: datetime, silence_minutes: int) -> dict[str, str]:
        """Critical problems only, as {code: message}. Cheap: a few small queries, no aggregations."""
        L, p = self.lang, {}
        try:
            ch = await self.ix.cluster_health()
            if ch.get("status") == "red":
                p["indexer_status"] = t(L, "flag.indexer_status", s="red")
        except Exception as e:  # noqa: BLE001
            p["indexer_down"] = t(L, "live.indexer_down", e=str(e)[:160])
            return p  # nothing else can be checked through the indexer
        try:
            for a in await self.ix.allocation() or []:
                pc = _int(a.get("disk.percent"))
                if a.get("node") and pc is not None and pc >= 90:
                    p[f"indexer_disk:{a['node']}"] = t(L, "flag.indexer_disk", node=a["node"], p=pc)
        except Exception:  # noqa: BLE001
            pass
        try:
            for n in IH.nodes(await self.ix.node_stats()):
                if (n.get("heap_percent") or 0) >= IH.HEAP_CRIT:
                    p[f"indexer_heap:{n['node']}"] = t(L, "flag.indexer_heap", node=n["node"], p=n["heap_percent"],
                                                       g=n.get("heap_max_gb"))
        except Exception:  # noqa: BLE001
            pass
        try:
            last = await self.ix.search(self.env.alerts_index, {
                "size": 1, "sort": [{S.TS: "desc"}], "_source": [S.TS],
                "query": {"range": {S.TS: {"gte": "now-7d", "lte": "now+5m"}}}})
            hits = last["hits"]["hits"]
            if not hits:
                p["silence"] = t(L, "flag.no_alerts_7d")
            else:
                sil = round((now - _parse(hits[0]["_source"][S.TS])).total_seconds() / 60)
                if sil > silence_minutes:
                    p["silence"] = t(L, "flag.silence", m=sil, t=silence_minutes)
        except Exception as e:  # noqa: BLE001
            p["alerts_query"] = t(L, "live.query_failed", e=str(e)[:160])
        if self.api:
            try:
                ms = await self.api.manager_status()
                down = sorted(k for k in self.env.required_daemons if ms.get(k, "running") != "running")
                if down:
                    p["daemons"] = t(L, "flag.daemons", d=", ".join(down))
            except Exception as e:  # noqa: BLE001
                p["api_down"] = t(L, "live.api_down", e=str(e)[:160])
            try:
                cl = await self.api.cluster_health()
                if cl and cl.get("enabled") == "yes" and cl.get("running") != "yes":
                    p["cluster"] = t(L, "flag.cluster")
            except Exception:  # noqa: BLE001
                pass
        return p

    # ------------------------------------------------------------------ volume

    async def _vulns(self, now: datetime | None = None) -> dict | None:
        now = now or datetime.now(UTC)
        sla = self.env.vuln_sla.days()
        aggs: dict[str, Any] = {
            "sev": {"terms": {"field": S.VULN_SEV, "size": 10}},
            "crit_agents": {"filter": {"term": {S.VULN_SEV: "Critical"}},
                            "aggs": {"a": {"terms": {"field": S.AGENT_NAME, "size": 15}}}},
            "crit_pkgs": {"filter": {"term": {S.VULN_SEV: "Critical"}},
                          "aggs": {"p": {"terms": {"field": S.PKG_NAME, "size": 15}}}},
            "dated": {"filter": {"exists": {"field": S.VULN_DETECTED}}},
        }
        for sev, days in sla.items():  # open longer than the SLA allows
            aggs[f"over_{sev}"] = {
                "filter": {"bool": {"filter": [
                    {"term": {S.VULN_SEV: sev}},
                    {"range": {S.VULN_DETECTED: {"lt": iso(now - timedelta(days=days))}}}]}},
                "aggs": {"a": {"terms": {"field": S.AGENT_NAME, "size": 10}},
                         "p": {"terms": {"field": S.PKG_NAME, "size": 8}},
                         "oldest": {"min": {"field": S.VULN_DETECTED}}}}
        r = await self.ix.search(self.env.vuln_index, {"size": 0, "aggs": aggs})
        if r["hits"]["total"]["value"] == 0:
            return None
        ag = r["aggregations"]
        out = {"severity": {b["key"]: b["doc_count"] for b in _b(ag["sev"])},
               "critical_by_agent": {b["key"]: b["doc_count"] for b in _b(ag["crit_agents"]["a"])},
               "critical_by_package": {b["key"]: b["doc_count"] for b in _b(ag["crit_pkgs"]["p"])}}
        if sla:
            if not ag["dated"]["doc_count"]:
                out["sla"] = {"unavailable": True}
            else:
                out["sla"] = {sev: {"days": days, "overdue": ag[f"over_{sev}"]["doc_count"],
                                    "by_agent": {b["key"]: b["doc_count"] for b in _b(ag[f"over_{sev}"]["a"])},
                                    "by_package": {b["key"]: b["doc_count"] for b in _b(ag[f"over_{sev}"]["p"])},
                                    "oldest": (ag[f"over_{sev}"]["oldest"] or {}).get("value_as_string")}
                              for sev, days in sla.items()}
        return out

    # ------------------------------------------------------------------ anomalies (no AI)

    async def _coverage(self, now: datetime) -> dict:
        agents = [a for a in await self.api.agents(limit=5000) if str(a.get("id")) != "000"]
        info = await self._safe("api_info", self.api.info()) or {}
        mver = str(info.get("api_version") or "").lstrip("v")
        by_status: dict[str, int] = {}
        versions: dict[str, int] = {}
        by_node: dict[str, int] = {}
        drift, stale, never = [], [], []
        for a in agents:
            st = a.get("status") or "?"
            by_status[st] = by_status.get(st, 0) + 1
            v = str(a.get("version") or "").replace("Wazuh", "").strip().lstrip("v")
            if v:
                versions[v] = versions.get(v, 0) + 1
                if mver and v != mver:
                    drift.append({"name": a.get("name"), "version": v})
            node = a.get("node_name") or "-"
            if st == "active":
                by_node[node] = by_node.get(node, 0) + 1
            if st == "never_connected":
                never.append(a.get("name"))
            elif st != "active":
                ka = a.get("lastKeepAlive")
                try:
                    hrs = round((now - _parse(ka)).total_seconds() / 3600, 1) if ka else None
                except ValueError:
                    hrs = None
                stale.append({"name": a.get("name"), "status": st, "last_keepalive": ka, "hours": hrs})
        out = {"total": len(agents), "by_status": by_status, "manager_version": mver, "versions": versions,
               "version_drift": drift[:60], "active_by_node": by_node, "not_active": stale[:60], "never_connected": never}
        if self.inventory:
            have = {str(a.get("name")) for a in agents}
            inv = set(self.inventory)
            out["inventory"] = {"expected": len(inv), "missing": sorted(inv - have), "unexpected": sorted(have - inv)}
        return out

    # ------------------------------------------------------------------ flags
