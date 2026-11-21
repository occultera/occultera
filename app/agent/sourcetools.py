# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The tools over the other sources of an environment: Prometheus (one or more clusters), Loki, Kubernetes."""
from __future__ import annotations


class SourceTools:
    """Mixed into ``ToolBox``; ``self.sources`` holds the started source clients."""

    sources: dict

    def _prom(self, a):
        from ..services import clusters_of
        cs = clusters_of(self.sources)
        name = str(a.get("cluster") or "")
        if not name or len(cs) == 1:
            return self.sources["prometheus"]
        if name not in cs:
            raise ValueError(f"unknown cluster {name!r}; one of {sorted(cs)}")
        return cs[name]

    async def prom_query(self, a):
        return await self._prom(a).query(a["expr"], a.get("time"))

    async def prom_alerts(self, a):
        from ..clusteralerts import collect, for_ai
        from ..services import clusters_of
        cs = clusters_of(self.sources)
        name = str(a.get("cluster") or "")
        if name:
            if name not in cs:
                raise ValueError(f"unknown cluster {name!r}; one of {sorted(cs)}")
            cs = {name: cs[name]}
        res = await collect(cs)
        return {n: ({"counts": r["counts"], "alerts": for_ai(r["groups"])} if "groups" in r else r)
                for n, r in res.items()}

    async def prom_range(self, a):
        return await self._prom(a).query_range(a["expr"], a.get("from"), a.get("to"), a.get("step"))

    async def loki_query(self, a):
        return await self.sources["loki"].query(a["query"], a.get("from"), a.get("to"), int(a.get("limit") or 100),
                                                "forward" if a.get("oldest_first") else "backward")

    async def loki_labels(self, a):
        return await self.sources["loki"].labels(a.get("name"))

    async def k8s_get(self, a):
        return await self.sources["kubernetes"].get(a["kind"], a.get("namespace"), a.get("name"),
                                                    a.get("label_selector"), a.get("field_selector"),
                                                    int(a.get("limit") or 200))

    async def k8s_logs(self, a):
        return await self.sources["kubernetes"].logs(a["namespace"], a["pod"], a.get("container"),
                                                     int(a.get("tail") or 200), bool(a.get("previous")),
                                                     a.get("since_seconds"))
