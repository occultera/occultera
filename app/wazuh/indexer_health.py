# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Indexer (OpenSearch) health beyond green/yellow/red: heap, circuit breakers, shards per heap, unassigned shards.

Pure functions over the indexer's own answers (``_nodes/stats``, ``_cat/shards``, ``_cluster/health``,
``_cat/allocation``), so the report, the watch and the tests share one judgement. Each finding carries a code and
the numbers; the advice text lives in the i18n files (``flag.indexer_*``).
"""
from __future__ import annotations

from collections import Counter
from typing import Any

HEAP_WARN, HEAP_CRIT = 85, 95
SHARDS_PER_HEAP_GB = 20          # OpenSearch / Elastic sizing guidance: at most ~20 shards per GB of heap
RECOVERY_REASONS = {"CLUSTER_RECOVERED", "NODE_LEFT", "NODE_RESTARTING", "INDEX_CREATED", "INDEX_REOPENED",
                    "EXISTING_INDEX_RESTORED", "DANGLING_INDEX_IMPORTED", "REINITIALIZED"}
GB = 1024 ** 3


def _i(x: Any) -> int | None:
    try:
        return int(float(x))
    except (TypeError, ValueError):
        return None


def nodes(stats: dict | None, alloc: list | None = None) -> list[dict]:
    """One row per data node: heap use, parent breaker trips, shard count."""
    shards = {a.get("node"): _i(a.get("shards")) for a in alloc or [] if a.get("node")}
    out = []
    for n in ((stats or {}).get("nodes") or {}).values():
        mem = (n.get("jvm") or {}).get("mem") or {}
        parent = ((n.get("breakers") or {}).get("parent") or {})
        name = n.get("name")
        heap_max = _i(mem.get("heap_max_in_bytes")) or 0
        out.append({
            "node": name,
            "heap_percent": _i(mem.get("heap_used_percent")),
            "heap_max_gb": round(heap_max / GB, 1) if heap_max else None,
            "breaker_tripped": _i(parent.get("tripped")) or 0,
            "breaker_limit_gb": round((_i(parent.get("limit_size_in_bytes")) or 0) / GB, 2) or None,
            "shards": shards.get(name),
        })
    return sorted(out, key=lambda r: str(r["node"]))


def shard_summary(rows: list | None) -> dict:
    """Unassigned / initializing shards grouped by reason, primaries vs replicas, top indices."""
    un = [r for r in rows or [] if r.get("state") == "UNASSIGNED"]
    init = [r for r in rows or [] if r.get("state") == "INITIALIZING"]
    return {
        "unassigned": len(un),
        "unassigned_primary": sum(1 for r in un if r.get("prirep") == "p"),
        "unassigned_replica": sum(1 for r in un if r.get("prirep") == "r"),
        "initializing": len(init),
        "reasons": dict(Counter(r.get("unassigned.reason") or "?" for r in un).most_common()),
        "indices": [i for i, _ in Counter(r.get("index") for r in un if r.get("prirep") == "p").most_common(5)],
    }


def findings(health: dict | None, node_rows: list[dict], shards: dict | None, data_nodes: int | None = None) -> list[dict]:
    """[{severity, code, **numbers}] — deterministic, no model involved."""
    f: list[dict] = []
    for n in node_rows:
        p = n.get("heap_percent")
        if p is not None and p >= HEAP_WARN:
            f.append({"severity": "critical" if p >= HEAP_CRIT else "warn", "code": "indexer_heap",
                      "node": n["node"], "p": p, "g": n.get("heap_max_gb")})
        if n.get("breaker_tripped"):
            f.append({"severity": "warn", "code": "indexer_breaker", "node": n["node"], "n": n["breaker_tripped"],
                      "g": n.get("heap_max_gb")})
        g, s = n.get("heap_max_gb"), n.get("shards")
        if g and s and s > SHARDS_PER_HEAP_GB * g:
            f.append({"severity": "warn", "code": "indexer_shards", "node": n["node"], "s": s, "g": g,
                      "m": int(SHARDS_PER_HEAP_GB * g)})
    sh = shards or {}
    h = health or {}
    if sh.get("unassigned") or sh.get("initializing"):
        reasons = set(sh.get("reasons") or {})
        recovering = (sh.get("initializing") or h.get("initializing_shards")) and reasons <= RECOVERY_REASONS
        if sh.get("unassigned_primary") and recovering:
            f.append({"severity": "info", "code": "indexer_recovering", "i": sh.get("initializing") or 0,
                      "u": sh["unassigned"], "p": round(float(h.get("active_shards_percent_as_number") or 0), 1)})
        elif sh.get("unassigned_primary"):
            f.append({"severity": "critical", "code": "indexer_primaries", "n": sh["unassigned_primary"],
                      "r": ", ".join(f"{k} {v}" for k, v in (sh.get("reasons") or {}).items()),
                      "x": ", ".join(sh.get("indices") or [])})
        if "ALLOCATION_FAILED" in reasons:
            f.append({"severity": "warn", "code": "indexer_alloc_failed", "n": (sh.get("reasons") or {})["ALLOCATION_FAILED"]})
        if sh.get("unassigned_replica") and (data_nodes or h.get("number_of_data_nodes") or 0) == 1:
            f.append({"severity": "info", "code": "indexer_replicas", "n": sh["unassigned_replica"]})
    return f
