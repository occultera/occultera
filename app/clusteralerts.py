# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Alerts the clusters' own Prometheus fires (Alertmanager rules: KubePodCrashLooping, etcd, disk …).

Grouped by alert name and severity so that one rule firing for twenty pods is one line. Used by the cluster pulse
(panel and the AI explanation), the daily review (``cluster_alerts`` in the collected summary), the watch
(``prom_alerts`` trigger) and the ``prom_alerts`` tool.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

# always firing by design (the alerting pipeline's heartbeat) or only there to inhibit others
IGNORE = frozenset({"Watchdog", "InfoInhibitor"})
SEVERITY_ORDER = {"critical": 0, "error": 1, "warning": 2, "info": 3, "none": 4}
TARGET_LABELS = ("pod", "node", "instance", "service", "deployment", "statefulset", "daemonset", "job_name",
                 "persistentvolumeclaim", "container", "name")


def _ts(v) -> datetime | None:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def group(alerts: list[dict], limit: int = 60) -> list[dict]:
    """``[{name, severity, count, namespaces, targets, since, summary, description}]``, most severe first."""
    by: dict[tuple[str, str], dict] = {}
    for a in alerts:
        lab, ann = a.get("labels") or {}, a.get("annotations") or {}
        name = str(lab.get("alertname") or "")
        if not name or name in IGNORE:
            continue
        sev = str(lab.get("severity") or "none").lower()
        g = by.setdefault((name, sev), {"name": name, "severity": sev, "count": 0, "namespaces": set(),
                                        "targets": [], "since": None, "summary": "", "description": ""})
        g["count"] += 1
        if lab.get("namespace"):
            g["namespaces"].add(str(lab["namespace"]))
        tgt = next((f"{k}={lab[k]}" for k in TARGET_LABELS if lab.get(k)), "")
        if tgt and tgt not in g["targets"] and len(g["targets"]) < 6:
            g["targets"].append(tgt)
        t = _ts(a.get("active_at"))
        if t and (g["since"] is None or t < g["since"]):
            g["since"] = t
        if not g["summary"]:
            g["summary"] = str(ann.get("summary") or ann.get("message") or "")[:300]
        if not g["description"]:
            g["description"] = str(ann.get("description") or ann.get("message") or "")[:600]
    out = []
    for g in by.values():
        g["namespaces"] = sorted(g["namespaces"])[:12]
        g["since"] = g["since"].isoformat() if g["since"] else None
        out.append(g)
    out.sort(key=lambda g: (SEVERITY_ORDER.get(g["severity"], 5), -g["count"], g["name"]))
    return out[:limit]


def counts(groups: list[dict]) -> dict[str, int]:
    c = {"critical": 0, "warning": 0, "other": 0}
    for g in groups:
        k = g["severity"] if g["severity"] in ("critical", "warning") else "other"
        c[k] += g["count"]
    return c


async def collect(clusters: dict, limit: int = 40) -> dict[str, dict]:
    """``{cluster: {"groups": [...], "counts": {...}}}`` or ``{"error": …}`` per cluster; never raises."""
    async def one(p):
        try:
            g = group(await p.alerts(), limit)
            return {"groups": g, "counts": counts(g)}
        except Exception as e:  # noqa: BLE001 - one unreachable cluster must not hide the others
            return {"error": f"{type(e).__name__}: {str(e)[:200]}"}
    names = list(clusters)
    res = await asyncio.gather(*(one(clusters[n]) for n in names))
    return dict(zip(names, res, strict=True))


def for_ai(groups: list[dict]) -> list[dict]:
    keep = ("name", "severity", "count", "namespaces", "targets", "since", "summary", "description")
    return [{k: g[k] for k in keep if g.get(k) not in (None, "", [])} for g in groups]
