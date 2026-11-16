# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Cluster pulse: security-relevant signals read from Prometheus, shown on one page.

Deterministic, no AI. Every panel compares the last 24 hours with the daily average of the six days before (the
window stays inside a 7-day retention) and gets a status — ``ok``, ``warn`` or ``bad`` — from fixed thresholds:

* outbound transfer per workload (cAdvisor), the volume behind the watch's ``egress`` trigger
* ingress responses (Kong, Traefik or ingress-nginx, whichever has metrics): 401/403 (credential stuffing, scanning), 404/405, 5xx; the routes with most errors
* Kubernetes API reads of secrets (reconnaissance, token theft)
* DNS (CoreDNS) volume and NXDOMAIN share (tunnelling, DGA malware)
* CPU per workload against its own average (crypto miners)
* container restarts and the last termination reasons (OOMKilled, crash loops)
* certificates managed by cert-manager (days left, not ready)
* scrape targets that are down — the places where this page, and Occultera, are blind

A panel whose metrics do not exist (no Kong, no cert-manager …) says so instead of failing; one broken query
never hides the others.
"""
from __future__ import annotations

import asyncio
import logging
import math
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from .watch import WORKLOAD_RX, _rx

log = logging.getLogger("wdt.pulse")

TTL = 60.0
_CACHE: dict[str, tuple[float, dict]] = {}
BASE = "[6d] offset 1d"           # six full days before the last 24 h: inside a 7-day retention
BASE_DAYS = 6
CERT_WARN_DAYS, CERT_BAD_DAYS = 21, 7
CPU_MIN_CORES, CPU_WARN_X = 0.25, 3.0
RATE_WARN_X, RATE_BAD_X = 3.0, 10.0
# ingress controllers, tried in this order: (name, request counter, status-code label, route label)
INGRESS = (("Kong", "kong_http_requests_total", "code", "route"),
           ("Traefik", "traefik_router_requests_total", "code", "router"),
           ("Traefik", "traefik_service_requests_total", "code", "service"),
           ("ingress-nginx", "nginx_ingress_controller_requests", "status", "ingress"))


def _num(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def ratio_status(cur: float | None, base: float | None, floor: float = 0) -> str:
    """``bad``/``warn``/``ok`` for a count against its daily average; small numbers never raise a flag."""
    if cur is None or cur <= floor:
        return "ok"
    if not base:
        return "warn"
    x = cur / base
    return "bad" if x >= RATE_BAD_X else "warn" if x >= RATE_WARN_X else "ok"


def cert_status(days: float, ready: bool = True) -> str:
    if not ready or days < CERT_BAD_DAYS:
        return "bad"
    return "warn" if days < CERT_WARN_DAYS else "ok"


def worst(*states: str) -> str:
    return "bad" if "bad" in states else "warn" if "warn" in states else "ok"


def change(cur: float | None, base: float | None) -> float | None:
    return (cur - base) / base if cur is not None and base else None


def code_class(code: str) -> str:
    return f"{code[0]}xx" if code[:1] in "12345" and len(code) == 3 else "other"


def _wl(inner: str) -> str:
    """Per-pod vector → per-workload vector (``workload`` = pod name without its ReplicaSet/DaemonSet suffix)."""
    return f'sum by (namespace, workload) (label_replace(label_replace({inner}, "workload", "$1", "pod", "(.+)"), ' \
           f'"workload", "$1", "pod", "{WORKLOAD_RX}"))'


class Pulse:
    def __init__(self, prom, exclude: list[str], now: datetime | None = None):
        self.p, self.now = prom, now or datetime.now(UTC)
        self.at = self.now.isoformat()
        self.exclude = "|".join(_rx(n) for n in exclude)
        self.errors: list[str] = []

    # ------------------------------------------------------------------ query helpers
    async def vec(self, expr: str) -> list[tuple[dict, float]]:
        r = await self.p.query(expr, self.at)
        out = []
        for s in r.get("series") or []:
            v = _num(s.get("value"))
            if v is not None:
                out.append((s.get("labels") or {}, v))
        return out

    async def one(self, expr: str) -> float | None:
        rows = await self.vec(expr)
        return sum(v for _, v in rows) if rows else None

    async def hourly(self, expr: str) -> list[float]:
        start = (self.now - timedelta(hours=24)).isoformat()
        r = await self.p.query_range(expr, start, self.at, "3600s")
        s = (r.get("series") or [])
        if not s:
            return []
        return [_num(v) or 0.0 for _, v in s[0].get("points") or []]

    def sel(self, metric: str, extra: str = "") -> str:
        parts = ['pod!=""'] + ([f'namespace!~"{self.exclude}"'] if self.exclude else []) + ([extra] if extra else [])
        return metric + "{" + ",".join(parts) + "}"

    # ------------------------------------------------------------------ panels
    async def egress(self) -> dict:
        sel = self.sel("container_network_transmit_bytes_total")
        cur = _wl(f"sum by (namespace, pod) (increase({sel}[24h]))")
        base = _wl(f"sum by (namespace, pod) (increase({sel}{BASE}))")
        top, prev, total, total_base, spark = await asyncio.gather(
            self.vec(f"topk(8, {cur})"), self.vec(f"({base}) and on (namespace, workload) topk(8, {cur})"),
            self.one(f"sum(increase({sel}[24h]))"), self.one(f"sum(increase({sel}{BASE}))"),
            self.hourly(f"sum(increase({sel}[1h]))"))
        if total is None:
            return {"empty": True}
        b = {(lab.get("namespace"), lab.get("workload")): v / BASE_DAYS for lab, v in prev}
        rows = []
        for lab, v in sorted(top, key=lambda x: -x[1]):
            k = (lab.get("namespace"), lab.get("workload"))
            avg = b.get(k)
            rows.append({"ns": k[0], "workload": k[1], "bytes": v, "avg": avg, "change": change(v, avg),
                         "status": ratio_status(v, avg, floor=1e9)})
        tb = (total_base or 0) / BASE_DAYS
        return {"total": total, "avg": tb, "change": change(total, tb), "spark": spark, "rows": rows,
                "status": worst(*(r["status"] for r in rows))}

    async def _ingress_source(self) -> tuple[str, str, str, str] | None:
        """The first ingress controller with metrics: (name, metric, status label, route label)."""
        for name, metric, code, route in INGRESS:
            if await self.one(f"count({metric})"):
                return name, metric, code, route
        return None

    async def ingress(self) -> dict:
        src = await self._ingress_source()
        if src is None:
            return {"empty": True}
        name, m, cl, rl = src

        def sel(rx: str) -> str:
            return f'{m}{{{cl}=~"{rx}"}}'
        codes, base, routes, rcodes, s4, s5 = await asyncio.gather(
            self.vec(f"sum by ({cl}) (increase({m}[24h]))"), self.vec(f"sum by ({cl}) (increase({m}{BASE}))"),
            self.vec(f"topk(8, sum by ({rl}) (increase({sel('4..|5..')}[24h])))"),
            self.vec(f"sum by ({rl}, {cl}) (increase({sel('401|403|404|5..')}[24h])) and on ({rl}) "
                     f"topk(8, sum by ({rl}) (increase({sel('4..|5..')}[24h])))"),
            self.hourly(f"sum(increase({sel('401|403')}[1h]))"),
            self.hourly(f"sum(increase({sel('5..')}[1h]))"))
        if not codes:
            return {"empty": True}

        def group(rows):
            g: dict[str, float] = {"total": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "auth": 0, "404": 0}
            for lab, v in rows:
                c = str(lab.get(cl) or "")
                g["total"] += v
                cc = code_class(c)
                if cc in g:
                    g[cc] += v
                if c in ("401", "403"):
                    g["auth"] += v
                if c in ("404", "405"):
                    g["404"] += v
            return g
        cur, prev = group(codes), {k: v / BASE_DAYS for k, v in group(base).items()}
        per: dict[str, dict] = {}
        for lab, v in rcodes:
            r = str(lab.get(rl) or "")
            c = str(lab.get(cl) or "")
            d = per.setdefault(r, {"401": 0, "403": 0, "404": 0, "5xx": 0})
            if c.startswith("5"):
                d["5xx"] += v
            else:
                d[c] = d.get(c, 0) + v
        rows = [{"route": str(lab.get(rl) or ""), "errors": v, **per.get(str(lab.get(rl) or ""), {})}
                for lab, v in sorted(routes, key=lambda x: -x[1])]
        st_auth = ratio_status(cur["auth"], prev["auth"], floor=500)
        st_5xx = ratio_status(cur["5xx"], prev["5xx"], floor=500)
        return {"source": name, "cur": cur, "prev": prev, "rows": rows, "spark_auth": s4, "spark_5xx": s5,
                "status_auth": st_auth, "status_5xx": st_5xx, "status": worst(st_auth, st_5xx)}

    async def secrets(self) -> dict:
        m = 'apiserver_request_total{resource="secrets"}'
        verbs, base, spark = await asyncio.gather(
            self.vec(f"sum by (verb) (increase({m}[24h]))"), self.vec(f"sum by (verb) (increase({m}{BASE}))"),
            self.hourly('sum(increase(apiserver_request_total{resource="secrets",verb=~"GET|LIST"}[1h]))'))
        if not verbs:
            return {"empty": True}
        b = {str(lab.get("verb")): v / BASE_DAYS for lab, v in base}
        rows = [{"verb": str(lab.get("verb")), "count": v, "avg": b.get(str(lab.get("verb"))),
                 "change": change(v, b.get(str(lab.get("verb"))))} for lab, v in sorted(verbs, key=lambda x: -x[1]) if v >= 0.5]
        reads = sum(r["count"] for r in rows if r["verb"] in ("GET", "LIST"))
        reads_avg = sum(r["avg"] or 0 for r in rows if r["verb"] in ("GET", "LIST"))
        writes = sum(r["count"] for r in rows if r["verb"] in ("CREATE", "POST", "PUT", "PATCH", "DELETE"))
        st = ratio_status(reads, reads_avg, floor=1000)
        return {"reads": reads, "avg": reads_avg, "change": change(reads, reads_avg), "writes": writes,
                "rows": rows, "spark": spark, "status": st}

    async def dns(self) -> dict:
        m = "coredns_dns_responses_total"
        cur, base, spark = await asyncio.gather(
            self.vec(f"sum by (rcode) (increase({m}[24h]))"), self.vec(f"sum by (rcode) (increase({m}{BASE}))"),
            self.hourly(f"sum(increase({m}[1h]))"))
        if not cur:
            return {"empty": True}
        c = {str(lab.get("rcode")): v for lab, v in cur}
        b = {str(lab.get("rcode")): v / BASE_DAYS for lab, v in base}
        total, total_b = sum(c.values()), sum(b.values())
        nx = c.get("NXDOMAIN", 0) / total if total else 0
        nx_b = b.get("NXDOMAIN", 0) / total_b if total_b else None
        st = worst(ratio_status(total, total_b, floor=10_000),
                   "warn" if nx_b is not None and nx - nx_b >= 0.15 else "ok",
                   "warn" if c.get("SERVFAIL", 0) > max(100, 3 * b.get("SERVFAIL", 0)) else "ok")
        return {"total": total, "avg": total_b, "change": change(total, total_b), "nx": nx, "nx_avg": nx_b,
                "servfail": c.get("SERVFAIL", 0), "spark": spark, "status": st}

    async def cpu(self) -> dict:
        sel = self.sel("container_cpu_usage_seconds_total", 'container!=""')
        cur = _wl(f"sum by (namespace, pod) (rate({sel}[1h]))")
        base = f"({_wl(f'sum by (namespace, pod) (increase({sel}{BASE}))')} / {BASE_DAYS * 86400})"
        ratio = f"topk(8, ({cur} > {CPU_MIN_CORES}) / on (namespace, workload) ({base} > 0.01))"
        top_x, cores, avg, total = await asyncio.gather(
            self.vec(ratio), self.vec(f"({cur}) and on (namespace, workload) {ratio}"),
            self.vec(f"{base} and on (namespace, workload) {ratio}"),
            self.one(f"sum(rate({sel}[1h]))"))
        if total is None:
            return {"empty": True}
        cc = {(lab.get("namespace"), lab.get("workload")): v for lab, v in cores}
        aa = {(lab.get("namespace"), lab.get("workload")): v for lab, v in avg}
        rows = []
        for lab, x in sorted(top_x, key=lambda r: -r[1]):
            k = (lab.get("namespace"), lab.get("workload"))
            rows.append({"ns": k[0], "workload": k[1], "cores": cc.get(k), "avg": aa.get(k), "x": x,
                         "status": "warn" if x >= CPU_WARN_X else "ok"})
        hot = [r for r in rows if r["status"] != "ok"]
        return {"total": total, "rows": rows, "hot": len(hot), "status": "warn" if hot else "ok"}

    async def restarts(self) -> dict:
        m = "kube_pod_container_status_restarts_total"
        top, total, base, spark, reasons = await asyncio.gather(
            self.vec(f"topk(8, {_wl(f'sum by (namespace, pod) (increase({m}[24h]))')} > 0.5)"),
            self.one(f"sum(increase({m}[24h]))"), self.one(f"sum(increase({m}{BASE}))"),
            self.hourly(f"sum(increase({m}[1h]))"),
            self.vec("sum by (reason) (kube_pod_container_status_last_terminated_reason)"))
        if total is None:
            return {"empty": True}
        b = (base or 0) / BASE_DAYS
        rows = [{"ns": lab.get("namespace"), "workload": lab.get("workload"), "count": round(v)}
                for lab, v in sorted(top, key=lambda x: -x[1])]
        rs = {str(lab.get("reason")): round(v) for lab, v in reasons if v >= 0.5}
        st = worst(ratio_status(total, b, floor=20), "warn" if any(r["count"] >= 10 for r in rows) else "ok")
        return {"total": round(total), "avg": b, "change": change(total, b), "rows": rows, "reasons": rs,
                "oom": rs.get("OOMKilled", 0), "spark": spark, "status": st}

    async def certs(self) -> dict:
        left, notready = await asyncio.gather(
            self.vec("certmanager_certificate_expiration_timestamp_seconds - time()"),
            self.vec('certmanager_certificate_ready_status{condition="False"} == 1'))
        if not left:
            return {"empty": True}
        bad = {(lab.get("exported_namespace") or lab.get("namespace"), lab.get("name")) for lab, _ in notready}
        rows = []
        for lab, sec in left:
            k = (lab.get("exported_namespace") or lab.get("namespace"), lab.get("name"))
            ready = k not in bad
            d = sec / 86400
            rows.append({"ns": k[0], "name": k[1], "issuer": lab.get("issuer_name") or "", "days": d,
                         "ready": ready, "status": cert_status(d, ready)})
        rows.sort(key=lambda r: r["days"])
        return {"rows": rows, "soonest": rows[0]["days"], "n_warn": sum(r["status"] != "ok" for r in rows),
                "status": worst(*(r["status"] for r in rows))}

    async def targets(self) -> dict:
        up, down = await asyncio.gather(self.one("count(up)"), self.vec("up == 0"))
        if up is None:
            return {"empty": True}
        rows = [{"job": lab.get("job") or "", "instance": lab.get("instance") or "",
                 "ns": lab.get("namespace") or "", "pod": lab.get("pod") or ""} for lab, _ in down]
        rows.sort(key=lambda r: (r["job"], r["instance"]))
        return {"total": round(up), "down": len(rows), "rows": rows, "status": "warn" if rows else "ok"}

    async def _safe(self, name: str, coro) -> dict:
        try:
            return await coro
        except Exception as e:  # noqa: BLE001 - one broken panel must not hide the others
            log.warning("pulse %s failed: %s", name, e)
            self.errors.append(name)
            return {"error": f"{type(e).__name__}"}

    async def collect(self) -> dict:
        names = ("egress", "ingress", "secrets", "dns", "cpu", "restarts", "certs", "targets")
        res = await asyncio.gather(*(self._safe(n, getattr(self, n)()) for n in names))
        out: dict[str, Any] = dict(zip(names, res, strict=True))
        out["at"] = self.now.isoformat()
        out["errors"] = self.errors
        out["status"] = worst(*(p.get("status", "ok") for p in res))
        return out


async def pulse(env_id: str, prom, exclude: list[str], use_cache: bool = True) -> dict:
    if getattr(prom, "demo", False):
        from .demo_pulse import demo_pulse
        return demo_pulse()
    hit = _CACHE.get(env_id)
    if use_cache and hit and time.monotonic() - hit[0] < TTL:
        return hit[1]
    data = await Pulse(prom, exclude).collect()
    _CACHE[env_id] = (time.monotonic(), data)
    return data


__all__ = ["Pulse", "cert_status", "code_class", "pulse", "ratio_status", "worst"]
