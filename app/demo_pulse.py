# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Demo data for the cluster pulse page (invented names and documentation addresses only)."""
from __future__ import annotations

import math
from datetime import UTC, datetime


class DemoPrometheus:
    """Stands in for a Prometheus source in the demo: the pulse page shows fixed data, other callers see nothing."""

    demo = True

    async def query(self, expr: str, at: str | None = None) -> dict:
        return {"type": "vector", "series": [], "total_series": 0}

    async def query_range(self, expr: str, start, end, step) -> dict:
        return {"step": step, "series": [], "total_series": 0}

    async def close(self):
        return None


def _wave(n: int, base: float, amp: float, spike_at: int | None = None, spike: float = 0, phase: float = 0) -> list[float]:
    out = [max(0.0, base + amp * math.sin(i / 3.8 + phase)) for i in range(n)]
    if spike_at is not None:
        out[spike_at] += spike
    return out


def demo_pulse() -> dict:
    gb, mb = 1e9, 1e6
    egress_rows = [
        {"ns": "erp", "workload": "report-export", "bytes": 3.4 * gb, "avg": 0.12 * gb},
        {"ns": "shop", "workload": "api-gateway", "bytes": 2.1 * gb, "avg": 1.9 * gb},
        {"ns": "data", "workload": "kafka-broker-0", "bytes": 1.6 * gb, "avg": 1.5 * gb},
        {"ns": "data", "workload": "kafka-broker-1", "bytes": 1.5 * gb, "avg": 1.5 * gb},
        {"ns": "wazuh", "workload": "wazuh-manager-worker-0", "bytes": 640 * mb, "avg": 610 * mb},
        {"ns": "auth", "workload": "keycloak", "bytes": 310 * mb, "avg": 290 * mb},
        {"ns": "ci", "workload": "jenkins", "bytes": 220 * mb, "avg": 400 * mb},
        {"ns": "shop", "workload": "web", "bytes": 180 * mb, "avg": 170 * mb},
    ]
    for r in egress_rows:
        r["change"] = (r["bytes"] - r["avg"]) / r["avg"]
        r["status"] = "bad" if r["bytes"] / r["avg"] >= 10 else "warn" if r["bytes"] / r["avg"] >= 3 else "ok"
    total = sum(r["bytes"] for r in egress_rows) + 0.4 * gb
    avg = sum(r["avg"] for r in egress_rows) + 0.4 * gb
    cur = {"total": 1_204_000, "2xx": 1_101_000, "3xx": 41_300, "4xx": 59_800, "5xx": 1_900, "auth": 31_400, "404": 22_100}
    prev = {"total": 1_150_000, "2xx": 1_080_000, "3xx": 40_100, "4xx": 27_500, "5xx": 1_700, "auth": 6_200, "404": 19_800}
    return {
        "at": datetime.now(UTC).isoformat(), "errors": [], "status": "bad",
        "egress": {"total": total, "avg": avg, "change": (total - avg) / avg, "rows": egress_rows, "status": "bad",
                   "spark": _wave(25, 380 * mb, 60 * mb, 19, 2.9 * gb)},
        "ingress": {"source": "Traefik", "cur": cur, "prev": prev, "status_auth": "bad", "status_5xx": "ok", "status": "bad",
                    "spark_auth": _wave(25, 300, 120, 21, 18_000), "spark_5xx": _wave(25, 75, 30, phase=1.2),
                    "rows": [
                        {"route": "auth.keycloak.sso.example.com.8080", "errors": 26_900, "401": 2_100, "403": 24_300, "404": 500, "5xx": 0},
                        {"route": "shop.web.www.example.com.443", "errors": 14_200, "401": 0, "403": 900, "404": 13_100, "5xx": 200},
                        {"route": "shop.api-gateway.api.example.com.443", "errors": 9_800, "401": 3_600, "403": 400, "404": 4_200, "5xx": 1_400},
                        {"route": "ci.jenkins.ci.example.com.8080", "errors": 2_600, "401": 120, "403": 2_300, "404": 180, "5xx": 0},
                        {"route": "wazuh.dashboard.siem.example.com.443", "errors": 900, "401": 380, "403": 0, "404": 240, "5xx": 280},
                    ]},
        "secrets": {"reads": 41_200, "avg": 38_900, "change": 0.06, "writes": 37, "status": "ok",
                    "spark": _wave(25, 1700, 120, phase=0.4),
                    "rows": [{"verb": "GET", "count": 27_600, "avg": 26_000, "change": 0.06},
                             {"verb": "WATCH", "count": 13_900, "avg": 13_800, "change": 0.01},
                             {"verb": "LIST", "count": 13_600, "avg": 12_900, "change": 0.05},
                             {"verb": "PUT", "count": 31, "avg": 30, "change": 0.03},
                             {"verb": "DELETE", "count": 6, "avg": 4, "change": 0.5}]},
        "dns": {"total": 2_310_000, "avg": 2_250_000, "change": 0.03, "nx": 0.571, "nx_avg": 0.566, "servfail": 0,
                "status": "ok", "spark": _wave(25, 96_000, 9_000, phase=2.0)},
        "cpu": {"total": 18.4, "hot": 1, "status": "warn", "rows": [
            {"ns": "ci", "workload": "build-runner", "cores": 3.6, "avg": 0.4, "x": 9.0, "status": "warn"},
            {"ns": "data", "workload": "etl-worker", "cores": 1.2, "avg": 0.7, "x": 1.7, "status": "ok"},
            {"ns": "shop", "workload": "api-gateway", "cores": 0.9, "avg": 0.8, "x": 1.1, "status": "ok"}]},
        "restarts": {"total": 14, "avg": 6.0, "change": 1.33, "oom": 3, "status": "warn",
                     "spark": _wave(25, 0.3, 0.4, 9, 6),
                     "rows": [{"ns": "erp", "workload": "report-export", "count": 11},
                              {"ns": "shop", "workload": "web", "count": 2},
                              {"ns": "data", "workload": "etl-worker", "count": 1}],
                     "reasons": {"Error": 6, "OOMKilled": 3, "Completed": 2}},
        "certs": {"soonest": 6.5, "n_warn": 2, "status": "bad", "rows": [
            {"ns": "auth", "name": "sso-example-tls", "issuer": "letsencrypt", "days": 6.5, "ready": False, "status": "bad"},
            {"ns": "shop", "name": "wildcard-example", "issuer": "letsencrypt", "days": 17.2, "ready": True, "status": "warn"},
            {"ns": "ci", "name": "ci-example-tls", "issuer": "letsencrypt", "days": 58.0, "ready": True, "status": "ok"},
            {"ns": "monitoring", "name": "prometheus-admission", "issuer": "self-signed", "days": 302.9, "ready": True,
             "status": "ok"}]},
        "targets": {"total": 96, "down": 1, "status": "warn", "rows": [
            {"job": "kubernetes-pods", "instance": "198.51.100.41:9464", "ns": "erp", "pod": "report-export-7c9d8b6f5-x2k4p"}]},
    }
