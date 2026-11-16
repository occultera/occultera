# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Per-environment service container: clients, store and the run/deploy locks."""
from __future__ import annotations

import asyncio
import logging

from .config import Environment
from .store import MemoryStore, Repo

log = logging.getLogger("wdt")


class Clusters(dict):
    """Every Prometheus of one environment by cluster name (the first is the default)."""

    async def close(self):
        for p in self.values():
            await p.close()


def clusters_of(sources: dict | None) -> dict:
    """``{name: Prometheus}`` for an environment's sources (also when only the single ``prometheus`` is set)."""
    src = sources or {}
    if src.get("clusters"):
        return dict(src["clusters"])
    return {"default": src["prometheus"]} if src.get("prometheus") else {}


def build_sources(env: Environment) -> dict:
    """Prometheus / Loki / Kubernetes clients for one environment (only those configured)."""
    from .sources import Kubernetes, Loki, Prometheus, SourceError
    out: dict = {}
    sc = env.sources
    clusters = Clusters()
    if sc.prometheus:
        out["prometheus"] = clusters[sc.prometheus.name or "default"] = Prometheus(sc.prometheus)
    for ep in sc.prometheus_extra:
        clusters[ep.name] = Prometheus(ep)
    if clusters:
        out.setdefault("prometheus", next(iter(clusters.values())))   # the default for tools that take one
        out["clusters"] = clusters
    if sc.loki:
        out["loki"] = Loki(sc.loki)
    if sc.kubernetes.enabled:
        try:
            out["kubernetes"] = Kubernetes(sc.kubernetes)
        except (SourceError, OSError) as e:
            log.warning("%s: Kubernetes source disabled: %s", env.id, e)
    return out


class EnvRuntime:
    def __init__(self, env: Environment, ix, api, store):
        self.env = env
        self.ix = ix
        self.api = api
        self.store = store
        self.repo = Repo(store, env.id)
        self.lock = asyncio.Lock()
        self.deploy_lock = asyncio.Lock()
        self.current_run: str | None = None
        self.settings = None            # EnvSettings, loaded lazily from <prefix>-settings (Runtime.env_settings)
        self.settings_at = 0.0
        self.sources: dict = build_sources(env) if not isinstance(store, MemoryStore) else {}
