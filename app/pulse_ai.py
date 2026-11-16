# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""AI explanation of the alerts a cluster's Prometheus is firing (cluster pulse → "Explain with AI").

The model gets the grouped alerts and may check them with ``prom_query`` on that cluster; everything it sees goes
through the environment's masking like every other AI call. The answer is kept in memory for six hours per
environment and cluster; without a model (demo, provider ``mock``) a plain list is written instead.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime

from .clusteralerts import counts, for_ai, group
from .i18n import OUTPUT_LANGUAGE

log = logging.getLogger("wdt.pulse_ai")
TTL = 6 * 3600
_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}

SYSTEM = """You are an experienced SRE and security engineer. Explain the alerts that the Prometheus of the
Kubernetes/OpenShift cluster "{cluster}" (environment "{env}") is firing right now, for the person on call.

- Group alerts that share a cause into one item. For each item: what is happening in plain words, the likely cause,
  the impact, a priority (now / today / this week / noise) and one to three concrete checks (oc / kubectl / PromQL).
- Put anything that touches security first (certificates, authentication, unexpected workloads, exposed services).
- Say plainly which alerts are expected noise for this kind of cluster (for example overcommit on a test cluster)
  and how to tune or silence them.
- Before you claim a cause, check it with prom_query (cluster="{cluster}"); a few queries are enough.
- Do not invent alerts or numbers. Write in {language}, markdown, short headings, no preamble, at most ~450 words."""


def cached(env_id: str, cluster: str) -> dict | None:
    hit = _CACHE.get((env_id, cluster))
    return hit[1] if hit and time.time() - hit[0] < TTL else None


def _plain(groups: list[dict], lang: str) -> str:
    if not groups:
        return "—"
    return "\n".join(f"- **{g['name']}** ({g['severity']}, ×{g['count']})"
                     + (f" — {', '.join(g['namespaces'][:4])}" if g.get("namespaces") else "")
                     + (f": {g['summary']}" if g.get("summary") else "") for g in groups)


async def explain(runtime, env_id: str, cluster: str, lang: str) -> dict:
    from .agent.runner import run_agent
    from .agent.tools import ToolBox
    from .llm.base import LLMError
    from .services import clusters_of
    rt = runtime.get(env_id)
    cs = clusters_of(rt.sources)
    if cluster not in cs:
        raise KeyError(cluster)
    groups = group(await cs[cluster].alerts())
    c = counts(groups)
    sysmsg = SYSTEM.format(cluster=cluster, env=rt.env.name, language=OUTPUT_LANGUAGE.get(lang, "English"))
    usr = (f"# Firing alerts on {cluster} at {datetime.now(UTC).isoformat()} "
           f"(critical {c['critical']}, warning {c['warning']}, other {c['other']})\n"
           f"```json\n{json.dumps(for_ai(groups), ensure_ascii=False)}\n```")
    ai = False
    if not groups:
        md = "—"
    else:
        tb = ToolBox(rt.env, rt.ix, rt.api, rt.repo, mode="tools", sources=rt.sources)
        tb._handlers = {k: v for k, v in tb._handlers.items() if k in ("prom_query", "prom_range", "prom_alerts")}
        try:
            if runtime.llm_cfg(rt.env).provider == "mock":
                raise LLMError("demo mode")
            res = await run_agent(runtime.llm_for(rt.env), sysmsg, [{"role": "user", "content": usr}], tb,
                                  min(runtime.llm_cfg(rt.env).max_tool_steps, 8))
            md, ai = (res.text or "").strip() or _plain(groups, lang), bool((res.text or "").strip())
        except LLMError as e:
            log.warning("pulse explanation without AI: %s", e)
            md = _plain(groups, lang)
    out = {"cluster": cluster, "md": md, "ai": ai, "at": datetime.now(UTC).isoformat(), "counts": c}
    _CACHE[(env_id, cluster)] = (time.time(), out)
    return out
