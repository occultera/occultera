# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The watch's small pieces: fields, event shape, classification, muting, quiet hours, AI verdicts."""
from __future__ import annotations

import logging
import math
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ..collector import _parse
from ..config import DAYS
from ..i18n import t
from ..notify import NotifyCfg
from ..settingsdoc import CHANNELS, TUNABLE, WatchSettings
from ..store import new_id, now_iso
from ..wazuh.schema import S

if TYPE_CHECKING:
    pass
log = logging.getLogger("wdt.watch")


def fields() -> list[str]:
    return [S.TS, S.AGENT_NAME, S.RULE_ID, S.RULE_LEVEL, S.RULE_DESC, S.RULE_GROUPS, S.SRCIP,
            S.SRCUSER, S.DSTUSER, S.LOCATION, S.FULL_LOG]
AUTH_FAIL = ["authentication_failed", "authentication_failures"]
AUTH_OK = ["authentication_success"]
MAX_HITS = 500
MAX_WINDOW_MINUTES = 120          # after downtime the watch does not replay more than this
PROM_FRESH = 2 * 3600             # a cluster alert active longer than this when first seen is not "new"
PENDING = ("new", "notified", "held", "muted")
VERDICTS = ("real_incident", "investigate", "expected", "noise")


def _get(d: dict, path: str) -> Any:
    cur: Any = d
    for p in path.split("."):
        cur = cur.get(p) if isinstance(cur, dict) else None
    return cur


def _groups(src: dict) -> list[str]:
    g = _get(src, S.RULE_GROUPS) or []
    return [g] if isinstance(g, str) else [str(x) for x in g]


def _level(src: dict) -> int:
    try:
        return int(_get(src, S.RULE_LEVEL) or 0)
    except (TypeError, ValueError):
        return 0


def classify(src: dict, cfg: WatchSettings, rules: set[str], groups: set[str]) -> tuple[str, str] | None:
    """``(trigger, severity)`` for one alert, most specific trigger first; ``None`` when nothing applies."""
    g = set(_groups(src))
    lvl = _level(src)
    if cfg.on("active_response") and "active_response" in g:
        return "active_response", "high"
    if cfg.on("level") and lvl >= cfg.critical_level:
        return "level", "critical" if lvl >= max(cfg.critical_level, 15) else "high"
    if cfg.on("rules") and str(_get(src, S.RULE_ID)) in rules:
        return "rules", "high"
    if cfg.on("groups") and g & groups and lvl >= cfg.group_min_level:
        return "groups", "high"
    return None


def _event(env_id: str, key: str, trigger: str, severity: str, **kw) -> dict:
    now = now_iso()
    return {"id": new_id("w"), "env": env_id, "key": key, "trigger": trigger, "severity": severity,
            "status": "new", "verdict": None, "created_at": now, "last_seen": now, "count": 1, **kw}




POD_SUFFIX = "(-[a-z0-9]{6,10})?-[a-z0-9]{5}"
WORKLOAD_RX = "(.+?)" + POD_SUFFIX
NAME_OK = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?/[a-z0-9]([a-z0-9.-]*[a-z0-9])?")


def _rx(name: str) -> str:
    """A Kubernetes name as a literal inside a PromQL regex string (only ``.`` needs escaping); ``*`` is a wildcard."""
    return name.replace(".", "\\\\.").replace("*", ".*")


def _num(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def fmt_bytes(n: float) -> str:
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if n >= size:
            v = n / size
            return f"{v:.1f} {unit}" if v < 10 else f"{v:,.0f} {unit}"
    return f"{n:.0f} B"


def _agg_ts(agg: dict | None) -> datetime | None:
    if not agg:
        return None
    v = agg.get("value_as_string") or agg.get("value")
    if v is None:
        return None
    try:
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v / 1000, UTC)
        return _parse(str(v))
    except (ValueError, OSError):
        return None


# ------------------------------------------------------------------ sorting out
def muted(ev: dict, mute: list[str]) -> bool:
    """A mute entry is an event key, a key prefix ending in ``*`` or ``rule:<id>``."""
    for m in mute:
        if m == ev["key"] or (m.endswith("*") and ev["key"].startswith(m[:-1])):
            return True
        if m.startswith("rule:") and m[5:] in (ev.get("rule_ids") or []):
            return True
    return False


def known_noise(ev: dict, baseline_rules: set[str]) -> bool:
    """Alert-based events whose rule a human already filed as known noise (knowledge base ``baseline``)."""
    return ev["trigger"] in ("rules", "groups", "level", "spike") and ev["severity"] != "critical" \
        and bool(ev.get("rule_ids")) and set(ev["rule_ids"]) <= baseline_rules


def channels_for(cfg: NotifyCfg, selected: list[str]) -> NotifyCfg:
    """The notification config limited to the channels chosen in the settings page (empty = all)."""
    if not selected:
        return cfg
    out = cfg.model_copy(deep=True)
    for name in CHANNELS:
        if name not in selected:
            setattr(out, name, type(getattr(out, name))())
    return out


def quiet_now(cfg: WatchSettings, now_local: datetime) -> bool:
    day = DAYS[now_local.weekday()]
    prev = DAYS[(now_local.weekday() - 1) % 7]
    return cfg.quiet.active(now_local.strftime("%H:%M"), day, prev)


def event_line(ev: dict, lang: str) -> str:
    mark = "🔴" if ev["severity"] == "critical" else "🟠"
    where = ", ".join((ev.get("agents") or [])[:3])
    bits = [t(lang, "watch.trigger." + ev["trigger"])]
    if ev.get("rule_ids") and ev["rule_ids"][0]:
        bits.append(f"{ev['rule_ids'][0]} (L{ev.get('level', '?')})")
    head = f"{mark} [{' · '.join(bits)}] {ev.get('title') or ev['key']}"
    tail = [f"×{ev['count']}"] if ev.get("count", 1) > 1 and ev["trigger"] in ("level", "rules", "groups",
                                                                                "active_response") else []
    if where and ev["trigger"] != "agents":
        tail.append(where)
    if ev.get("srcips") and ev["trigger"] != "brute_force":
        tail.append(", ".join(ev["srcips"][:3]))
    return head + (" — " + " · ".join(tail) if tail else "")


def compact_for_ai(ev: dict) -> dict:
    """What the AI round sees of one event (ids and numbers; the sample goes through the masker like all text)."""
    keep = ("id", "trigger", "severity", "title", "rule_ids", "level", "agents", "srcips", "users", "count",
            "first_seen", "last_seen", "baseline", "factor", "successes", "status", "sample", "contributors",
            "recurring", "workload", "bytes", "baseline_bytes", "peak_7d_bytes", "cluster", "alert",
            "alert_severity", "namespaces", "targets", "still_firing")
    return {k: ev[k] for k in keep if ev.get(k) not in (None, "", [])}


def normalize_verdicts(raw, known_ids: set[str]) -> list[dict]:
    """Model output → verdicts for events that exist; a malformed entry is dropped, never fatal."""
    out: list[dict] = []
    if not isinstance(raw, list):
        return out
    for v in raw:
        if not isinstance(v, dict) or str(v.get("event_id")) not in known_ids:
            continue
        verdict = str(v.get("verdict") or "")
        if verdict not in VERDICTS:
            verdict = "investigate"
        sug = None
        s = v.get("suggestion")
        if isinstance(s, dict):
            if s.get("mute") is True:
                sug = {"type": "mute"}
            elif s.get("param") in TUNABLE:
                try:
                    val = float(s.get("value"))
                except (TypeError, ValueError):
                    val = None
                lo, hi = TUNABLE[s["param"]]
                if val is not None and lo <= val <= hi:
                    sug = {"type": "param", "param": s["param"], "value": val}
            if sug:
                sug["why"] = str(s.get("why") or "")[:300]
        out.append({"event_id": str(v["event_id"]), "verdict": verdict, "reason": str(v.get("reason") or "")[:600],
                    "suggestion": sug})
    return out


# ------------------------------------------------------------------ runtime side
