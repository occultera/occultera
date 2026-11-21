# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Alert filters and the compact event shape the tools return, in the bound Wazuh schema."""
from __future__ import annotations

import json
from typing import Any

from ..collector import iso
from ..query_guard import field, query_string, time_range
from ..wazuh.schema import S


def event_fields() -> list[str]:
    """The event fields returned to the model, in the bound schema."""
    return [S.TS, S.AGENT_NAME, S.AGENT_ID, S.RULE_ID, S.RULE_LEVEL, S.RULE_DESC, S.RULE_GROUPS,
            S.FULL_LOG, S.LOCATION, S.DECODER, S.SRCIP, S.SRCUSER, S.DSTUSER,
            S.URL, S.EVENT_ID, S.PROTOCOL, S.FIM_PATH, S.FIM_EVENT,
            S.VERB, S.USERNAME, S.K8S_OBJECT, S.K8S_STATUS,
            S.ALERT_CVE, S.ALERT_VULN_SEV, S.ALERT_VULN_PKG]


def _filters(a: dict, limits=None) -> list[dict]:
    """Build the filter clauses; the time window, field names and query text pass the guard rails."""
    max_hours = int(getattr(limits, "max_range_hours", 24 * 14))
    frm, to = time_range(a.get("from") or "now-24h", a.get("to") or "now", max_hours)
    extra = getattr(limits, "extra_fields", None)
    f: list[dict] = [{"range": {S.TS: {"gte": iso(frm), "lte": iso(to)}}}]
    q = query_string(a.get("query"), extra)
    if q:
        f.append({"query_string": {"query": q, "analyze_wildcard": True, "default_operator": "AND",
                                   "allow_leading_wildcard": False, "max_determinized_states": 2000}})
    if a.get("rule_ids"):
        f.append({"terms": {S.RULE_ID: [str(x) for x in a["rule_ids"]][:50]}})
    if a.get("agent"):
        f.append({"term": {field(S.AGENT_NAME, extra): str(a["agent"])}})
    if a.get("min_level") is not None:
        f.append(S.level_gte(int(a["min_level"])))
    return f


def _compact_event(src: dict) -> dict:
    out: dict[str, Any] = {}

    def put(path, val):
        if val in (None, "", [], {}):
            return
        if isinstance(val, str) and len(val) > 500:
            val = val[:500] + "…"
        out[path] = val

    for f in event_fields():
        cur: Any = src
        for p in f.split("."):
            cur = cur.get(p) if isinstance(cur, dict) else None
        if isinstance(cur, dict):
            cur = json.dumps(cur, ensure_ascii=False)[:300]
        put(f, cur)
    return out
