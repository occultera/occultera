# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Wazuh 4.x alert fields → Wazuh Common Schema (5.0 rc). Unknown `data.*` fields keep their name under `data.`."""
from __future__ import annotations

from typing import Any

FIELDS: dict[str, str] = {
    "full_log": "event.original",
    "location": "log.file.path",
    "agent.name": "wazuh.agent.name",
    "agent.id": "wazuh.agent.id",
    "agent.ip": "wazuh.agent.host.ip",
    "manager.name": "wazuh.cluster.node",
    "rule.id": "wazuh.rule.id",
    "rule.level": "wazuh.rule.level",
    "rule.description": "wazuh.rule.title",
    "rule.groups": "wazuh.rule.groups",
    "decoder.name": "wazuh.decoders.name",
    "predecoder.program_name": "process.name",
    "predecoder.hostname": "host.hostname",
    "data.srcip": "source.ip",
    "data.dstip": "destination.ip",
    "data.srcport": "source.port",
    "data.dstport": "destination.port",
    "data.srcuser": "source.user.name",
    "data.dstuser": "user.name",
    "data.user": "user.name",
    "data.url": "url.original",
    "data.protocol": "network.protocol",
    "data.id": "event.code",
    "data.status": "event.outcome",
    "data.action": "event.action",
    "data.system_name": "host.name",
    "data.extra_data": "event.reason",
    "syscheck.path": "file.path",
    "syscheck.event": "event.action",
}

# rule condition element → 4.x alert field it tests
CONDITION_FIELD: dict[str, str] = {
    "match": "full_log", "regex": "full_log", "srcip": "data.srcip", "dstip": "data.dstip", "srcport": "data.srcport",
    "dstport": "data.dstport", "srcuser": "data.srcuser", "dstuser": "data.dstuser", "user": "data.user",
    "url": "data.url", "id": "data.id", "status": "data.status", "action": "data.action", "protocol": "data.protocol",
    "system_name": "data.system_name", "extra_data": "data.extra_data", "hostname": "predecoder.hostname",
    "program_name": "predecoder.program_name", "location": "location",
}


def to_wcs(name: str) -> tuple[str, bool]:
    """(WCS name, known?) for a 4.x field name; `field name="x"` elements are decoded fields under `data.`."""
    if name in FIELDS:
        return FIELDS[name], True
    full = name if name.startswith("data.") or "." in name and name.split(".")[0] in ("rule", "agent") else "data." + name
    if full in FIELDS:
        return FIELDS[full], True
    return full, False


def _get(doc: dict, path: str) -> Any:
    cur: Any = doc
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _set(doc: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    cur = doc
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
        if not isinstance(cur, dict):
            return
    cur[parts[-1]] = value


def _walk(d: dict, prefix: str = ""):
    for k, v in d.items():
        p = f"{prefix}{k}"
        if isinstance(v, dict):
            yield from _walk(v, p + ".")
        else:
            yield p, v


def alert_to_wcs(doc: dict) -> dict:
    """A 4.x alert document re-shaped with the WCS names (for the match check; not a full 5.x event)."""
    out: dict = {}
    for path, v in _walk(doc):
        new = FIELDS.get(path)
        if new is None and path.startswith("data."):
            new = path
        if new and _get(out, new) is None:
            _set(out, new, v)
    return out
