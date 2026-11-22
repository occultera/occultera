# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Small helpers shared by the collector, the watch and the tools: time ranges, buckets, flags."""
from __future__ import annotations

from datetime import UTC, datetime

from ..wazuh.schema import S


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def rng(frm: datetime | str, to: datetime | str) -> dict:
    f = iso(frm) if isinstance(frm, datetime) else frm
    t = iso(to) if isinstance(to, datetime) else to
    return {"range": {S.TS: {"gte": f, "lt": t}}}


def _b(agg: dict) -> list[dict]:
    return agg.get("buckets", []) if agg else []


def _int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _parse(ts: str) -> datetime:
    ts = ts.replace("Z", "+00:00")
    if len(ts) > 5 and ts[-5] in "+-" and ts[-3] != ":":  # +0000 → +00:00
        ts = ts[:-2] + ":" + ts[-2:]
    dt = datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def accept_flags(flags: list[dict], accepted: list[str]) -> list[dict]:
    """Warning flags listed in `health_accept` become informational (marked `accepted`); critical ones stay."""
    acc = set(accepted or [])
    for fl in flags:
        if fl["code"] in acc and fl["severity"] == "warn":
            fl["severity"] = "info"
            fl["accepted"] = True
    return flags


def health_status(flags: list[dict]) -> str:
    if any(f["severity"] == "critical" for f in flags):
        return "critical"
    if any(f["severity"] == "warn" for f in flags):
        return "warn"
    return "ok"
