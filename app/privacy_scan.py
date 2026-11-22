# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Personal data stored in clear text in Wazuh: detection in alerts (split from privacy.py; names re-exported there)."""
from __future__ import annotations

import json
import re

from .privacy import DETECTORS, Masker

# ------------------------------------------------------------------ detection in logs


def scan(text: str, kinds: set[str] | None = None) -> dict[str, int]:
    """Validated personal-data hits in ``text`` per kind (no values returned)."""
    out: dict[str, int] = {}
    for d in DETECTORS:
        if (kinds and d.kind not in kinds) or (not kinds and d.optional):
            continue
        for m in d.rx.finditer(text):
            val = m.groupdict().get("v") or m.group(0)
            if d.ok and not d.ok(val):
                continue
            out[d.kind] = out.get(d.kind, 0) + 1
    return out


def scan_alerts(hits: list[dict], kinds: set[str] | None = None, allow: list[str] | None = None,
                top: int = 15) -> dict:
    """Group personal-data hits by rule × agent × location; examples are fully masked."""
    allow_rx = [re.compile(a) for a in allow or []]
    groups: dict[tuple, dict] = {}
    totals: dict[str, int] = {}
    affected = 0
    for h in hits:
        s = h.get("_source") or h
        payload = {k: s.get(k) for k in ("full_log", "data") if s.get(k)}
        desc = str((s.get("rule") or {}).get("description") or "")
        in_desc = scan(desc, kinds) if desc else {}
        txt = json.dumps({**payload, "rule_description": desc}, ensure_ascii=False, default=str)
        for a in allow_rx:
            txt = a.sub("", txt)
        found = scan(txt, kinds)
        if not found:
            continue
        affected += 1
        r = s.get("rule") or {}
        key = (str(r.get("id", "")), (s.get("agent") or {}).get("name", ""), s.get("location", ""))
        g = groups.setdefault(key, {"rule_id": key[0], "rule": r.get("description", ""), "agent": key[1],
                                    "location": key[2], "decoder": (s.get("decoder") or {}).get("name", ""),
                                    "alerts": 0, "kinds": {}, "example": ""})
        g["alerts"] += 1
        if in_desc:   # the rule itself copies personal data into rule.description (indexed, mailed, dashboards)
            g["in_rule_description"] = True
        for k, n in found.items():
            g["kinds"][k] = g["kinds"].get(k, 0) + n
            totals[k] = totals.get(k, 0) + n
        if not g["example"]:
            ex = Masker(ips="keep").mask(str(s.get("full_log") or txt) + (f" | rule: {desc}" if in_desc else ""))
            g["example"] = ex[:300]
    rows = sorted(groups.values(), key=lambda g: (-len([k for k in g["kinds"] if k in SENSITIVE]), -g["alerts"]))
    return {"sampled": len(hits), "affected_alerts": affected, "kinds": totals, "sources": rows[:top]}


# kinds that are clearly a leak (special care) — the rest (e-mail, phone) are often legitimate in auth logs
SENSITIVE = {"password", "private_key", "jwt", "bearer", "aws_key", "card", "iban",
             "national_id_tr", "national_id_be", "national_id_fr"}
