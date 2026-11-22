# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Match check: the same sample events through the 4.x rule (whatif's evaluator) and the converted Sigma rule.

The Sigma side runs on the event re-shaped with the WCS names (fields.alert_to_wcs). This proves the conversion
on your events; a check against a real Wazuh 5.x indexer follows in the 4.x/5.x lab.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from defusedxml import ElementTree as SafeET

from ..rules import _normalise
from ..whatif import compile_rule
from .fields import _get, alert_to_wcs


def _vals(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def _one(field_mod: str, want: Any, doc: dict) -> bool:
    field, *mods = field_mod.split("|")
    have = _vals(_get(doc, field))
    wants = want if isinstance(want, list) else [want]
    mode_all = "all" in mods

    def test(w) -> bool:
        if isinstance(w, list):                       # value of a combined |all entry
            return any(test(x) for x in w)
        ws = str(w)
        for h in have:
            hl, wl = h.lower(), ws.lower()
            if "contains" in mods and wl in hl:
                return True
            if "startswith" in mods and hl.startswith(wl):
                return True
            if "endswith" in mods and hl.endswith(wl):
                return True
            if "re" in mods and re.search(ws, h):
                return True
            if "cidr" in mods:
                try:
                    if ipaddress.ip_address(h.strip()) in ipaddress.ip_network(ws, strict=False):
                        return True
                except ValueError:
                    pass
            if "gte" in mods:
                try:
                    if float(h) >= float(ws):
                        return True
                except ValueError:
                    pass
            if not {"contains", "startswith", "endswith", "re", "cidr", "gte"} & set(mods) and hl == wl:
                return True
        return False
    return all(test(w) for w in wants) if mode_all else any(test(w) for w in wants)


def sigma_matches(sigma: dict, wcs_doc: dict) -> bool:
    det = sigma["detection"]
    if not all(_one(k, v, wcs_doc) for k, v in det["selection"].items()):
        return False
    for name, block in det.items():
        if name.startswith("filter_") and all(_one(k, v, wcs_doc) for k, v in block.items()):
            return False
    return True


def check(xml: str, rows: list[dict], events: list[dict]) -> dict[str, dict]:
    """{rule_id: {"events", "xml_matches", "sigma_matches", "agree", "skipped"}} for converted/review rules."""
    root = SafeET.fromstring(f"<root>{_normalise(xml)}</root>")
    by_id = {r.get("id"): r for r in root.iter("rule")}
    wcs = [alert_to_wcs(e) for e in events]
    out: dict[str, dict] = {}
    for row in rows:
        if row["status"] == "unsupported" or row["id"] not in by_id:
            continue
        tests, skipped = compile_rule(by_id[row["id"]])
        if not tests:
            continue
        x = [all(t(e) for t in tests) for e in events]
        s = [sigma_matches(row["sigma"], w) for w in wcs]
        out[row["id"]] = {"events": len(events), "xml_matches": sum(x), "sigma_matches": sum(s),
                          "agree": sum(a == b for a, b in zip(x, s, strict=True)), "skipped": skipped}
    return out
