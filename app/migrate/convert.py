# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""One custom XML rule → one Sigma rule (or a reason why a person has to do it)."""
from __future__ import annotations

import re
import uuid
from typing import Any

import yaml
from defusedxml import ElementTree as SafeET

from ..rules import _normalise
from ..wazuh.schema import severity_of
from ..whatif import os_regex
from .fields import CONDITION_FIELD, to_wcs

NS = uuid.UUID("6f1f6c0e-6c1b-4f4e-9d8a-0cc0e1a7e2a1")     # stable Sigma ids per Wazuh rule id
SKIP = {"description", "options", "group", "info", "mitre"}
REVIEW = {
    "list": "CDB list lookup — Sigma has no list match; use a detector with a lookup or inline the values",
    "time": "time-of-day condition — not expressible in Sigma",
    "weekday": "weekday condition — not expressible in Sigma",
    "if_matched_group": "correlation with an earlier group — needs a Sigma correlation rule",
    "check_diff": "check_diff compares with the previous event — no Sigma equivalent",
    "if_fts": "first-time-seen logic — no Sigma equivalent",
}
GROUP_BY = {"same_source_ip": "source.ip", "same_srcip": "source.ip", "same_dstip": "destination.ip",
            "same_user": "user.name", "same_location": "log.file.path", "same_id": "event.code",
            "same_srcuser": "source.user.name", "same_dstuser": "user.name"}
SAME = re.compile(r"^(same|different|not_same)_")
CORR = "frequency/timeframe — converted as the base detection; add a Sigma correlation rule (event_count)"


def _osmatch(text: str) -> tuple[str, Any]:
    """OS_Match → (modifier, value or values). Case-insensitive substring semantics, `|` = OR, ^/$ anchors."""
    alts = text.split("|")
    if all(a.startswith("^") and a.endswith("$") and len(a) > 1 for a in alts):
        return "", [a[1:-1] for a in alts]
    if all(a.startswith("^") for a in alts):
        return "|startswith", [a[1:] for a in alts]
    if all(a.endswith("$") for a in alts):
        return "|endswith", [a[:-1] for a in alts]
    if any(a.startswith("^") or a.endswith("$") for a in alts):
        return "|re", "(?i)" + "|".join(("^" if a.startswith("^") else "") + re.escape(a.strip("^$"))
                                        + ("$" if a.endswith("$") else "") for a in alts)
    return "|contains", alts if len(alts) > 1 else alts[0]


def _value(tag: str, attrs: dict, text: str) -> tuple[str, Any, list[str]]:
    """(modifier, value, notes) for a textual condition."""
    typ = (attrs.get("type") or "").lower()
    if typ == "pcre2":
        return "|re", text, []
    if tag == "match" or typ == "osmatch":
        if text.startswith("!"):
            return "!", text, []
        m, v = _osmatch(text)
        return m, v, []
    if typ == "osregex" or tag in ("regex", "field") or tag in CONDITION_FIELD:
        if tag in ("srcip", "dstip"):
            return "|cidr", [x.strip() for x in text.split(",") if x.strip()], []
        pat = os_regex(text).pattern
        if re.fullmatch(r"[A-Za-z0-9_.@:/ -]+", text) and tag not in ("regex", "field"):
            return "", text, []                              # a plain word: exact value
        return "|re", pat, ["OS_Regex translated to PCRE; check the dialect"]
    return "|re", text, []


def convert_rule(r, by_id: dict[str, Any], depth: int = 0) -> dict:
    rid = r.get("id") or "?"
    level = int(r.get("level") or 0)
    desc = next(((el.text or "").strip() for el in r.iter("description")), "") or f"Wazuh rule {rid}"
    review, notes, unknown = [], [], []
    sel: dict[str, Any] = {}
    filters: list[dict] = []
    logsource: dict[str, str] = {"product": "wazuh"}
    if r.get("overwrite") == "yes":
        review.append("overwrite=\"yes\" changes a stock rule — re-create the change on the 5.x stock detector")
    if (r.get("frequency") or r.get("timeframe")) and not any(el.tag == "if_matched_sid" for el in r):
        review.append(CORR)
    for el in r:
        tag, text, attrs = el.tag, (el.text or "").strip(), dict(el.attrib)
        if tag in SKIP:
            continue
        if tag in REVIEW:
            review.append(REVIEW[tag])
            continue
        if SAME.match(tag):
            review.append(f"<{tag}> needs a Sigma correlation rule (group-by)")
            continue
        if tag == "if_matched_sid":
            review.append("correlation with earlier events of rule " + text + " — the base detection is converted; "
                          "add a Sigma correlation rule (event_count over the timeframe)")
        if tag in ("if_sid", "if_matched_sid"):
            for pid in re.split(r"[,\s]+", text):
                parent = by_id.get(pid)
                if parent is not None and depth < 4:          # parent in the same file: inline its conditions
                    sub = convert_rule(parent, by_id, depth + 1)
                    for k, v in (sub.get("_selection") or {}).items():
                        sel.setdefault(k, v)
                    filters += sub.get("_filters") or []
                    review += [f"from parent {pid}: {x}" for x in sub["review"]]
                    logsource.update(sub.get("_logsource") or {})
                    notes.append(f"conditions of parent rule {pid} inlined")
                elif pid:
                    review.append(f"parent rule {pid} is a stock rule — find the 5.x stock detector it maps to "
                                  "and add its conditions")
            continue
        if tag == "if_group":
            sel.setdefault("wazuh.rule.groups|contains", []).append(text)
            notes.append("if_group kept as wazuh.rule.groups — the 5.x detector may group differently")
            continue
        if tag == "decoded_as":
            logsource["service"] = text
            continue
        if tag == "if_level":
            sel["wazuh.rule.level|gte"] = int(text or 0)
            continue
        if tag == "field":
            src = attrs.get("name", "")
        elif tag in CONDITION_FIELD:
            src = CONDITION_FIELD[tag]
        else:
            unknown.append(tag)
            continue
        wcs, known = to_wcs(src)
        if not known and tag == "field":
            notes.append(f"field {src} kept as {wcs} — map it to your 5.x decoder output")
        neg = attrs.get("negate") == "yes" or (tag in ("srcip", "dstip") and text.startswith("!"))
        mod, val, n = _value(tag, attrs, text.lstrip("!") if tag in ("srcip", "dstip") else text)
        notes += n
        if mod == "!":                                        # OS_Match with a leading "!"
            neg, (mod, val) = True, _osmatch(text[1:])
        key = wcs + mod
        if neg:
            filters.append({key: val})
        elif key in sel:
            review.append(f"two conditions on {key} — combined with AND, check the intent")
            sel[key + "|all"] = [sel.pop(key), val]
        else:
            sel[key] = val
    if unknown:
        review.append("unsupported elements: " + ", ".join(sorted(set(f"<{t}>" for t in unknown))))
    mitre = [(i.text or "").strip() for m in r.iter("mitre") for i in m.iter("id") if i.text]
    groups = [g.strip() for el in r.iter("group") for g in (el.text or "").split(",") if g.strip()]
    status = "review" if review else "converted"
    if not sel and not filters:
        status, review = "unsupported", review + ["no condition that Sigma can express"]
    detection: dict[str, Any] = {"selection": sel or {"wazuh.rule.id": rid}}
    cond = "selection"
    for i, f in enumerate(filters, 1):
        detection[f"filter_{i}"] = f
        cond += f" and not filter_{i}"
    detection["condition"] = cond
    sigma = {
        "title": desc[:120], "id": str(uuid.uuid5(NS, rid)), "status": "experimental",
        "description": f"Converted by occultera-migrate from Wazuh 4.x rule {rid} (level {level}).",
        "author": "occultera-migrate", "logsource": logsource, "detection": detection,
        "level": severity_of(level),
        "tags": [f"attack.{m.lower()}" for m in mitre] + [f"wazuh.group.{g}" for g in groups][:10],
        "falsepositives": ["Unknown — compare with the 4.x rule on real events before enabling"],
        "fields": [], "custom": {"wazuh_rule_id": rid, "wazuh_level": level},
    }
    if not sigma["tags"]:
        sigma.pop("tags")
    sigma.pop("fields")
    corr = None
    if r.get("frequency") and status != "unsupported":
        gb = sorted({GROUP_BY[el.tag] for el in r if el.tag in GROUP_BY})
        corr = {"title": f"{desc[:110]} (correlation)", "id": str(uuid.uuid5(NS, rid + "/correlation")),
                "status": "experimental", "correlation": {
                    "type": "event_count", "rules": [sigma["id"]], **({"group-by": gb} if gb else {}),
                    "timespan": f"{int(r.get('timeframe') or 60)}s",
                    "condition": {"gte": int(r.get("frequency") or 2)}},
                "level": severity_of(level)}
        notes.append("Sigma correlation draft (event_count) added after the base rule")
    return {"id": rid, "title": desc, "level": level, "status": status, "review": review, "notes": sorted(set(notes)),
            "sigma": sigma, "correlation": corr, "_selection": sel, "_filters": filters, "_logsource": logsource}


def convert(xml: str) -> dict:
    """Every <rule> in the text → result rows plus a coverage summary."""
    root = SafeET.fromstring(f"<root>{_normalise(xml)}</root>")
    rules = list(root.iter("rule"))
    by_id = {r.get("id"): r for r in rules if r.get("id")}
    rows = [convert_rule(r, by_id) for r in rules]
    for row in rows:
        docs = [row["sigma"]] + ([row["correlation"]] if row.get("correlation") else [])
        row["yaml"] = yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True, width=120)
        for k in ("_selection", "_filters", "_logsource"):
            row.pop(k, None)
    count = {s: sum(1 for r in rows if r["status"] == s) for s in ("converted", "review", "unsupported")}
    total = len(rows) or 1
    decoders = len(list(root.iter("decoder")))
    return {"rules": rows, "summary": {**count, "total": len(rows), "decoders_reported": decoders,
                                      "coverage_percent": round(100 * count["converted"] / total)}}
