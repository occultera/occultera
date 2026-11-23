# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""ISO/IEC 27001:2022 Annex A evidence summary for the monthly audit report.

Deterministic, no model involved: every status rests on a number that ``audit.build()`` already produced. The report
supports an ISMS with monitoring evidence; it is not a statement of conformity. Only the ~10 controls a SIEM review
really produces evidence for are covered.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

CATALOG = {
    "A.5.9": "Inventory of information and other associated assets",
    "A.5.25": "Assessment and decision on information security events",
    "A.5.26": "Response to information security incidents",
    "A.5.27": "Learning from information security incidents",
    "A.5.28": "Collection of evidence",
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.15": "Logging",
    "A.8.16": "Monitoring activities",
    "A.8.32": "Change management",
}

SECTION_MAP = {
    "volume": ["A.8.15", "A.8.16"],
    "runs": ["A.8.16", "A.5.25"],
    "findings": ["A.5.25", "A.5.26"],
    "rule_changes": ["A.8.32"],
    "knowledge": ["A.5.27"],
    "liveness": ["A.8.15", "A.8.16"],
    "coverage": ["A.5.9", "A.8.16"],
    "vulnerabilities": ["A.8.8"],
}

Result = tuple[str, str, dict]          # (status, i18n key, params)


def _a8_15(d: dict, c) -> Result:
    v, lv = d.get("volume") or {}, d.get("liveness") or {}
    if not v.get("total"):
        return "no_data", "au.c.no_volume", {}
    outages = [e for e in lv.get("events") or []]
    mins = int(lv.get("minutes") or 0)
    if outages and (mins > c.max_outage_minutes or any(e.get("end") is None for e in outages)):
        return "gap", "au.c.log_gap", {"k": len(outages), "m": mins}
    return "evidence", "au.c.log_ok", {"n": f"{v['total']:,}", "m": c.max_outage_minutes}


def _a8_16(d: dict, c) -> Result:
    r = d.get("runs") or {}
    days = int(d.get("days_in_month") or 30)
    try:                                  # the current month counts only the days that have passed
        from datetime import datetime
        frm = datetime.fromisoformat(str(d["from"]).replace("Z", "+00:00"))
        end = min(datetime.fromisoformat(str(d["to"]).replace("Z", "+00:00")),
                  datetime.fromisoformat(str(d["generated_at"]).replace("Z", "+00:00")))
        days = max(1, min(days, -(-int((end - frm).total_seconds()) // 86400)))
    except (KeyError, ValueError, TypeError):
        pass
    need = int(days * c.min_run_ratio)
    done, err = int(r.get("done") or 0), int(r.get("error") or 0)
    if not r.get("count"):
        return "no_data", "au.c.no_runs", {}
    if done >= need:
        return "evidence", "au.c.mon_ok", {"done": done, "days": days, "e": err}
    return "gap", "au.c.mon_gap", {"done": done, "days": days, "need": need, "e": err}


def _a5_25(d: dict, c) -> Result:
    notable = (d.get("findings") or {}).get("notable") or []
    if not notable:
        return "no_data", "au.c.dec_none", {}
    open_ = [x for x in notable if x.get("user_status", "new") == "new"]
    if open_:
        return "gap", "au.c.dec_gap", {"u": len(open_), "n": len(notable)}
    return "evidence", "au.c.dec_ok", {"n": len(notable)}


def _a5_26(d: dict, c) -> Result:
    inc = [x for x in (d.get("findings") or {}).get("notable") or [] if x.get("label") == "real_incident"]
    if not inc:
        return "no_data", "au.c.inc_none", {}
    bare = [x for x in inc if x.get("user_status", "new") == "new" and not x.get("note")]
    if bare:
        return "gap", "au.c.inc_gap", {"u": len(bare), "n": len(inc)}
    return "evidence", "au.c.inc_ok", {"n": len(inc)}


def _a5_27(d: dict, c) -> Result:
    k = d.get("knowledge") or {}
    n = len(k.get("decision") or []) + len(k.get("lesson") or [])
    return ("evidence", "au.c.learn_ok", {"n": n}) if n else ("no_data", "au.c.learn_none", {})


def _a5_28(d: dict, c) -> Result:
    return ("evidence", "au.c.hash", {"h": d["sha256"][:16]}) if d.get("sha256") else ("no_data", "au.c.no_rule", {})


def _a8_8(d: dict, c) -> Result:
    vu = d.get("vulnerabilities") or {}
    sla = {k: s for k, s in (vu.get("sla") or {}).items() if isinstance(s, dict)}
    if not sla:
        return "no_data", "au.c.vuln_none", {}
    over = {k: s.get("overdue") for k, s in sla.items() if s.get("overdue")}
    if over:
        return "gap", "au.c.vuln_gap", {"s": ", ".join(f"{k} {n}" for k, n in over.items())}
    return "evidence", "au.c.vuln_ok", {"n": sum((vu.get("severity") or {}).values())}


def _a8_9(d: dict, c) -> Result:
    return "no_data", "au.c.sca_none", {}


def _a8_32(d: dict, c) -> Result:
    ch = d.get("rule_changes") or []
    if not ch:
        return "no_data", "au.c.chg_none", {}
    anon = [x for x in ch if not x.get("by") and x.get("action") != "reject"]
    if anon:
        return "gap", "au.c.chg_gap", {"u": len(anon), "n": len(ch)}
    return "evidence", "au.c.chg_ok", {"n": len(ch)}


def _a5_9(d: dict, c) -> Result:
    inv = (d.get("coverage") or {}).get("inventory")
    if not inv:
        return "no_data", "au.c.inv_none", {}
    if inv.get("missing"):
        return "gap", "au.c.inv_gap", {"a": ", ".join(inv["missing"][:10])}
    return "evidence", "au.c.inv_ok", {}


RULES: dict[str, Callable[[dict, Any], Result]] = {
    "A.5.9": _a5_9, "A.5.25": _a5_25, "A.5.26": _a5_26, "A.5.27": _a5_27, "A.5.28": _a5_28,
    "A.8.8": _a8_8, "A.8.9": _a8_9, "A.8.15": _a8_15, "A.8.16": _a8_16, "A.8.32": _a8_32,
}


def digest(d: dict) -> str:
    """SHA-256 over the canonical report (without the digest and the controls computed from it)."""
    body = {k: v for k, v in d.items() if k not in ("sha256", "controls", "section_controls")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def evaluate(d: dict, cfg) -> list[dict]:
    out = []
    for cid in CATALOG:
        sections = [s for s, ids in SECTION_MAP.items() if cid in ids]
        ref = (cfg.isms_refs or {}).get(cid, "")
        if cid in (cfg.exclude or {}):
            out.append({"id": cid, "title": CATALOG[cid], "status": "excluded", "key": "au.c.excluded_reason",
                        "params": {"r": cfg.exclude[cid]}, "sections": sections, "ref": ref})
            continue
        try:
            st, key, params = RULES[cid](d, cfg)
        except Exception:  # noqa: BLE001 - one odd field must not break the report
            st, key, params = "no_data", "au.c.no_rule", {}
        out.append({"id": cid, "title": CATALOG[cid], "status": st, "key": key, "params": params,
                    "sections": sections, "ref": ref})
    return out


def section_controls(controls: list[dict]) -> dict[str, list[str]]:
    shown = {c["id"] for c in controls if c["status"] != "excluded"}
    return {s: [c for c in ids if c in shown] for s, ids in SECTION_MAP.items()}


def counts(controls: list[dict]) -> dict[str, int]:
    return {s: sum(1 for c in controls if c["status"] == s) for s in ("evidence", "gap", "no_data", "excluded")}
