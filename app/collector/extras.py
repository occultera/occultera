# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Optional collector sections: anomalies, mail pressure, personal data found in alerts."""
from __future__ import annotations

import asyncio
from datetime import timedelta

from ..wazuh.schema import S
from .util import _b, iso, rng


class ExtrasMixin:
    """Optional sections: anomalies, mail pressure, personal data in the alerts."""

    async def _anomalies(self, frm, to, days: int = 14) -> dict:
        """rule × agent counts in the window vs. the daily mean / spread of the previous `days` days."""
        hours = max(1.0, (to - frm).total_seconds() / 3600)
        b_from = frm - timedelta(days=days)
        pair = {"r": {"terms": {"field": S.RULE_ID, "size": 150},
                      "aggs": {"a": {"terms": {"field": S.AGENT_NAME, "size": 40}},
                               "d": {"terms": {"field": S.RULE_DESC, "size": 1}},
                               "l": {"max": {"field": S.RULE_LEVEL}}}}}
        cur, base = await asyncio.gather(
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(frm, to), "aggs": pair}),
            self.ix.search(self.env.alerts_index, {"size": 0, "query": rng(b_from, frm), "aggs": {
                "r": {"terms": {"field": S.RULE_ID, "size": 400},
                      "aggs": {"a": {"terms": {"field": S.AGENT_NAME, "size": 60},
                                     "aggs": {"day": {"date_histogram": {
                                         "field": S.TS, "fixed_interval": "1d", "min_doc_count": 0,
                                         "extended_bounds": {"min": iso(b_from), "max": iso(frm - timedelta(seconds=1))}}}}}}}}}))
        hist: dict[tuple, list[int]] = {}
        for rb in _b(base["aggregations"]["r"]):
            for ab in _b(rb["a"]):
                days_ = [d["doc_count"] for d in _b(ab["day"])]
                hist[(rb["key"], ab["key"])] = days_[1:-1] if len(days_) > 3 else days_   # edges are partial days
        spikes, new_pairs = [], []
        for rb in _b(cur["aggregations"]["r"]):
            lvl = int(rb["l"]["value"] or 0)
            desc = (_b(rb["d"]) or [{"key": ""}])[0]["key"]
            for ab in _b(rb["a"]):
                n = ab["doc_count"]
                per_day = n * 24 / hours
                h = hist.get((rb["key"], ab["key"]))
                if not h or not any(h):
                    if n >= 5 or lvl >= self.env.high_level:
                        new_pairs.append({"rule": rb["key"], "agent": ab["key"], "count": n, "level": lvl, "desc": desc})
                    continue
                vals = h or [0]
                mean = sum(vals) / len(vals)
                sd = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
                z = (per_day - mean) / max(sd, 1.0, mean * 0.1)
                if z >= 3 and n >= 20:
                    spikes.append({"rule": rb["key"], "agent": ab["key"], "count": n, "per_day": round(per_day),
                                   "baseline_per_day": round(mean, 1), "z": round(z, 1), "level": lvl, "desc": desc})
        spikes.sort(key=lambda x: (-x["z"]))
        new_pairs.sort(key=lambda x: (-x["level"], -x["count"]))
        return {"baseline_days": days, "spikes": spikes[:25], "new_pairs": new_pairs[:25]}

    # ------------------------------------------------------------------ e-mail channel saturation

    async def _mail_pressure(self, frm, to) -> dict:
        m = self.env.mail
        r = await self.ix.search(self.env.alerts_index, {
            "size": 0,
            "query": {"bool": {"filter": [rng(frm, to), S.level_gte(m.alert_level)]}},
            "aggs": {"h": {"date_histogram": {"field": S.TS, "fixed_interval": "1h", "min_doc_count": 1},
                           "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": 10},
                                          "aggs": {"d": {"terms": {"field": S.RULE_DESC, "size": 1}},
                                                   "l": {"max": {"field": S.RULE_LEVEL}},
                                                   "a": {"terms": {"field": S.AGENT_NAME, "size": 3}}}}}}}})
        hours, buried = [], {}
        for b in _b(r["aggregations"]["h"]):
            if b["doc_count"] <= m.max_per_hour:
                continue
            rules = []
            for x in _b(b["r"]):
                d = _b(x["d"])
                rules.append({"id": x["key"], "n": x["doc_count"], "level": int(x["l"]["value"] or 0),
                              "desc": d[0]["key"] if d else "", "agents": [a["key"] for a in _b(x["a"])]})
            hours.append({"t": b["key_as_string"], "n": b["doc_count"], "over": b["doc_count"] - m.max_per_hour,
                          "flood": rules[:1]})
            # everything except the dominant rule competed for the same few mails
            for x in rules[1:]:
                k = buried.setdefault(x["id"], {**x, "n": 0, "hours": 0})
                k["n"] += x["n"]
                k["hours"] += 1
        return {"alert_level": m.alert_level, "max_per_hour": m.max_per_hour,
                "saturated_hours": hours[-48:], "excess": sum(h["over"] for h in hours),
                "possibly_unmailed": sorted(buried.values(), key=lambda x: (-x["level"], -x["n"]))[:25]}

    # ------------------------------------------------------------------ personal data in logs (GDPR / KVKK)

    async def _personal_data(self, frm, to, sample: int) -> dict:
        """Scan the newest ``sample`` alerts of the window (plus a share of the high-level ones) for personal data
        stored in clear text. Only counts and fully masked examples leave this function."""
        from ..privacy import scan_alerts
        src = [S.FULL_LOG, S.DATA, S.RULE_ID, S.RULE_DESC, S.AGENT_NAME, S.LOCATION, S.DECODER]
        q = {"bool": {"filter": [rng(frm, to)]}}
        r = await self.ix.search(self.env.alerts_index, {"size": sample, "query": q, "_source": src,
                                                         "sort": [{S.TS: "desc"}]})
        hits = r["hits"]["hits"]
        # spread the sample over the window: the newest alerts alone are often one noisy source
        r2 = await self.ix.search(self.env.alerts_index, {
            "size": 0, "query": q,
            "aggs": {"loc": {"terms": {"field": S.LOCATION, "size": 40},
                             "aggs": {"s": {"top_hits": {"size": 5, "_source": src, "sort": [{S.TS: "desc"}]}}}}}})
        seen = {h.get("_id") for h in hits}
        for b in _b(r2["aggregations"]["loc"]):
            for h in b["s"]["hits"]["hits"]:
                if h.get("_id") not in seen:
                    seen.add(h.get("_id"))
                    hits.append(h)
        pv = self.env.privacy
        return scan_alerts(hits, set(pv.kinds) if pv.kinds else None, pv.allow)

    # ------------------------------------------------------------------ agent coverage
