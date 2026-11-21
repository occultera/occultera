# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Tools available to the AI — all READ-ONLY.

Nothing in Wazuh is ever changed. The only writes are adding a `proposed`
entry to this application's own knowledge base (no effect until a human
approves it) and submitting the report of a triage run.

Security note: alert contents (URLs, full_log, user names, user agents) are
attacker-controlled and may carry prompt injection. The tool set is kept
deliberately narrow: no active response, no configuration writes, no
outbound requests.
"""
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any, Literal

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from ..collector import _b, _parse, iso
from ..config import Environment
from ..errors import public_error
from ..query_guard import QueryError, check_interval, field, histogram_buckets, size, time_range
from ..rules import ip_element_issues
from ..sources import SourcePolicyError
from ..store import KNOWLEDGE_KINDS, Repo
from ..wazuh.api import WazuhAPI
from ..wazuh.indexer import Indexer
from ..wazuh.schema import S, bind
from .events import _compact_event, _filters, event_fields  # noqa: F401
from .sourcetools import SourceTools
from .specs import (  # noqa: F401 - re-exported for app.mcp, app.reporting, app.web.ui
    FILTER_PROPS,
    FINDING,
    LABELS,
    SEVERITIES,
    SPECS,
    TIME_PROPS,
    _obj,
)

MAX_RESULT_CHARS = 14000
log = logging.getLogger("wdt")

ToolMode = Literal["triage", "tools", "mcp"]


class ToolBox(SourceTools):
    def __init__(self, env: Environment, ix: Indexer, api: WazuhAPI | None, repo: Repo,
                 mode: ToolMode = "tools", run_id: str | None = None, sources: dict | None = None):
        self.env = env
        self.sources = sources or {}
        self.ix = ix
        self.api = api
        self.repo = repo
        self.mode = mode
        self.run_id = run_id
        self.limits = env.query
        self.submitted: dict | None = None
        self.rejected_submits = 0
        self.proposals: list[dict] = []
        self._handlers: dict[str, Callable[[dict], Awaitable[Any]]] = {
            "search_alerts": self.search_alerts,
            "aggregate_alerts": self.aggregate_alerts,
            "rule_timeline": self.rule_timeline,
            "ip_profile": self.ip_profile,
            "correlate_around": self.correlate_around,
            "vulnerabilities": self.vulnerabilities,
            "propose_knowledge": self.propose_knowledge,
            "validate_rule_xml": self.validate_rule_xml,
            "simulate_rule": self.simulate_rule,
        }
        if api:
            self._handlers.update({"agent_info": self.agent_info, "rule_info": self.rule_info,
                                   "logtest": self.logtest})
        if self.sources.get("prometheus"):
            self._handlers.update({"prom_query": self.prom_query, "prom_range": self.prom_range,
                                   "prom_alerts": self.prom_alerts})
        if self.sources.get("loki"):
            self._handlers.update({"loki_query": self.loki_query, "loki_labels": self.loki_labels})
        if self.sources.get("kubernetes"):
            self._handlers.update({"k8s_get": self.k8s_get})
            if self.env.sources.kubernetes.pod_logs:
                self._handlers["k8s_logs"] = self.k8s_logs
        if mode in ("tools", "mcp"):
            self._handlers.update({"list_reports": self.list_reports, "get_report": self.get_report,
                                   "knowledge": self.knowledge})
        if mode == "triage":
            self._handlers["submit_report"] = self.submit_report

    # ------------------------------------------------------------- schemas
    def specs(self) -> list[dict]:
        return [SPECS[n] for n in self._handlers if n in SPECS]

    async def call(self, name: str, args: dict) -> str:
        bind(self.env)
        h = self._handlers.get(name)
        if not h:
            return json.dumps({"error": f"unknown tool: {name}"})
        try:
            res = await h(args or {})
        except SourcePolicyError as e:
            res = {"error": str(e)}
        except QueryError as e:
            res = {"error": str(e), "hint": "narrow the window, use an allow-listed field or a coarser interval"}
        except Exception as e:  # noqa: BLE001
            # The model gets a category and a reference, never the exception text (URLs, index names, raw
            # responses); the operator finds the traceback in the log under the same reference.
            res, ref = public_error(e)
            log.warning("tool %s failed (env=%s, mode=%s, ref=%s): %s", name, self.env.id, self.mode, ref, e,
                        exc_info=True)
        txt = json.dumps(res, ensure_ascii=False, default=str)
        if len(txt) > MAX_RESULT_CHARS:
            txt = txt[:MAX_RESULT_CHARS] + f'… [truncated, {len(txt)} chars in total — narrow the filter]'
        return txt

    # ------------------------------------------------------------- tools
    def _span(self, a: dict) -> float:
        frm, to = time_range(a.get("from") or "now-24h", a.get("to") or "now",
                             int(getattr(self.limits, "max_range_hours", 24 * 14)))
        return max(0.01, (to - frm).total_seconds() / 3600)

    async def search_alerts(self, a):
        size_n = size(a.get("size", 10), min(25, int(getattr(self.limits, "max_size", 25))), "size")
        r = await self.ix.search(self.env.alerts_index, {
            "size": size_n, "sort": [{S.TS: "asc" if a.get("oldest_first") else "desc"}],
            "query": {"bool": {"filter": _filters(a, self.limits)}}, "_source": event_fields()})
        return {"total": r["hits"]["total"]["value"],
                "events": [_compact_event(h["_source"]) for h in r["hits"]["hits"]]}

    async def aggregate_alerts(self, a):
        extra = getattr(self.limits, "extra_fields", None)
        fld = field(a["field"], extra)
        sub = field(a["sub_field"], extra) if a.get("sub_field") else None
        size_n = size(a.get("size", 20), int(getattr(self.limits, "max_terms_size", 50)), "size")
        agg: dict = {"terms": {"field": fld, "size": size_n}}
        if sub:
            agg["aggs"] = {"sub": {"terms": {"field": sub, "size": 5}}}
        agg.setdefault("aggs", {})
        agg["aggs"]["first"] = {"min": {"field": S.TS}}
        agg["aggs"]["last"] = {"max": {"field": S.TS}}
        body = {"size": 0, "query": {"bool": {"filter": _filters(a, self.limits)}}, "aggs": {"x": agg}}
        histogram_buckets(body, self._span(a), self.limits)   # final check on the aggregation tree
        r = await self.ix.search(self.env.alerts_index, body)
        out = []
        for b in _b(r["aggregations"]["x"]):
            row = {"key": b["key"], "count": b["doc_count"], "first": b["first"].get("value_as_string"),
                   "last": b["last"].get("value_as_string")}
            if sub and "sub" in b:
                row[sub] = {s["key"]: s["doc_count"] for s in _b(b["sub"])}
            out.append(row)
        return {"total": r["hits"]["total"]["value"], "field": fld, "buckets": out,
                "other": r["aggregations"]["x"].get("sum_other_doc_count", 0)}

    async def rule_timeline(self, a):
        interval = check_interval(str(a.get("interval", "1h")), str(getattr(self.limits, "min_interval", "1m")),
                                  self._span(a), int(getattr(self.limits, "max_buckets", 200)))
        r = await self.ix.search(self.env.alerts_index, {"size": 0, "query": {"bool": {"filter": _filters(a, self.limits)}},
            "aggs": {"h": {"date_histogram": {"field": S.TS, "fixed_interval": interval, "min_doc_count": 1}}}})
        b = [{"t": x["key_as_string"], "n": x["doc_count"]} for x in _b(r["aggregations"]["h"])]
        return {"total": r["hits"]["total"]["value"], "interval": interval, "buckets": b[-200:],
                "note": "Non-empty buckets only. Look at the distribution, not the average: everything may sit in one short window."}

    async def ip_profile(self, a):
        ip = a["ip"].strip()
        q = {"prefix": {S.SRCIP: ip}} if ip.endswith((".", ":")) else {"term": {S.SRCIP: ip}}
        f = _filters({k: a.get(k) for k in ("from", "to")}, self.limits) + [q]
        iv = str(a.get("interval", "30m"))
        check_interval(iv, str(getattr(self.limits, "min_interval", "1m")), self._span(a),
                       int(getattr(self.limits, "max_buckets", 200)))
        r = await self.ix.search(self.env.alerts_index, {"size": 3, "sort": [{S.TS: "desc"}], "_source": event_fields(),
            "query": {"bool": {"filter": f}}, "aggs": {
                "rules": {"terms": {"field": S.RULE_ID, "size": 10}, "aggs": {"d": {"terms": {"field": S.RULE_DESC, "size": 1}}}},
                "codes": {"terms": {"field": S.EVENT_ID, "size": 10}},
                "urls": {"cardinality": {"field": S.URL}},
                "top_urls": {"terms": {"field": S.URL, "size": 10}},
                "agents": {"terms": {"field": S.AGENT_NAME, "size": 10}},
                "users": {"terms": {"field": S.SRCUSER, "size": 10}},
                "ips": {"terms": {"field": S.SRCIP, "size": 10}},
                "h": {"date_histogram": {"field": S.TS, "fixed_interval": iv, "min_doc_count": 1}},
            }})
        ag = r["aggregations"]
        return {
            "total": r["hits"]["total"]["value"],
            "rules": [{"id": b["key"], "n": b["doc_count"], "desc": (_b(b["d"]) or [{"key": ""}])[0]["key"]} for b in _b(ag["rules"])],
            "status_codes": {b["key"]: b["doc_count"] for b in _b(ag["codes"])},
            "distinct_urls": ag["urls"]["value"],
            "top_urls": {b["key"]: b["doc_count"] for b in _b(ag["top_urls"])},
            "agents": {b["key"]: b["doc_count"] for b in _b(ag["agents"])},
            "users": {b["key"]: b["doc_count"] for b in _b(ag["users"])},
            "ips": {b["key"]: b["doc_count"] for b in _b(ag["ips"])},
            "timeline": [{"t": b["key_as_string"], "n": b["doc_count"]} for b in _b(ag["h"])][-100:],
            "samples": [_compact_event(h["_source"]) for h in r["hits"]["hits"]],
            "note": "data.srcip is a keyword field; use a prefix (\"203.0.113.\") for ranges, not CIDR.",
        }

    async def correlate_around(self, a):
        ts = _parse(a["timestamp"])
        m = max(1, min(int(a.get("minutes", 30)), 360))
        f = [{"range": {S.TS: {"gte": iso(ts - timedelta(minutes=m)), "lte": iso(ts + timedelta(minutes=m))}}}]
        if a.get("agent"):
            f.append({"term": {S.AGENT_NAME: a["agent"]}})
        f.append(S.level_gte(int(a.get("min_level", 3))))
        r = await self.ix.search(self.env.alerts_index, {"size": 20, "sort": [{S.TS: "asc"}], "_source": event_fields(),
            "query": {"bool": {"filter": f}},
            "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": 25},
                           "aggs": {"d": {"terms": {"field": S.RULE_DESC, "size": 1}},
                                    "l": {"max": {"field": S.RULE_LEVEL}},
                                    "a": {"terms": {"field": S.AGENT_NAME, "size": 3}}}}}})
        return {"window": f"±{m} min", "total": r["hits"]["total"]["value"],
                "by_rule": [{"id": b["key"], "n": b["doc_count"], "level": int(b["l"]["value"] or 0),
                             "desc": (_b(b["d"]) or [{"key": ""}])[0]["key"],
                             "agents": [x["key"] for x in _b(b["a"])]} for b in _b(r["aggregations"]["r"])],
                "first_events": [_compact_event(h["_source"]) for h in r["hits"]["hits"]]}

    async def vulnerabilities(self, a):
        f = []
        if a.get("agent"):
            f.append({"term": {S.AGENT_NAME: a["agent"]}})
        if a.get("severity"):
            f.append({"term": {S.VULN_SEV: a["severity"]}})
        r = await self.ix.search(self.env.vuln_index, {"size": 0, "query": {"bool": {"filter": f}}, "aggs": {
            "sev": {"terms": {"field": S.VULN_SEV, "size": 10}},
            "cve": {"terms": {"field": S.VULN_ID, "size": int(min(a.get("size", 15), 40))},
                    "aggs": {"p": {"terms": {"field": S.PKG_NAME, "size": 3}},
                             "a": {"cardinality": {"field": S.AGENT_ID}}}},
            "pkg": {"terms": {"field": S.PKG_NAME, "size": 15}}}})
        ag = r["aggregations"]
        return {"total": r["hits"]["total"]["value"],
                "severity": {b["key"]: b["doc_count"] for b in _b(ag["sev"])},
                "top_cves": [{"cve": b["key"], "n": b["doc_count"], "agents": b["a"]["value"],
                              "packages": [p["key"] for p in _b(b["p"])]} for b in _b(ag["cve"])],
                "top_packages": {b["key"]: b["doc_count"] for b in _b(ag["pkg"])},
                "note": "The Critical count alone is not a risk measure: leftover kernel packages and feed false positives inflate it."}

    async def agent_info(self, a):
        q = str(a["agent"])
        items = await self.api.agents(search=q, limit=5)
        cnt = await self.ix.search(self.env.alerts_index, {"size": 0, "query": {"bool": {"filter": [
            {"range": {S.TS: {"gte": "now-24h"}}}, {"term": {S.AGENT_NAME: items[0]["name"]}}]}} if items else {"match_none": {}},
            "aggs": {"r": {"terms": {"field": S.RULE_ID, "size": 10}}}})
        return {"agents": items, "alerts_24h": cnt["hits"]["total"]["value"],
                "top_rules_24h": {b["key"]: b["doc_count"] for b in _b(cnt.get("aggregations", {}).get("r", {}))}}

    async def rule_info(self, a):
        ids = [str(x) for x in a["rule_ids"]][:20]
        items = await self.api.rules(ids)
        return [{"id": r.get("id"), "level": r.get("level"), "description": r.get("description"),
                 "filename": r.get("filename"), "relative_dirname": r.get("relative_dirname"),
                 "groups": r.get("groups"), "details": r.get("details")} for r in items]

    async def logtest(self, a):
        d = await self.api.logtest(a["event"], a.get("log_format", "syslog"), a.get("location", "daily-triage"))
        out = d.get("output", {})
        return {"rule": out.get("rule"), "decoder": out.get("decoder"), "data": out.get("data"),
                "alert": d.get("alert"), "messages": d.get("messages")}

    async def simulate_rule(self, a):
        from ..whatif import simulate
        return await simulate(self.env, self.ix, a["xml"], days=max(1, min(int(a.get("days") or 14), 30)),
                              sample=1000)

    def id_range(self) -> tuple[int, int]:
        c = self.env.rule_deploy
        return int(c.id_min), int(c.id_max)

    async def suggest_rule_id(self, avoid: set[int] | None = None) -> int | None:
        """First free rule ID in the environment's range: above existing drafts, not taken in Wazuh, not in `avoid`."""
        from ..noise import next_rule_id
        lo, hi = self.id_range()
        drafts: list[dict] = []
        if self.repo is not None:
            try:
                drafts = await self.repo.list_knowledge(kinds=["rule_draft"], size=1000)
            except Exception:                       # noqa: BLE001 - a hint only, never fail the tool
                drafts = []
        start = next_rule_id(drafts, self.env.rule_deploy)
        cands = [i for i in range(start, min(start + 50, hi + 1)) if i not in (avoid or set())]
        if not cands:
            return None
        if self.api:
            try:
                taken = {int(r["id"]) for r in await self.api.rules([str(i) for i in cands])}
                cands = [i for i in cands if i not in taken]
            except Exception:                       # noqa: BLE001
                pass
        return cands[0] if cands and lo <= cands[0] <= hi else None

    def _range_errors(self, ids: list[str | None]) -> list[str]:
        lo, hi = self.id_range()
        out = []
        for i in ids:
            if not i or not str(i).isdigit():
                out.append(f"rule without numeric id: {i!r}")
            elif not lo <= int(i) <= hi:
                out.append(f"rule {i}: id outside the allowed range {lo}-{hi}")
        return out

    async def validate_rule_xml(self, a):
        xml = a["xml"]
        res: dict[str, Any] = {}
        try:
            root = SafeET.fromstring(f"<root>{xml}</root>")   # no DTD / entity expansion
            ids = [r.get("id") for r in root.iter("rule")]
            res["xml_ok"] = True
            res["rule_ids"] = ids
            levels = {r.get("id"): r.get("level") for r in root.iter("rule")}
            res["levels"] = levels
            issues = []
            for r in root.iter("rule"):
                for fld in r.iter("field"):
                    t = fld.get("type", "osregex")
                    if t == "osregex" and "(" in (fld.text or "") and "|" in (fld.text or ""):
                        issues.append(f"rule {r.get('id')}: <field> OS_Regex does not support grouped alternation — use type=\"pcre2\"")
                for tag in ("srcip", "dstip"):
                    for el in r.iter(tag):
                        issues.extend(f"rule {r.get('id')}: {m}" for m in ip_element_issues(tag, el))
                for tag in ("id", "match", "regex"):
                    for el in r.iter(tag):
                        if el.get("type") in (None, "osregex") and "(" in (el.text or "") and "|" in (el.text or ""):
                            issues.append(f"rule {r.get('id')}: <{tag}> OS_Regex does not support grouping; write ^400$|^408$ or use pcre2")
            res["warnings"] = issues
        except DefusedXmlException:
            return {"xml_ok": False, "error": "DTDs and entities are not allowed"}
        except ET.ParseError as e:
            return {"xml_ok": False, "error": str(e)}
        if self.api and res.get("rule_ids"):
            existing = await self.api.rules([i for i in res["rule_ids"] if i])
            res["id_collisions"] = [{"id": r["id"], "file": r.get("filename"), "description": r.get("description")}
                                    for r in existing]
        lo, hi = self.id_range()
        res["allowed_id_range"] = f"{lo}-{hi}"
        res["id_errors"] = self._range_errors(res.get("rule_ids") or [])
        if res["id_errors"]:
            sid = await self.suggest_rule_id()
            res["suggested_id"] = sid
            res["fix"] = (f"Renumber the new rule(s) into {lo}-{hi}"
                          + (f", starting at {sid}" if sid else "")
                          + ". Parent IDs in <if_sid>/<if_matched_sid> stay as they are. Deployment refuses IDs outside the range.")
        res["note"] = ("Syntax/ID check only. Propose it with propose_knowledge(kind=rule_draft, xml=..., tests=...); "
                       "the user approves and deploys it (validated, restarted, rolled back on failure) or runs the commands.")
        return res

    async def propose_knowledge(self, a):
        kind = a["kind"]
        if kind not in KNOWLEDGE_KINDS or kind in ("answer",):
            return {"error": f"invalid kind; one of: {', '.join(k for k in KNOWLEDGE_KINDS if k != 'answer')}"}
        if len(self.proposals) >= 10:
            return {"error": "at most 10 proposals per run"}
        extra = {}
        if kind == "rule_draft":
            if a.get("xml"):
                extra["xml"] = str(a["xml"])[:20000]
                try:
                    ids = [r.get("id") for r in SafeET.fromstring(f"<root>{extra['xml']}</root>").iter("rule")]
                except (DefusedXmlException, ET.ParseError):
                    ids = []
                bad = self._range_errors(ids)
                if bad:
                    lo, hi = self.id_range()
                    sid = await self.suggest_rule_id()
                    return {"error": "rule draft refused: " + "; ".join(bad),
                            "allowed_id_range": f"{lo}-{hi}", "suggested_id": sid,
                            "fix": f"Renumber the new rule(s) into {lo}-{hi}"
                                   + (f" (e.g. {sid})" if sid else "")
                                   + ", keep parent IDs in <if_sid> unchanged, check with validate_rule_xml and "
                                     "call propose_knowledge again."}
            tests = [t for t in (a.get("tests") or []) if isinstance(t, dict) and t.get("event")][:6]
            if tests:
                extra["tests"] = [{"event": str(t["event"])[:4000], "log_format": str(t.get("log_format") or "syslog"),
                                   "location": str(t.get("location") or "daily-triage"),
                                   "expect": "no_match" if t.get("expect") == "no_match" else "match"} for t in tests]
        doc = await self.repo.add_knowledge(kind, a["title"], a.get("body", ""), status="proposed",
                                            created_by="ai", rule_ids=a.get("rule_ids"), source_run=self.run_id,
                                            extra=extra or None)
        self.proposals.append(doc)
        return {"ok": True, "id": doc["id"], "status": "proposed",
                "note": "No effect until the user approves it in the UI."}

    # ------------------------------------------------------------- extra sources (read-only)
    async def list_reports(self, a):
        runs = await self.repo.list_runs(int(min(a.get("size", 10), 30)))
        return [{"run_id": r["run_id"], "started_at": r.get("started_at"), "status": r.get("status"),
                 "health": r.get("health"), "window": r.get("window"), "metrics": r.get("metrics"),
                 "headline": (r.get("summary_md") or "")[:200],
                 **({"error": str(r.get("error") or r.get("ai_error"))[:300]} if r.get("error") or r.get("ai_error") else {}),
                 "model": (r.get("agent") or {}).get("model"),
                 "steps": (r.get("agent") or {}).get("steps")} for r in runs]

    async def get_report(self, a):
        if a.get("run_id"):
            r = await self.repo.get_run(a["run_id"])
        else:
            r = await self.repo.last_success()
        if not r:
            return {"error": "report not found"}
        return {k: r.get(k) for k in ("run_id", "started_at", "status", "window", "health", "metrics", "summary_md",
                                       "findings", "questions", "flags", "error", "ai_error")}

    async def knowledge(self, a):
        rows = await self.repo.list_knowledge(kinds=a.get("kinds"), status=a.get("status") or ["active", "proposed"])
        return [{"id": r["id"], "kind": r["kind"], "status": r["status"], "title": r["title"],
                 "body": r["body"][:600], "rule_ids": r.get("rule_ids")} for r in rows]

    async def submit_report(self, a):
        """Accept only a usable report; otherwise tell the model what to fix so it can resubmit."""
        if "_raw" in a:
            self.rejected_submits += 1
            return {"error": "The report arguments were not valid JSON (probably cut off by the output limit). "
                             "Submit again, shorter: at most 8 findings, `detail` under 600 characters, "
                             "omit `evidence` lists longer than 5 items."}
        if not str(a.get("summary_md") or "").strip() or not isinstance(a.get("findings", []), list):
            self.rejected_submits += 1
            return {"error": "`summary_md` (non-empty) and `findings` (array) are required. Submit again."}
        self.submitted = a
        return {"ok": True}
