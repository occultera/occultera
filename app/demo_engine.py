# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""A tiny OpenSearch query engine over in-memory documents: what the demo and the tests use instead of an indexer.

Supports the query and aggregation shapes Occultera sends (bool/term/terms/range/exists/query_string, terms,
date_histogram, min/max, filter, top_hits, cardinality …) and date math such as ``now-24h``.
"""
from __future__ import annotations

import fnmatch
import re
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

from .collector import _parse


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _get(doc: Any, path: str):
    cur = doc
    for p in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _vals(doc, path) -> list:
    v = _get(doc, path)
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


_DM = re.compile(r"^now(?:([+-])(\d+)([smhdw]))?(?:/[dh])?$")


def _date(v) -> datetime:
    if isinstance(v, datetime):
        return v
    m = _DM.match(str(v))
    if m:
        dt = datetime.now(UTC)
        if m.group(1):
            n = int(m.group(2))
            delta = {"s": timedelta(seconds=n), "m": timedelta(minutes=n), "h": timedelta(hours=n),
                     "d": timedelta(days=n), "w": timedelta(weeks=n)}[m.group(3)]
            dt = dt + delta if m.group(1) == "+" else dt - delta
        return dt
    return _parse(str(v))


def _cmp_val(field, v):
    if field == "timestamp" or field.endswith("_at") or field == "ts":
        return _date(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return str(v)


def _match(doc, q: dict) -> bool:
    if not q:
        return True
    (kind, body), = q.items()
    if kind == "match_all":
        return True
    if kind == "match_none":
        return False
    if kind == "bool":
        for c in body.get("filter", []) + body.get("must", []):
            if not _match(doc, c):
                return False
        for c in body.get("must_not", []):
            if _match(doc, c):
                return False
        sh = body.get("should", [])
        if sh and not any(_match(doc, c) for c in sh):
            return False
        return True
    if kind == "range":
        (field, cond), = body.items()
        vals = _vals(doc, field)
        if not vals:
            return False
        x = _cmp_val(field, vals[0])
        for op, lim in cond.items():
            if op in ("format", "time_zone"):
                continue
            y = _cmp_val(field, lim)
            if op == "gte" and not x >= y or op == "gt" and not x > y or op == "lte" and not x <= y \
                    or op == "lt" and not x < y:
                return False
        return True
    if kind == "term":
        (field, val), = body.items()
        if isinstance(val, dict):
            val = val.get("value")
        return str(val) in [str(x) for x in _vals(doc, field)]
    if kind == "terms":
        (field, vals), = body.items()
        have = {str(x) for x in _vals(doc, field)}
        return bool(have & {str(v) for v in vals})
    if kind == "prefix":
        (field, val), = body.items()
        if isinstance(val, dict):
            val = val.get("value")
        return any(str(x).startswith(str(val)) for x in _vals(doc, field))
    if kind == "exists":
        return bool(_vals(doc, body["field"]))
    if kind == "query_string":
        return _qs(doc, body["query"])
    if kind == "function_score":    # random sampling: the order does not matter for the demo
        return _match(doc, body.get("query") or {})
    raise ValueError(f"demo engine does not support: {kind}")


def _qs(doc, s: str) -> bool:
    """Simple query_string: `a:b AND c:d OR e:f`, NOT, wildcards (*), free text."""
    ors = re.split(r"\s+OR\s+", s.strip())
    for part in ors:
        ok = True
        for tok in re.split(r"\s+AND\s+", part):
            neg = tok.startswith("NOT ")
            tok = tok[4:] if neg else tok
            tok = tok.strip().strip("()")
            if ":" in tok and not tok.startswith("http"):
                f, v = tok.split(":", 1)
                v = v.strip('"')
                hit = any(fnmatch.fnmatch(str(x), v) for x in _vals(doc, f))
            else:
                hit = tok.strip('"').lower() in str(doc.get("full_log", "")).lower()
            if hit == neg:
                ok = False
                break
        if ok:
            return True
    return False


_IV = {"m": 60, "h": 3600, "d": 86400}


def _interval(s: str) -> int:
    return int(s[:-1]) * _IV[s[-1]]


def _agg(docs: list[dict], spec: dict) -> dict:
    sub = spec.get("aggs") or spec.get("aggregations") or {}
    if "terms" in spec:
        t = spec["terms"]
        counts: dict[Any, list] = {}
        for d in docs:
            for v in _vals(d, t["field"]):
                counts.setdefault(v, []).append(d)
        items = list(counts.items())
        order = t.get("order", {"_count": "desc"})
        if "_key" in order:
            items.sort(key=lambda kv: kv[0], reverse=order["_key"] == "desc")
        else:
            items.sort(key=lambda kv: (-len(kv[1]), str(kv[0])))
        size = t.get("size", 10)
        out = []
        for k, ds in items[:size]:
            b = {"key": k, "doc_count": len(ds)}
            for n, s in sub.items():
                b[n] = _agg(ds, s)
            out.append(b)
        return {"buckets": out, "sum_other_doc_count": sum(len(ds) for _, ds in items[size:])}
    if "date_histogram" in spec:
        h = spec["date_histogram"]
        iv = _interval(h.get("fixed_interval") or h.get("interval", "1h"))
        bk: dict[int, list] = {}
        for d in docs:
            ts = int(_date(_get(d, h["field"])).timestamp())
            bk.setdefault(ts - ts % iv, []).append(d)
        keys = set(bk)
        if h.get("extended_bounds") and h.get("min_doc_count", 1) == 0:
            lo = int(_date(h["extended_bounds"]["min"]).timestamp())
            hi = int(_date(h["extended_bounds"]["max"]).timestamp())
            k = lo - lo % iv
            while k <= hi:
                keys.add(k)
                k += iv
        out = []
        for k in sorted(keys):
            ds = bk.get(k, [])
            if len(ds) < h.get("min_doc_count", 1):
                continue
            b = {"key": k * 1000, "key_as_string": _iso(datetime.fromtimestamp(k, UTC)), "doc_count": len(ds)}
            for n, s in sub.items():
                b[n] = _agg(ds, s)
            out.append(b)
        return {"buckets": out}
    if "min" in spec or "max" in spec:
        op = "min" if "min" in spec else "max"
        f = spec[op]["field"]
        vals = [v for d in docs for v in _vals(d, f)]
        if not vals:
            return {"value": None}
        if f == "timestamp" or f.endswith("_at"):
            dts = [_date(v) for v in vals]
            dt = min(dts) if op == "min" else max(dts)
            return {"value": dt.timestamp() * 1000, "value_as_string": _iso(dt)}
        nums = [float(v) for v in vals]
        return {"value": min(nums) if op == "min" else max(nums)}
    if "cardinality" in spec:
        return {"value": len({str(v) for d in docs for v in _vals(d, spec["cardinality"]["field"])})}
    if "filter" in spec:
        ds = [d for d in docs if _match(d, spec["filter"])]
        b = {"doc_count": len(ds)}
        for n, s in sub.items():
            b[n] = _agg(ds, s)
        return b
    if "top_hits" in spec:
        th = spec["top_hits"]
        ds = _sort(docs, th.get("sort"))[: th.get("size", 3)]
        return {"hits": {"total": {"value": len(docs)}, "hits": [{"_source": _src(d, th.get("_source"))} for d in ds]}}
    raise ValueError(f"demo engine does not support agg: {list(spec)}")


def _sort(docs, sort):
    if not sort:
        return docs
    (field, o), = sort[0].items()
    desc = (o if isinstance(o, str) else o.get("order", "asc")) == "desc"
    return sorted(docs, key=lambda d: str(_get(d, field) or ""), reverse=desc)


def _src(d, fields):
    if not fields:
        return deepcopy(d)
    out: dict = {}
    for f in fields:
        v = _get(d, f)
        if v is None:
            continue
        cur = out
        parts = f.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = deepcopy(v)
    return out
