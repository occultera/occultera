# SPDX-License-Identifier: AGPL-3.0-only
"""The web tests start the app in demo mode; they expect an empty store, so the demo sample data is off."""
import os

os.environ.setdefault("WDT_DEMO_SEED", "false")


# ---- query recorder (refactor safety net) -----------------------------------------------------------
# OCC_RECORD=/path/file.jsonl writes every indexer query (index + body) per test, with timestamps blanked,
# so the queries before and after a refactor can be compared: tools/compare_queries.py.
_REC = os.environ.get("OCC_RECORD")
if _REC:
    import json
    import re

    import pytest

    from app.demo import FakeIndexer
    from app.wazuh.indexer import Indexer

    _TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?([+-]\d{2}:?\d{2}|Z)?|\d{4}\.\d{2}\.\d{2}")
    _cur = {"id": "-"}
    _out = open(_REC, "a", encoding="utf-8")  # noqa: SIM115

    def _log(kind, index, body):
        s = _TS.sub("<ts>", json.dumps(body, sort_keys=True, default=str))
        _out.write(json.dumps({"t": _cur["id"], "k": kind, "i": _TS.sub("<ts>", str(index)), "b": s}) + "\n")

    for _cls in (FakeIndexer, Indexer):
        _s, _c = _cls.search, _cls.count

        def _mk(orig, kind):
            async def w(self, index, body, *a, **kw):
                _log(kind, index, body)
                return await orig(self, index, body, *a, **kw)
            return w
        _cls.search, _cls.count = _mk(_s, "search"), _mk(_c, "count")

    @pytest.fixture(autouse=True)
    def _record_name(request):
        _cur["id"] = request.node.nodeid
        yield
        _out.flush()
