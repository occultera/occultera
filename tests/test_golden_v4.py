# SPDX-License-Identifier: AGPL-3.0-only
"""Golden outputs on Wazuh 4.x-shaped demo data at a fixed time.

The Wazuh adapter refactor (1.0) must not change what Occultera reports on 4.x. Every entry point that reads the
indexer runs once here against the same synthetic alerts; the result is compared with tests/data/golden_v4.json.
Regenerate deliberately with OCC_GOLDEN_UPDATE=1 when a change in output is intended.
"""
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app import dash, mitre
from app import watch as W
from app.agent.tools import ToolBox
from app.collector import Collector
from app.config import load_settings
from app.demo import FakeAPI, FakeIndexer, generate
from app.settingsdoc import WatchSettings
from app.store import MemoryStore, Repo

ROOT = Path(__file__).resolve().parent.parent
GOLD = ROOT / "tests" / "data" / "golden_v4.json"
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
F, T = (NOW - timedelta(hours=24)).isoformat(), NOW.isoformat()


def _norm(x):
    return json.loads(json.dumps(x, sort_keys=True, default=str))


async def _sweep() -> dict:
    env = load_settings(ROOT / "config" / "demo.yaml").environments[0]
    alerts = generate(now=NOW)
    out: dict = {}
    out["collector"] = await Collector(env, FakeIndexer(alerts=alerts), FakeAPI()).collect(NOW - timedelta(hours=24), NOW)
    for p in ("24h", "7d"):
        out[f"dash_{p}"] = await dash.overview(env, FakeIndexer(alerts=alerts), p, now=NOW, use_cache=False)
    out["mitre_matrix"] = await mitre.matrix(env, FakeIndexer(alerts=alerts), now=NOW)
    sc = W.Scanner(env, FakeIndexer(alerts=alerts), FakeAPI(), WatchSettings(enabled=True))
    ev, _ = await sc.scan(NOW - timedelta(hours=24), NOW, None)
    out["watch"] = [{k: v for k, v in e.items() if k not in ("id", "created_at")} for e in ev]
    tb = ToolBox(env, FakeIndexer(alerts=alerts), FakeAPI(), Repo(MemoryStore(), env.id), mode="tools")
    calls = {
        "search_alerts": {"from": F, "to": T, "min_level": 10, "size": 5},
        "search_alerts_q": {"from": F, "to": T, "query": "rule.groups:authentication_failed", "size": 3},
        "aggregate_alerts": {"from": F, "to": T, "field": "agent.name"},
        "aggregate_alerts_rule": {"from": F, "to": T, "field": "rule.id", "min_level": 7},
        "rule_timeline": {"rule_id": "5710", "from": F, "to": T, "interval": "1h"},
        "ip_profile": {"ip": "198.51.100.23", "from": F, "to": T},
        "vulnerabilities": {"severity": "Critical"},
    }
    for name, args in calls.items():
        tool = name.rsplit("_q", 1)[0] if name.endswith("_q") else name.replace("_rule", "")
        out["tool_" + name] = json.loads(await tb.call(tool, args))
    return _norm(out)


class _Frozen(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


async def test_golden_v4(monkeypatch):
    import app.demo as demo
    import app.demo_engine as engine
    monkeypatch.setattr(demo, "datetime", _Frozen)   # the synthetic agents and vulnerabilities are dated from "now"
    monkeypatch.setattr(engine, "datetime", _Frozen)  # and date math such as now-24h
    got = await _sweep()
    if os.environ.get("OCC_GOLDEN_UPDATE") or not GOLD.exists():
        GOLD.write_text(json.dumps(got, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    want = json.loads(GOLD.read_text(encoding="utf-8"))
    for k in want:
        assert got.get(k) == want[k], f"golden section {k!r} changed"
    assert set(got) == set(want)
