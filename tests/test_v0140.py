# SPDX-License-Identifier: AGPL-3.0-only
"""0.14: the clusters' own Prometheus alerts — grouping, pulse panel, AI explanation, watch trigger, tool, run."""
import os
from datetime import UTC, datetime, timedelta

import httpx

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

from app import clusteralerts as CA  # noqa: E402
from app import watch as W  # noqa: E402
from app.config import SourceEndpoint, load_settings  # noqa: E402
from app.demo import FakeIndexer  # noqa: E402
from app.settingsdoc import WatchSettings  # noqa: E402
from app.sources import Prometheus  # noqa: E402

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def _al(name, sev, ns="", since="2026-11-16T11:30:00Z", **lab):
    return {"labels": {"alertname": name, "severity": sev, **({"namespace": ns} if ns else {}), **lab},
            "annotations": {"summary": f"{name} summary"}, "active_at": since}


class AlertProm:
    def __init__(self, alerts=None, fail=False):
        self._a, self.fail = alerts or [], fail

    async def alerts(self):
        if self.fail:
            raise RuntimeError("down")
        return self._a


def test_group_and_counts():
    g = CA.group([_al("Watchdog", "none"), _al("KubePodCrashLooping", "warning", "erp", pod="a-1"),
                  _al("KubePodCrashLooping", "warning", "shop", pod="b-1", since="2026-11-16T09:00:00Z"),
                  _al("KubePersistentVolumeFillingUp", "critical", "data", persistentvolumeclaim="d"),
                  _al("KubeCPUOvercommit", "warning")])
    assert [x["name"] for x in g] == ["KubePersistentVolumeFillingUp", "KubePodCrashLooping", "KubeCPUOvercommit"]
    crash = g[1]
    assert crash["count"] == 2 and crash["namespaces"] == ["erp", "shop"] and crash["targets"] == ["pod=a-1", "pod=b-1"]
    assert crash["since"].startswith("2026-11-16T09:00")
    assert CA.counts(g) == {"critical": 1, "warning": 3, "other": 0}
    assert set(CA.for_ai(g)[0]) <= {"name", "severity", "count", "namespaces", "targets", "since", "summary",
                                    "description"}


async def test_prometheus_alerts_api_and_fallback():
    def api(req: httpx.Request):
        if req.url.path == "/api/v1/alerts":
            return httpx.Response(200, json={"status": "success", "data": {"alerts": [
                {"labels": {"alertname": "TargetDown", "severity": "warning"}, "annotations": {"summary": "s"},
                 "state": "firing", "activeAt": "2026-11-16T10:00:00Z"},
                {"labels": {"alertname": "X"}, "state": "pending"}]}})
        return httpx.Response(404)
    p = Prometheus(SourceEndpoint(url="http://p"), transport=httpx.MockTransport(api))
    a = await p.alerts()
    assert len(a) == 1 and a[0]["annotations"]["summary"] == "s" and a[0]["active_at"].startswith("2026-11-16T10")

    def old(req: httpx.Request):
        if req.url.path == "/api/v1/alerts":
            return httpx.Response(404, text="not found")
        q = req.url.params.get("query")
        m = {"alertname": "TargetDown", "severity": "warning", "namespace": "erp"}
        if q.startswith("ALERTS{"):
            return httpx.Response(200, json={"data": {"result": [{"metric": {"__name__": "ALERTS", "alertstate": "firing",
                                                                             **m}, "value": [0, "1"]}]}})
        return httpx.Response(200, json={"data": {"result": [{"metric": {"__name__": "ALERTS_FOR_STATE", **m},
                                                              "value": [0, "1794830400"]}]}})
    p = Prometheus(SourceEndpoint(url="http://p"), transport=httpx.MockTransport(old))
    a = await p.alerts()
    assert len(a) == 1 and a[0]["annotations"] == {}
    assert a[0]["labels"] == {"alertname": "TargetDown", "severity": "warning", "namespace": "erp"}
    assert a[0]["active_at"].startswith("2026-11-16")


def _scanner(clusters, **cfg):
    env = load_settings(os.path.join(ROOT, "config/demo.yaml")).environments[0]
    cfg = {"enabled": True, "triggers": {"prom_alerts": True}, **cfg}
    return W.Scanner(env, FakeIndexer(alerts=[]), None, WatchSettings(**cfg), "en", clusters=clusters)


async def test_watch_prom_alerts():
    fresh = _al("KubePersistentVolumeFillingUp", "critical", "data", since=(NOW - timedelta(minutes=20)).isoformat())
    old = _al("etcdMembersDown", "critical", "openshift-etcd", since=(NOW - timedelta(hours=5)).isoformat())
    warn = _al("TargetDown", "warning", "erp", since=(NOW - timedelta(minutes=5)).isoformat())
    sc = _scanner({"approd": AlertProm([fresh, old, warn]), "sftest": AlertProm(fail=True)})
    evs = await sc.prom_alerts(NOW)
    assert [e["key"] for e in evs] == ["promalert:approd:KubePersistentVolumeFillingUp:critical",
                                       "promalert:approd:etcdMembersDown:critical"]
    assert evs[0]["severity"] == "critical" and not evs[0].get("still_firing") and evs[1]["still_firing"] is True
    assert evs[0]["title"].startswith("[approd] KubePersistentVolumeFillingUp (critical) ×1 — data")
    assert sc.errors and sc.errors[0].startswith("prom_alerts[sftest]")
    sc = _scanner({"approd": AlertProm([fresh, old, warn])}, prom_alert_severities="critical, warning")
    assert len(await sc.prom_alerts(NOW)) == 3
    assert await _scanner({"approd": AlertProm([fresh])}, triggers={}).prom_alerts(NOW) == []
    w = WatchSettings()
    assert w.triggers["prom_alerts"] is False and w.prom_alert_severities == ["critical"]
    line = W.event_line(evs[0], "tr")
    assert "Küme alarmı" in line


async def test_tool_prom_alerts():
    from app.agent.tools import ToolBox
    from app.services import Clusters
    env = load_settings(os.path.join(ROOT, "config/demo.yaml")).environments[0]
    a = AlertProm([_al("TargetDown", "warning", "erp")])
    tb = ToolBox(env, FakeIndexer(alerts=[]), None, None,
                 sources={"prometheus": a, "clusters": Clusters(sfkube=a, approd=AlertProm(fail=True))})
    r = await tb.prom_alerts({})
    assert r["sfkube"]["counts"]["warning"] == 1 and r["sfkube"]["alerts"][0]["name"] == "TargetDown"
    assert "error" in r["approd"]
    assert list(await tb.prom_alerts({"cluster": "sfkube"})) == ["sfkube"]
    assert "prom_alerts" in str(tb.specs())


def test_pulse_alerts_panel_and_explain_demo():
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        c.post("/login", data={"password": "pw"})
        c.post("/lang", data={"lang": "en"})
        r = c.get("/e/demo/pulse")
        assert r.status_code == 200 and "Firing alerts" in r.text and "KubePersistentVolumeFillingUp" in r.text
        assert "data-explain=" in r.text and "Watchdog" not in r.text
        r = c.post("/api/e/demo/pulse/explain")
        assert r.status_code == 200 and "KubePodCrashLooping" in r.json()["html"] and r.json()["ai"] is False
    with TestClient(app) as v:
        v.post("/login", data={"password": "vwpw"})
        assert v.post("/api/e/demo/pulse/explain").status_code == 403       # the viewer cannot spend AI calls
        assert "data-explain=" not in v.get("/e/demo/pulse").text


async def test_explain_with_a_model(monkeypatch):
    from app import pulse_ai
    from app.services import Clusters

    class Res:
        text = "## Disk\\nThe Kafka volume is filling up."

    class RT:
        class _E:
            env = load_settings(os.path.join(ROOT, "config/demo.yaml")).environments[0]
            ix = api = repo = None
            sources = {"prometheus": AlertProm([_al("KubePersistentVolumeFillingUp", "critical", "data")]),
                       "clusters": None}

        def get(self, env_id):
            return self._E

        def llm_cfg(self, env):
            class C:
                provider, max_tool_steps = "openai", 8
            return C

        def llm_for(self, env):
            return object()

    RT._E.sources["clusters"] = Clusters(approd=RT._E.sources["prometheus"])
    seen = {}

    async def fake_agent(llm, sysmsg, msgs, tb, steps):
        seen.update(sys=sysmsg, usr=msgs[0]["content"], tools=sorted(tb._handlers))
        return Res
    import app.agent.runner as runner
    monkeypatch.setattr(runner, "run_agent", fake_agent)
    out = await pulse_ai.explain(RT(), "demo", "approd", "tr")
    assert out["ai"] is True and "Kafka" in out["md"] and out["counts"]["critical"] == 1
    assert 'cluster="approd"' in seen["sys"] and "Turkish" in seen["sys"] and "KubePersistentVolumeFillingUp" in seen["usr"]
    assert seen["tools"] == ["prom_alerts", "prom_query", "prom_range"]
    assert pulse_ai.cached("demo", "approd")["md"] == out["md"]
