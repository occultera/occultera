# SPDX-License-Identifier: AGPL-3.0-only
"""0.12.2: the watch's outbound-transfer trigger (possible data leak) read from Prometheus."""
import os
from datetime import UTC, datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

from app import watch as W  # noqa: E402
from app.config import load_settings  # noqa: E402
from app.demo import FakeIndexer  # noqa: E402
from app.i18n import CATALOG  # noqa: E402
from app.settingsdoc import EGRESS_EXCLUDE, TRIGGERS, TUNABLE, WatchSettings  # noqa: E402

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
MB = 1_000_000


class FakeProm:
    """Answers the three queries of the trigger: the current window, the 7-day sum and the 7-day peak."""

    def __init__(self, current: dict[tuple[str, str], float], week: float = 0.0, peak: float = 0.0):
        self.current, self.week, self.peak = current, week, peak
        self.queries: list[str] = []

    async def query(self, expr: str, at=None) -> dict:
        self.queries.append(expr)
        if expr.startswith("topk("):
            floor = float(expr.rsplit(">", 1)[1].rstrip(")").strip())
            return {"series": [{"labels": {"namespace": ns, "workload": wl}, "value": str(v)}
                               for (ns, wl), v in self.current.items() if v > floor]}
        if expr.startswith("max_over_time("):
            return {"series": [{"labels": {}, "value": str(self.peak)}]}
        return {"series": [{"labels": {}, "value": str(self.week)}]}


def _scanner(prom, **cfg):
    env = load_settings(os.path.join(ROOT, "config/demo.yaml")).environments[0]
    cfg = {"enabled": True, "triggers": {"egress": True}, **cfg}
    return W.Scanner(env, FakeIndexer(alerts=[]), None, WatchSettings(**cfg), "en", prom=prom)


async def test_egress_burst_names_the_workload():
    # usual: 7 days × 288 five-minute windows × 2 MB = 4,032 MB a week; now 900 MB in 5 min
    prom = FakeProm({("erp", "odoo"): 900 * MB}, week=7 * 288 * 2 * MB, peak=3 * MB)
    evs = await _scanner(prom).egress(NOW - timedelta(minutes=5), NOW)
    assert len(evs) == 1
    ev = evs[0]
    assert ev["key"] == "egress:erp/odoo" and ev["trigger"] == "egress" and ev["workload"] == "erp/odoo"
    assert ev["bytes"] == 900 * MB and ev["baseline_bytes"] == 2 * MB and ev["factor"] == 450.0
    assert not ev.get("recurring")
    assert ev["title"] == "erp/odoo sent 900 MB out in 5 min — >100× its 7-day average (2.0 MB)"
    # the per-workload queries select the pods of that workload only, with the plumbing namespaces left out
    sel = prom.queries[1]
    assert 'namespace="erp"' in sel and 'pod=~"odoo|odoo(-[a-z0-9]{6,10})?-[a-z0-9]{5}"' in sel
    assert "kube-system" in prom.queries[0] and "longhorn-system" in prom.queries[0]
    assert "[7d] offset 5m" in sel and prom.queries[2].startswith("max_over_time(")
    line = W.event_line(ev, "en")
    assert "Unusual outbound transfer" in line and "erp/odoo" in line
    assert {"workload", "bytes", "baseline_bytes"} <= set(W.compact_for_ai(ev))


async def test_egress_thresholds_new_and_recurring():
    week = 7 * 288 * 100 * MB                                            # 100 MB per window is normal here
    assert await _scanner(FakeProm({("erp", "odoo"): 400 * MB}, week=week)).egress(NOW - timedelta(minutes=5), NOW) == []
    assert await _scanner(FakeProm({("erp", "odoo"): 300 * MB})).egress(NOW - timedelta(minutes=5), NOW) == []  # < 500 MB
    new = await _scanner(FakeProm({("erp", "export.v2"): 2.5e9})).egress(NOW - timedelta(minutes=10), NOW)
    assert new[0]["title"] == "erp/export.v2 sent 2.5 GB out in 10 min — nothing in the previous 7 days"
    assert new[0]["factor"] is None
    rec = await _scanner(FakeProm({("backup", "velero"): 2e9}, week=7 * 288 * MB, peak=1.8e9)).egress(
        NOW - timedelta(minutes=5), NOW)
    assert rec[0]["recurring"] is True                                   # nightly backups did this before
    assert await _scanner(FakeProm({("x", "bad name"): 2e9})).egress(NOW - timedelta(minutes=5), NOW) == []


async def test_egress_off_without_prometheus_or_by_default():
    prom = FakeProm({("erp", "odoo"): 900 * MB})
    assert await _scanner(None).egress(NOW - timedelta(minutes=5), NOW) == []
    sc = _scanner(prom, triggers={})
    assert await sc.egress(NOW - timedelta(minutes=5), NOW) == [] and prom.queries == []
    evs, _ = await _scanner(prom).scan(NOW - timedelta(minutes=5), NOW, None)
    assert [e["trigger"] for e in evs] == ["egress"]


def test_egress_settings():
    w = WatchSettings()
    assert "egress" in TRIGGERS and w.triggers["egress"] is False and w.triggers["spike"] is True
    assert WatchSettings(triggers={"level": True}).triggers["egress"] is False      # stored before 0.12.2
    assert WatchSettings(triggers={"egress": True}).triggers["egress"] is True
    assert w.egress_excluded() == list(EGRESS_EXCLUDE)
    assert WatchSettings(egress_exclude_namespaces="-").egress_excluded() == []
    assert WatchSettings(egress_exclude_namespaces="velero, minio").egress_excluded() == ["velero", "minio"]
    assert TUNABLE["egress_factor"] == (1.5, 100) and "egress_min_mb" in TUNABLE
    assert W.normalize_verdicts([{"event_id": "w1", "verdict": "expected", "suggestion": {
        "param": "egress_min_mb", "value": 2000, "why": "nightly export"}}], {"w1"})[0]["suggestion"]["value"] == 2000


def test_egress_texts():
    for lang in ("en", "tr", "es", "de"):
        assert CATALOG[lang]["watch.trigger.egress"] and "{wl}" in CATALOG[lang]["watch.ev.egress"]
    assert W.fmt_bytes(999) == "999 B" and W.fmt_bytes(1.5e6) == "1.5 MB" and W.fmt_bytes(12e9) == "12 GB"


# ---------------------------------------------------------------- cluster pulse
from app import pulse as P  # noqa: E402


class PulseProm:
    """Answers the pulse queries by the metric they read; ``fail`` makes one metric raise."""

    def __init__(self, kong=True, empty=False, fail=""):
        self.kong, self.empty, self.fail = kong, empty, fail
        self.queries: list[str] = []

    def _rows(self, expr: str) -> list[tuple[dict, float]]:
        if self.empty:
            return []
        if self.fail and self.fail in expr:
            raise RuntimeError("boom")
        if expr.startswith("count(kong_http_requests_total)"):
            return [({}, 120.0)] if self.kong else []
        if expr.startswith("count(traefik_router_requests_total)"):
            return [({}, 40.0)]
        if expr.startswith("count(") and "requests" in expr:
            return []
        if "kong_http_requests_total" in expr or "traefik_router_requests_total" in expr:
            rl = "route" if self.kong else "router"
            if "sum by (code)" in expr:
                base = "offset 1d" in expr
                k = 6 if base else 1
                return [({"code": "200"}, 100_000.0 * k), ({"code": "403"}, 600.0 * 6 if base else 9_000.0),
                        ({"code": "502"}, 50.0 * k)]
            if f"sum by ({rl}, code)" in expr:
                return [({rl: "auth.sso", "code": "403"}, 8_000.0), ({rl: "auth.sso", "code": "502"}, 30.0),
                        ({rl: "shop.web", "code": "404"}, 700.0)]
            if f"topk(8, sum by ({rl})" in expr:
                return [({rl: "shop.web"}, 700.0), ({rl: "auth.sso"}, 8_030.0)]
        if "certmanager_certificate_expiration" in expr:
            return [({"exported_namespace": "shop", "name": "web-tls", "issuer_name": "le"}, 5 * 86400.0),
                    ({"exported_namespace": "auth", "name": "sso-tls", "issuer_name": "le"}, 60 * 86400.0),
                    ({"exported_namespace": "ci", "name": "ci-tls", "issuer_name": "le"}, 15 * 86400.0)]
        if "certmanager_certificate_ready_status" in expr:
            return [({"exported_namespace": "auth", "name": "sso-tls"}, 1.0)]
        if expr == "count(up)":
            return [({}, 50.0)]
        if expr == "up == 0":
            return [({"job": "pods", "instance": "198.51.100.7:9100", "namespace": "erp", "pod": "x-1"}, 0.0)]
        if "container_network_transmit" in expr and expr.startswith("topk(8"):
            return [({"namespace": "erp", "workload": "export"}, 5e9), ({"namespace": "shop", "workload": "web"}, 1e9)]
        if "container_network_transmit" in expr and "and on" in expr:
            return [({"namespace": "erp", "workload": "export"}, 6 * 0.2e9), ({"namespace": "shop", "workload": "web"}, 6 * 1e9)]
        if "container_network_transmit" in expr:
            return [({}, 7e9 if "offset" not in expr else 6 * 3e9)]
        return []

    async def query(self, expr, at=None):
        self.queries.append(expr)
        return {"series": [{"labels": lab, "value": str(v)} for lab, v in self._rows(expr)]}

    async def query_range(self, expr, start, end, step):
        self.queries.append(expr)
        rows = self._rows(expr) if not self.empty else []
        return {"series": [{"labels": {}, "points": [["11-16 10:00", "1"], ["11-16 11:00", "3"]]}] if rows or not self.empty else []}


async def test_pulse_panels():
    p = await P.Pulse(PulseProm(), ["kube-system"], NOW).collect()
    assert p["errors"] == []
    ig = p["ingress"]
    assert ig["source"] == "Kong" and ig["cur"]["auth"] == 9_000 and ig["prev"]["auth"] == 600
    assert ig["status_auth"] == "bad" and ig["rows"][0]["route"] == "auth.sso" and ig["rows"][0]["403"] == 8_000
    assert ig["rows"][0]["5xx"] == 30
    ce = p["certs"]
    assert [r["name"] for r in ce["rows"]] == ["web-tls", "ci-tls", "sso-tls"]
    assert [r["status"] for r in ce["rows"]] == ["bad", "warn", "bad"] and ce["rows"][2]["ready"] is False
    assert p["targets"]["down"] == 1 and p["targets"]["total"] == 50 and p["targets"]["status"] == "warn"
    eg = p["egress"]
    assert eg["rows"][0]["workload"] == "export" and eg["rows"][0]["status"] == "bad"      # 5 GB vs 0.2 GB a day: 25×
    assert eg["rows"][1]["status"] == "ok" and eg["spark"] == [1.0, 3.0]
    assert p["status"] == "bad" and p["dns"] == {"empty": True}


async def test_pulse_traefik_empty_and_partial():
    p = await P.Pulse(PulseProm(kong=False), [], NOW).collect()
    assert p["ingress"]["source"] == "Traefik" and p["ingress"]["rows"][0]["route"] == "auth.sso"
    empty = await P.Pulse(PulseProm(empty=True), [], NOW).collect()
    assert all(empty[k] == {"empty": True} for k in ("egress", "ingress", "secrets", "dns", "cpu", "restarts", "certs",
                                                     "targets"))
    assert empty["status"] == "ok" and empty["errors"] == []
    broken = await P.Pulse(PulseProm(fail="certmanager"), [], NOW).collect()
    assert broken["errors"] == ["certs"] and "error" in broken["certs"] and broken["targets"]["down"] == 1


def test_pulse_rules():
    assert P.ratio_status(100, 50, floor=500) == "ok"          # small numbers never raise a flag
    assert P.ratio_status(2_000, 100) == "bad" and P.ratio_status(400, 100) == "warn" and P.ratio_status(200, 100) == "ok"
    assert P.ratio_status(2_000, 0) == "warn"
    assert P.cert_status(30) == "ok" and P.cert_status(20) == "warn" and P.cert_status(6) == "bad"
    assert P.cert_status(90, ready=False) == "bad"
    assert P.worst("ok", "warn") == "warn" and P.worst("warn", "bad") == "bad" and P.worst() == "ok"
    assert P.code_class("503") == "5xx" and P.code_class("x") == "other"


def test_pulse_page():
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        c.post("/login", data={"password": "pw"})
        r = c.get("/e/demo/pulse")
        assert r.status_code == 200
        assert "Cluster pulse" in r.text and "report-export" in r.text and "sso-example-tls" in r.text
        assert 'href="/e/demo/pulse"' in c.get("/e/demo/attack").text
        c.post("/lang", data={"lang": "tr"})
        assert "Küme nabzı" in c.get("/e/demo/pulse").text


class DownProm:
    async def query(self, *a, **k):
        raise RuntimeError("cannot reach")

    async def query_range(self, *a, **k):
        raise RuntimeError("cannot reach")


def test_pulse_page_renders_when_prometheus_is_down_or_empty(monkeypatch):
    import asyncio

    from fastapi.testclient import TestClient

    from app.main import app
    for prom, word in ((DownProm(), "did not answer"), (PulseProm(empty=True), "No metrics"),
                       (PulseProm(kong=False), "Traefik")):
        data = asyncio.run(P.Pulse(prom, [], NOW).collect())

        async def fake(env_id, p, exclude, use_cache=True, data=data):
            return data
        monkeypatch.setattr(P, "pulse", fake)
        with TestClient(app) as c:
            c.post("/login", data={"password": "pw"})
            c.post("/lang", data={"lang": "en"})
            r = c.get("/e/demo/pulse")
            assert r.status_code == 200 and word in r.text


# ---------------------------------------------------------------- 0.13: several clusters per environment
class RouterProm(PulseProm):
    """An OpenShift cluster: the router counts responses by class only."""

    def _rows(self, expr):
        if expr.startswith("count(haproxy_backend_http_responses_total)"):
            return [({}, 10.0)]
        if expr.startswith("count(") and "requests" in expr:
            return []
        if "haproxy_backend_http_responses_total" in expr:
            if "sum by (code)" in expr:
                base = "offset 1d" in expr
                return [({"code": "2xx"}, 50_000.0 * (6 if base else 1)), ({"code": "4xx"}, 300.0 * 6 if base else 4_000.0),
                        ({"code": "5xx"}, 20.0 * (6 if base else 1))]
            if "sum by (route, code)" in expr:
                return [({"route": "shop", "code": "4xx"}, 3_500.0), ({"route": "shop", "code": "5xx"}, 12.0)]
            if "topk(8, sum by (route)" in expr:
                return [({"route": "shop"}, 3_512.0)]
        return super()._rows(expr)


async def test_pulse_openshift_router():
    p = await P.Pulse(RouterProm(kong=False), [], NOW).collect()
    ig = p["ingress"]
    assert ig["source"] == "OpenShift router" and ig["classes_only"] is True
    assert ig["auth"] == 4_000 and ig["auth_prev"] == 300 and ig["auth_label"] == "pl.k.4xx" and ig["status_auth"] == "bad"
    assert ig["rows"][0] == {"route": "shop", "errors": 3_512.0, "401": 0, "403": 0, "404": 0, "4xx": 3_500.0, "5xx": 12.0}


def test_sources_several_clusters():
    from pydantic import ValidationError

    from app.config import SourcesCfg
    from app.services import Clusters, clusters_of
    s = SourcesCfg(prometheus={"url": "http://p:9090", "name": "sfkube"},
                   prometheus_extra=[{"name": "approd", "url": "https://t1", "bearer_token": "x"},
                                     {"name": "unused", "url": ""}])
    assert s.prometheus_names() == ["sfkube", "approd"]
    assert SourcesCfg(prometheus_extra=[{"name": "a", "url": "https://t"}]).prometheus_names() == ["a"]
    for bad in ([{"url": "https://t"}], [{"name": "Bad Name", "url": "https://t"}],
                [{"name": "default", "url": "https://t"}]):
        try:
            SourcesCfg(prometheus={"url": "http://p"}, prometheus_extra=bad)
        except ValidationError:
            continue
        raise AssertionError(bad)
    assert clusters_of({}) == {} and clusters_of({"prometheus": 1}) == {"default": 1}
    assert clusters_of({"prometheus": 1, "clusters": Clusters(a=1, b=2)}) == {"a": 1, "b": 2}


async def test_egress_on_several_clusters():
    env = load_settings(os.path.join(ROOT, "config/demo.yaml")).environments[0]
    cfg = WatchSettings(enabled=True, triggers={"egress": True})
    sc = W.Scanner(env, FakeIndexer(alerts=[]), None, cfg, "en",
                   clusters={"sfkube": FakeProm({("erp", "odoo"): 900 * MB}), "approd": DownProm(),
                             "scprod": FakeProm({("shop", "web"): 2e9})})
    evs = await sc.egress(NOW - timedelta(minutes=5), NOW)
    assert sorted(e["key"] for e in evs) == ["egress:scprod:shop/web", "egress:sfkube:erp/odoo"]
    assert all(e["title"].startswith("[" + e["cluster"] + "] ") for e in evs)
    assert sc.errors == ["egress[approd]: RuntimeError"]
    one = W.Scanner(env, FakeIndexer(alerts=[]), None, cfg, "en", prom=FakeProm({("erp", "odoo"): 900 * MB}))
    assert [e["key"] for e in await one.egress(NOW - timedelta(minutes=5), NOW)] == ["egress:erp/odoo"]


async def test_tools_pick_the_cluster():
    from app.agent.tools import ToolBox
    from app.services import Clusters
    env = load_settings(os.path.join(ROOT, "config/demo.yaml")).environments[0]
    a, b = FakeProm({}), FakeProm({})
    tb = ToolBox(env, FakeIndexer(alerts=[]), None, None, sources={"prometheus": a, "clusters": Clusters(sfkube=a, approd=b)})
    assert tb._prom({}) is a and tb._prom({"cluster": "approd"}) is b
    try:
        tb._prom({"cluster": "nope"})
    except ValueError as e:
        assert "approd" in str(e)
    else:
        raise AssertionError
    assert "cluster" in str(tb.specs())


def test_namespace_wildcards():
    assert W._rx("openshift-*") == "openshift-.*"
    assert WatchSettings(egress_exclude_namespaces="openshift-*, velero").egress_excluded() == ["openshift-*", "velero"]
    assert "openshift-*" in EGRESS_EXCLUDE
    try:
        WatchSettings(egress_exclude_namespaces='a"b')
    except Exception:
        pass
    else:
        raise AssertionError


def test_pulse_page_cluster_selector(monkeypatch):
    from fastapi.testclient import TestClient

    import app.services as S
    from app.main import app
    monkeypatch.setattr(S, "clusters_of", lambda src: {"sfkube": PulseProm(kong=False), "approd": RouterProm(kong=False)})
    P._CACHE.clear()
    with TestClient(app) as c:
        c.post("/login", data={"password": "pw"})
        c.post("/lang", data={"lang": "en"})
        r = c.get("/e/demo/pulse")
        assert r.status_code == 200 and 'href="?c=approd"' in r.text and "Traefik" in r.text
        r = c.get("/e/demo/pulse?c=approd")
        assert r.status_code == 200 and "OpenShift router" in r.text and "4xx at ingress" in r.text
