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
