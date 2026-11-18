# SPDX-License-Identifier: AGPL-3.0-only
"""A fresh installation (no alerts, no vulnerabilities, no reports) renders every page without errors or junk."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import demo, runtime  # noqa: E402
from app.main import app  # noqa: E402

PAGES = ["/", "/e/demo", "/e/demo/inbox", "/e/demo/attack", "/e/demo/pulse", "/e/demo/noise", "/e/demo/watch",
         "/e/demo/k", "/e/demo/audit", "/e/demo/settings", "/about"]
JUNK = re.compile(r">\s*(None|nan|NaN|undefined|null)\s*<|Traceback|\{\{|\{%")


@pytest.fixture
def empty(monkeypatch):
    monkeypatch.setattr(runtime, "FakeIndexer", lambda: demo.FakeIndexer(alerts=[], vulns=[]), raising=False)
    monkeypatch.setattr(demo, "generate", lambda *a, **k: [])
    monkeypatch.setattr(demo, "generate_vulns", lambda *a, **k: [])


@pytest.mark.parametrize("lang", ["en", "tr"])
def test_every_page_renders_empty(empty, lang):
    with TestClient(app) as cl:
        cl.post("/login", data={"password": "pw"})
        cl.cookies.set("lang", lang)
        bad = []
        for u in PAGES:
            r = cl.get(u)
            if r.status_code != 200:
                bad.append(f"{u}: {r.status_code}")
            elif m := JUNK.search(r.text):
                bad.append(f"{u}: {m.group(0)!r}")
        assert not bad, bad
