# SPDX-License-Identifier: AGPL-3.0-only
"""After 0.15.0: named MCP tokens, proxy hint, optional person_name detector."""
import os

ROOT = os.path.dirname(os.path.dirname(__file__))
os.environ.update(WDT_DEMO="true", APP_PASSWORD="pw", VIEWER_PASSWORD="vwpw", APP_SECRET="s",
                  WDT_SCHEDULER="false", WDT_CONFIG=os.path.join(ROOT, "config/demo.yaml"))

from fastapi.testclient import TestClient  # noqa: E402

from app import mcp  # noqa: E402
from app.main import app  # noqa: E402
from app.privacy import DEFAULT_KINDS, KINDS, Masker, scan  # noqa: E402
from app.web import common  # noqa: E402

PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}


def test_named_tokens_parse_and_revoke(monkeypatch, tmp_path):
    monkeypatch.delenv("MCP_TOKEN", raising=False)
    monkeypatch.setenv("MCP_TOKENS", "alice=aaaaaaaaaaaaaaaaaaaa, bad name=bbbbbbbbbbbbbbbbbbbb, short=x")
    f = tmp_path / "tokens"
    f.write_text("# team\ncursor-bob=cccccccccccccccccccc\n", encoding="utf-8")
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    assert mcp.tokens() == {"alice": "a" * 20, "cursor-bob": "c" * 20}
    with TestClient(app) as cl:
        assert cl.post("/mcp", json=PING, headers={"Authorization": "Bearer " + "c" * 20}).status_code == 200
        f.write_text("", encoding="utf-8")                                     # removed = revoked at once
        assert cl.post("/mcp", json=PING, headers={"Authorization": "Bearer " + "c" * 20}).status_code == 401


def test_named_clients_have_their_own_rate_limit(monkeypatch):
    monkeypatch.setenv("MCP_TOKEN", "default-token-123456")
    monkeypatch.setenv("MCP_TOKENS", "alice=aaaaaaaaaaaaaaaaaaaa,bob=bbbbbbbbbbbbbbbbbbbb")
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    monkeypatch.setattr(mcp, "MCP_REQUESTS", common.Throttle(limit=2, window=60))
    with TestClient(app) as cl:
        a = {"Authorization": "Bearer " + "a" * 20}
        b = {"Authorization": "Bearer " + "b" * 20}
        assert [cl.post("/mcp", json=PING, headers=a).status_code for _ in range(3)] == [200, 200, 429]
        assert cl.post("/mcp", json=PING, headers=b).status_code == 200        # same address, own quota


def test_audit_actor_is_the_client_name(monkeypatch):
    seen = {}
    monkeypatch.setattr(mcp.auditlog, "available", lambda: True)
    monkeypatch.setattr(mcp.auditlog, "record", lambda action, **kw: seen.update(kw) if action == "mcp.propose_knowledge" else None)
    monkeypatch.setenv("MCP_TOKENS", "alice=aaaaaaaaaaaaaaaaaaaa")
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "propose_knowledge", "arguments":
            {"env": "demo", "kind": "baseline", "title": "t"}}}
    with TestClient(app) as cl:
        cl.post("/mcp", json=call, headers={"Authorization": "Bearer " + "a" * 20, "X-Request-ID": "req-42"})
    assert seen["actor"] == "mcp:alice" and seen["env"] == "demo" and seen["request_id"] == "req-42"


def test_proxy_hint_in_connection_test(monkeypatch):
    monkeypatch.setattr(common, "TRUSTED_PROXIES", [])
    with TestClient(app) as cl:
        cl.post("/login", data={"password": "pw"})
        r = cl.post("/api/e/demo/check?wait=1", headers={"X-Forwarded-For": "198.51.100.9"})
        assert r.status_code == 200
        res = r.json()
        rows = {x["key"]: x for x in res.get("results", [])}
        assert rows["proxy"]["ok"] is False and "TRUSTED_PROXIES" in rows["proxy"]["detail"]


def test_person_name_is_optional():
    assert "person_name" in KINDS and "person_name" not in DEFAULT_KINDS
    assert "Ayşe Yılmaz" in Masker().mask("Ayşe Yılmaz giriş yaptı")
    assert "Ayşe Yılmaz" not in Masker(kinds=KINDS).mask("Ayşe Yılmaz giriş yaptı")
    assert "person_name" not in scan("Ayşe Yılmaz giriş yaptı")
