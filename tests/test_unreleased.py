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


def test_masked_notification_channels(monkeypatch):
    import httpx

    from app.config import Environment, Settings
    from app.notify import NotifyCfg, send
    sent = {}

    def handler(request):
        sent[request.url.host] = request.content.decode()
        return httpx.Response(200, json={"ok": True})

    cfg = NotifyCfg(telegram={"bot_token": "123:abc", "chat_id": "1"}, slack={"webhook_url": "https://hooks.slack.test/x"},
                    mask="telegram")
    env = Environment(id="t", name="T", indexer={"url": "https://x:9200"}, notify=cfg)
    ncfg = Settings(environments=[env]).notify_for(env)
    msg = {"title": "login ayse@firma.com.tr", "lines": ["TCKN 10000000146"], "link": "https://ui/x",
           "text": "login ayse@firma.com.tr TCKN 10000000146"}
    import asyncio
    res = asyncio.run(send(ncfg, msg, transport=httpx.MockTransport(handler)))
    assert res == {"telegram": "ok", "slack": "ok"}
    tg = next(v for k, v in sent.items() if "telegram" in k)
    sl = next(v for k, v in sent.items() if "slack" in k)
    assert "ayse@firma.com.tr" not in tg and "10000000146" not in tg and "<email:" in tg
    assert "ayse@firma.com.tr" in sl                      # not in the mask list: unchanged
    assert msg["text"].startswith("login ayse@")          # the caller's message is not modified


def test_structured_llm_content_is_masked():
    import asyncio

    from app.llm.base import LLMResponse
    from app.privacy import MaskingLLM
    seen = {}

    class Inner:
        name = "x"

        async def complete(self, system, messages, tools, force_tool=None):
            seen["m"] = messages
            return LLMResponse(text="", tool_calls=[])

    asyncio.run(MaskingLLM(Inner(), Masker()).complete("s", [{"role": "user", "content": [
        {"type": "text", "text": "mail ayse@firma.com.tr"}]}], []))
    assert "ayse@firma.com.tr" not in str(seen["m"])


def test_only_runtime_and_eval_build_llm_clients():
    """Every model call must go through Runtime.llm_for (which wraps it in MaskingLLM): no direct make_llm."""
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parent.parent / "app"
    users = sorted(str(p.relative_to(root)) for p in root.rglob("*.py")
                   if re.search(r"\bmake_llm\(", p.read_text(encoding="utf-8")))
    assert users == ["eval.py", "llm/base.py", "runtime.py"], users


def test_no_proxy_hint_when_uvicorn_resolved_the_client():
    from starlette.requests import Request
    scope = {"type": "http", "client": ("198.51.100.9", 1), "headers": [(b"x-forwarded-for", b"198.51.100.9")]}
    assert common.proxy_hint(Request(scope)) is None           # FORWARDED_ALLOW_IPS already applied
    scope["client"] = ("10.42.0.5", 1)
    assert common.proxy_hint(Request(scope)) == "10.42.0.5"   # the proxy itself is the peer


def test_public_demo_is_read_only_without_login(monkeypatch):
    monkeypatch.setattr(common, "PUBLIC_DEMO", True)
    with TestClient(app) as cl:
        r = cl.get("/")
        assert r.status_code == 200 and "Public demo" in r.text
        assert cl.get("/e/demo/inbox").status_code == 200
        assert cl.get("/e/demo/settings").status_code in (302, 303, 403)
        assert cl.post("/api/e/demo/run", json={}).status_code in (401, 403)
        assert cl.post("/api/e/demo/inbox/act", json={}).status_code in (401, 403)


def test_public_demo_needs_demo_mode():
    assert common.public_demo_enabled({"WDT_PUBLIC_DEMO": "true", "WDT_DEMO": "true"})
    assert not common.public_demo_enabled({"WDT_PUBLIC_DEMO": "true", "WDT_DEMO": "false"})
    assert not common.public_demo_enabled({"WDT_PUBLIC_DEMO": "true", "WDT_DEMO": "true", "AUTH_DISABLED": "true"})


async def test_weekly_summary_and_rule_effect(monkeypatch):
    import httpx

    from app.config import load_settings
    from app.runtime import Runtime
    sent = []

    def handler(request):
        sent.append(request.content.decode())
        return httpx.Response(200)

    rt = Runtime(load_settings(os.path.join(ROOT, "config/demo.yaml")), demo=True)
    env_id = next(iter(rt.envs))
    cfg = rt.settings.notify_for(rt.get(env_id).env)
    cfg.telegram.bot_token, cfg.telegram.chat_id = "1:x", "1"
    r = await rt.weekly_summary(env_id, transport=httpx.MockTransport(handler), force=True)
    assert r["result"] == {"telegram": "ok"} and len(r["lines"]) >= 5
    assert "AI round" in " ".join(r["lines"])
    assert await rt.weekly_summary(env_id) == {}                 # off unless notify.on_weekly


def test_effect_pct():
    from app.weekly import pct
    assert pct(10, 4) == "−60 %" and pct(0, 3) == "new" and pct(5, 5) == "±0 %"
