# SPDX-License-Identifier: AGPL-3.0-only
"""AI round without an API key: MCP client (start_review / submit_review) and the file channel (brief + pasted answer)."""
import json
import os
import re

import pytest

from app.config import LLMConfig, load_settings
from app.external import parse_answer
from app.llm.base import LLMError, make_llm
from app.runtime import Runtime

ROOT = os.path.dirname(os.path.dirname(__file__))


@pytest.fixture()
def rt():
    return Runtime(load_settings(os.path.join(ROOT, "config/demo.yaml")), demo=True)


def _answer(extra_detail=""):
    rep = {"summary_md": "Quiet day, one brute force to check.", "health_assessment": "Alerts flow, agents connected.",
           "findings": [{"title": "SSH brute force on db01", "label": "investigate", "severity": "medium",
                         "detail": "Many failed logins " + extra_detail, "rule_ids": ["5710"], "agents": ["db01"]}],
           "questions": [{"question": "Was the 03:10 login yours?"}],
           "proposals": [{"kind": "lesson", "title": "db01 is scanned nightly", "body": "seen in external round"}]}
    return "Here is the report:\n```json\n" + json.dumps(rep) + "\n```\nThanks."


async def test_file_channel_round_trip(rt):
    er = rt.get("demo")
    await er.repo.add_knowledge("request", "look at db01 ssh")
    r = await rt.external_start("demo", "file", actor="tester")
    assert "no tools" in r["brief"] and "Report object" in r["brief"] and "submit_review" not in r["brief"]
    run = await er.repo.get_run(r["run_id"])
    assert run["status"] == "awaiting" and run["external"]["channel"] == "file" and run["collected"]
    assert rt.get("demo").current_run is None                     # the environment is free while we wait
    tok = re.search(r"<(?:email|national_id_tr|phone):[0-9a-f]+>", r["brief"])
    done = await rt.external_submit("demo", r["run_id"], _answer(tok.group(0) if tok else ""), actor="tester")
    assert done["status"] == "done" and done["findings"][0]["title"] == "SSH brute force on db01"
    assert done["agent"]["provider"] == "external" and done["proposals"]
    if tok:      # pseudonyms are resolved inside the installation
        assert tok.group(0) not in done["findings"][0]["detail"]
    assert await er.repo.list_knowledge(kinds=["request"], status="active") == []
    with pytest.raises(ValueError, match="not waiting"):
        await rt.external_submit("demo", r["run_id"], _answer())


async def test_bad_answer_is_refused_and_run_stays_open(rt):
    r = await rt.external_start("demo", "file")
    with pytest.raises(ValueError, match="no report object"):
        await rt.external_submit("demo", r["run_id"], "I could not do it, sorry.")
    assert (await rt.get("demo").repo.get_run(r["run_id"]))["status"] == "awaiting"


def test_parse_answer_takes_the_report_block():
    assert parse_answer('noise {"a": 1} ```json\n{"summary_md": "x", "findings": []}\n```')["summary_md"] == "x"
    assert parse_answer('{"findings": [], "summary_md": "plain"}')["summary_md"] == "plain"
    with pytest.raises(ValueError):
        parse_answer('```json\n{"other": 1}\n```')


async def test_mcp_channel(rt, monkeypatch):
    monkeypatch.setenv("MCP_TOKEN", "x" * 32)
    from app import mcp
    tools = {t["name"]: t for t in mcp._tool_list(rt)}
    assert tools["start_review"]["annotations"]["readOnlyHint"] is False and "submit_review" in tools
    pl = await mcp._handle(rt, {"jsonrpc": "2.0", "id": 1, "method": "prompts/list"})
    assert pl["result"]["prompts"][0]["name"] == "daily_review"
    pg = await mcp._handle(rt, {"jsonrpc": "2.0", "id": 2, "method": "prompts/get",
                                "params": {"name": "daily_review", "arguments": {"env": "demo"}}})
    assert "start_review" in pg["result"]["messages"][0]["content"]["text"]
    s = json.loads(await mcp._call(rt, "start_review", {"env": "demo"}))
    assert "submit_review" in s["brief"] and s["run_id"] in s["brief"]
    rep = parse_answer(_answer())
    rep.pop("proposals")
    out = json.loads(await mcp._call(rt, "submit_review", {"env": "demo", "run_id": s["run_id"], "report": rep}))
    assert out["status"] == "done" and out["findings"] == 1


async def test_provider_none_keeps_the_deterministic_report(rt):
    with pytest.raises(LLMError, match="LLM_PROVIDER=none"):
        await make_llm(LLMConfig(provider="none")).complete("s", [], [])
