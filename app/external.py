# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""The AI round without an API key: an MCP client or any chat does the analysis, Occultera does the rest.

Two channels, one lifecycle:

* ``mcp``  — Claude Desktop, Cursor, VS Code …: ``start_review`` returns the round's brief, the client investigates
  with the usual read-only tools and calls ``submit_review``.
* ``file`` — Gemini, ChatGPT, Claude.ai …: the UI hands out a Markdown brief, the user pastes the model's answer
  (one JSON block) back into the UI.

The brief is the same one the built-in AI reads, masked with the environment's privacy profile. The answer is
unmasked inside the installation (pseudonyms are HMAC-stable, so re-masking the stored data rebuilds the map even
after a restart), checked by ``normalize_report`` and finished exactly like a built-in round: ATT&CK enrichment,
watch verdicts, requests closed, notification. Rule drafts in a file answer go through ``propose_knowledge``,
so the same ID-range and XML checks apply.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from .agent.specs import SPECS
from .agent.tools import ToolBox
from .collector import _parse, iso
from .i18n import t
from .privacy import Masker, masker_for
from .store import new_id, now_iso

log = logging.getLogger("wdt")
CHANNELS = ("file", "mcp")
EXPIRE_DAYS = 7
MAX_ANSWER = 400_000

_FILE_NOTE = """
# This session: no tools
You are NOT connected to Occultera's tools in this session. Do not call or simulate tools. Work only with the
data below. Where you would have drilled down, say what should be checked in `manual_checks` or ask in `questions`.

# How to answer
Reply with exactly ONE fenced code block marked `json` that contains the report object described below — nothing
needs to go outside it. Rule drafts and other proposals go into `proposals` (each like `propose_knowledge`:
kind, title, body, rule_ids, and for kind=rule_draft the complete `<group>…</group>` XML in `xml` plus `tests`).
Values such as `<email:3f9a…>` are pseudonyms: copy them exactly, never guess the real value.
"""

_MCP_NOTE = """
# This session: an MCP client
Investigate with the Occultera tools you have (search_alerts, aggregate_alerts, rule_timeline, ip_profile …) for
environment `{env}`. Propose rule drafts and other knowledge with `propose_knowledge`. Finish by calling
`submit_review` exactly once with env=`{env}`, run_id=`{run_id}` and `report` = the report object described below.
Values such as `<email:3f9a…>` are pseudonyms: pass them to the tools as they are.
"""


def report_schema() -> dict:
    """The submit_report schema plus the file channel's `proposals`."""
    p = json.loads(json.dumps(SPECS["submit_report"]["parameters"]))
    prop = json.loads(json.dumps(SPECS["propose_knowledge"]["parameters"]))
    p["properties"]["proposals"] = {"type": "array", "items": prop,
                                    "description": "file channel only: knowledge proposals and rule drafts"}
    return p


def brief(sysmsg: str, usr: str, channel: str, env_id: str, run_id: str) -> str:
    note = _FILE_NOTE if channel == "file" else _MCP_NOTE.format(env=env_id, run_id=run_id)
    return (f"<!-- Occultera AI round · environment {env_id} · run {run_id} -->\n\n{sysmsg}\n{note}\n"
            f"# Report object (JSON Schema)\n```json\n{json.dumps(report_schema(), ensure_ascii=False, indent=1)}\n```\n\n"
            f"# Data for this round\n{usr}\n")


def _fenced_objects(text: str) -> list[str]:
    """Bodies of ```json fences that hold a {...} object. A linear split, not a regex: CodeQL flagged the
    old lazy pattern as polynomial on pasted input full of '{'."""
    out = []
    for body in text.split("```")[1::2]:
        b = body.lstrip()
        if b[:4].lower() == "json":
            b = b[4:]
        b = b.strip()
        if b.startswith("{") and b.endswith("}"):
            out.append(b)
    return out


def parse_answer(text: str) -> dict:
    """The report object from a pasted answer: a ```json block, else the outermost {...}."""
    text = (text or "")[:MAX_ANSWER]
    cands = _fenced_objects(text)
    if not cands and "{" in text:
        cands = [text[text.index("{"): text.rindex("}") + 1]]
    for c in sorted(cands, key=len, reverse=True):
        try:
            d = json.loads(c)
        except ValueError:
            continue
        if isinstance(d, dict) and ("findings" in d or "summary_md" in d):
            return d
    raise ValueError("no report object found: paste the model's answer with its ```json block")


PREFETCH_RULES = 6


async def prefetch(rt, collected: dict, frm: datetime, to: datetime, high_level: int) -> str:
    """For the file channel the assistant has no tools: pre-fetch what the built-in AI usually asks for first —
    the time distribution and three sample events of the busiest high-level rules."""
    rules = sorted((r for r in collected.get("top_rules") or [] if int(r.get("level") or 0) >= high_level),
                   key=lambda r: (-int(r.get("level") or 0), -int(r.get("count") or 0)))[:PREFETCH_RULES]
    if not rules:
        return ""
    tb = ToolBox(rt.env, rt.ix, rt.api, rt.repo, mode="triage", sources=rt.sources)
    hours = max(1, (to - frm).total_seconds() / 3600)
    interval = "1h" if hours <= 48 else "6h"
    out = ["", "# Drill-down, pre-fetched (you have no tools: this is what you would have asked for first)", ""]
    for r in rules:
        args = {"rule_ids": [str(r["id"])], "from": iso(frm), "to": iso(to)}
        tl = await tb.call("rule_timeline", {**args, "interval": interval})
        ev = await tb.call("search_alerts", {**args, "size": 3})
        out += [f"## Rule {r['id']} (level {r.get('level')}, {r.get('count')} alerts): {r.get('desc', '')}",
                "Timeline:", "```json", tl[:4000], "```", "Sample events:", "```json", ev[:6000], "```", ""]
    return "\n".join(out)


class ExternalMixin:
    async def external_start(self, env_id: str, channel: str, actor: str = "", hours: int | None = None) -> dict:
        """Collect like a built-in round and park the run until the answer comes back. Returns the masked brief."""
        if channel not in CHANNELS:
            raise ValueError(f"channel must be one of {CHANNELS}")
        rt = self.get(env_id)
        if rt.current_run or rt.lock.locked():
            raise RuntimeError(t(self.lang(rt.env), "err.busy"))
        run_id = new_id(f"{env_id}-")
        rt.current_run = run_id
        started = datetime.now(UTC)
        run = {"run_id": run_id, "env": env_id, "status": "running", "trigger": f"external:{channel}",
               "lang": self.lang(rt.env), "started_at": iso(started), "stage": "collecting"}
        try:
            async with rt.lock:
                await rt.repo.save_run(run)
                prep = await self._prepare_round(rt, run, started, hours)
                run.update(status="awaiting", stage="external", external={
                    "channel": channel, "actor": actor, "from": iso(prep["frm"]),
                    "expires": iso(started + timedelta(days=EXPIRE_DAYS)),
                    "events": [e["id"] for e in prep["events"]], "requests": [r["id"] for r in prep["requests"]]})
                await rt.repo.save_run(run)
        except Exception:
            run.update(status="error", stage=None, finished_at=now_iso(), error="external round: collection failed")
            await rt.repo.save_run(run)
            raise
        finally:
            if rt.current_run == run_id:
                rt.current_run = None
        text = brief(prep["sysmsg"], prep["usr"], channel, env_id, run_id)
        if channel == "file":
            try:
                text += await prefetch(rt, run.get("collected") or {}, prep["frm"], started, rt.env.high_level)
            except Exception as e:  # noqa: BLE001 - the brief is still useful without the drill-down
                log.warning("external round %s: drill-down failed: %s", run_id, e)
        st = await self.env_settings(rt)
        m = masker_for(rt.env, st.mask)
        log.info("external round %s started (%s) by %s", run_id, channel, actor or "-")
        return {"run_id": run_id, "brief": m.mask(text) if m else text, "masked": bool(m),
                "expires": run["external"]["expires"]}

    async def external_submit(self, env_id: str, run_id: str, answer: Any, actor: str = "", client: str = "") -> dict:
        """Finish a parked run with the external answer (a dict from MCP, or pasted text from the file channel)."""
        rt = self.get(env_id)
        async with self.run_lock(run_id):
            run = await rt.repo.get_run(run_id)
            if not run or run.get("env") != env_id:
                raise KeyError(run_id)
            ext = run.get("external") or {}
            if run.get("status") != "awaiting":
                raise ValueError(f"run {run_id} is {run.get('status')}, not waiting for an answer")
            if ext.get("expires") and _parse(ext["expires"]) < datetime.now(UTC):
                raise ValueError(f"run {run_id} expired on {ext['expires'][:10]}; start a new round")
            sub = parse_answer(answer) if isinstance(answer, str) else answer
            if not isinstance(sub, dict):
                raise ValueError("report must be an object")
            st = await self.env_settings(rt)
            m = masker_for(rt.env, st.mask)
            if m:   # rebuild the pseudonym map from the stored data (HMAC-stable), then resolve the answer
                m.mask(json.dumps(run.get("collected") or {}, ensure_ascii=False, default=str))
                sub = Masker.unmask_obj(sub, rt.env.id)
            proposals: list[str] = []
            if ext.get("channel") == "file":
                tb = ToolBox(rt.env, rt.ix, rt.api, rt.repo, mode="triage", run_id=run_id, sources=rt.sources)
                for p in (sub.get("proposals") or [])[:20]:
                    if isinstance(p, dict):
                        await tb.call("propose_knowledge", p)
                proposals = [p["id"] for p in tb.proposals]
            run["proposals"] = proposals
            run["agent"] = {"steps": 0, "stopped": "external", "trace": [], "provider": "external",
                            "model": client or ext.get("channel"), "actor": actor or ext.get("actor", "")}
            run["external"] = {**ext, "answered_at": now_iso(), "answered_by": actor or client}
            started = _parse(run["started_at"])
            await self._finish_round(rt, run, sub, "", _parse(ext.get("from") or run["started_at"]), started,
                                     set(ext.get("events") or []), list(ext.get("requests") or []))
        await self.notify_run(rt, run)
        return run
