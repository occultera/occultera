# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Rule deployment through the Wazuh API: write the block, validate, restart, test, roll back (split from rules.py).

Every name stays importable from ``app.rules``.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from . import rules as _R  # POLL_* live in app.rules (tests shorten them there)
from .config import RuleDeployCfg
from .rules import remove_block, with_block
from .wazuh.api import WazuhAPI, WazuhAPIError


class DeployError(RuntimeError):
    steps: list[dict] | None = None
    rollback: str = "not_needed"          # done | failed | not_needed


async def _wait_back(api: WazuhAPI, ids: list[str], file: str, timeout: int, present: bool = True) -> str:
    """After a restart: wait for analysisd and (un)loaded rules. Returns a short status line."""
    deadline = time.monotonic() + timeout
    await asyncio.sleep(_R.POLL_FIRST)
    last = ""
    while time.monotonic() < deadline:
        try:
            api.reset_token()
            st = await api.manager_status()
            if st.get("wazuh-analysisd") == "running":
                found = {str(r["id"]) for r in await api.rules(ids) if r.get("filename") == file} if ids else set()
                if (set(ids) <= found) if present else not found:
                    return "analysisd running, rules " + ("loaded" if present else "removed")
                last = f"rules loaded: {sorted(found)}"
            else:
                last = f"analysisd {st.get('wazuh-analysisd')}"
        except WazuhAPIError as e:
            last = str(e)[:160]
        await asyncio.sleep(_R.POLL_EVERY)
    raise DeployError(f"manager did not come back as expected within {timeout}s ({last})")


async def _run_tests(api: WazuhAPI, ids: list[str], tests: list[dict], replay: int = 1) -> list[dict]:
    """Run the draft's logtest samples and classify each one.

    With ``replay`` > 1 (frequency / correlation rules) each sample is sent ``replay`` times through one logtest
    session, so the rule sees the history it needs; ``events`` records after how many events it fired.

    ``passed``      the expected outcome was observed,
    ``failed``      the observed outcome differs from the expectation (the rule is wrong),
    ``inconclusive`` no rule matched the sample at all, so the sample cannot be replayed through logtest,
    ``not_run``     handed out by the caller (no samples, or manager-internal events).
    """
    out = []
    for t in tests[:6]:
        fmt, loc = t.get("log_format", "syslog"), t.get("location", "daily-triage")
        if replay > 1 and hasattr(api, "logtest_replay"):
            seq = await api.logtest_replay(t["event"], replay, fmt, loc)
        else:
            seq = [await api.logtest(t["event"], fmt, loc)]
        rids = [str(((d.get("output") or {}).get("rule") or {}).get("id", "")) for d in seq]
        hit = next((i for i, r in enumerate(rids, 1) if r in ids), 0)
        rid = rids[hit - 1] if hit else next((r for r in reversed(rids) if r), "")
        want = t.get("expect", "match") == "match"
        # no rule at all matched the sample (not even a parent): the sample is not reproducible, not a rule failure
        if want and not rid:
            state = "inconclusive"
        elif bool(hit) == want:
            state = "passed"
        else:
            state = "failed"
        out.append({"expect": "match" if want else "no_match", "got_rule": rid, "state": state,
                    "ok": state == "passed", "inconclusive": state == "inconclusive",
                    "events": hit or len(seq), "replayed": len(seq)})
    return out


def _test_summary(res: list[dict]) -> str:
    sym = {"passed": "✓", "failed": "✗", "inconclusive": "?", "not_run": "–"}
    def one(r: dict) -> str:
        n = r.get("replayed", 1)
        when = f" (event {r.get('events')}/{n})" if n > 1 else ""
        return f"{r['expect']} → {r.get('got_rule') or '-'}{when} {sym.get(r.get('state'), '?')}"
    return "; ".join(one(r) for r in res)


async def apply(api: WazuhAPI, cfg: RuleDeployCfg, kid: str, xml: str, ids: list[str], title: str = "",
                tests: list[dict] | None = None, remove: bool = False, replayable: bool = True,
                allow_inconclusive: bool | None = None, replay: int = 1,
                on_step: Callable[[dict], None] | None = None) -> list[dict]:
    """Write (or remove) one draft's block, validate, restart, verify; roll back on any failure.

    Fail closed: a failed logtest expectation blocks deployment, and so does an inconclusive sample unless
    ``allow_inconclusive`` is enabled for the environment. Manager-internal events (which logtest cannot
    replay) are recorded as ``not_run`` rather than silently counted as a pass.
    """
    steps: list[dict] = []
    if allow_inconclusive is None:
        allow_inconclusive = cfg.allow_inconclusive

    def step(name, ok=True, detail="", state=""):
        d = {"step": name, "ok": ok, "detail": str(detail)[:500]}
        if state:
            d["state"] = state
        steps.append(d)
        if on_step:
            on_step(d)

    cluster = await api.cluster_running()
    step("cluster" if cluster else "standalone manager", True, "restart via /cluster/restart" if cluster else "")
    old = await api.rule_file_get(cfg.file)
    step("read " + cfg.file, True, "new file" if old is None else f"{len(old)} bytes")
    new = remove_block(old or "", kid) if remove else with_block(old, kid, xml, title)
    if remove and new == (old or ""):
        step("nothing to remove", True)
        return steps

    async def rollback(reason: str) -> bool:
        """Restore the previous file and verify the manager really came back; False when it did not."""
        step("rollback", True, reason)
        try:
            if old is not None:
                await api.rule_file_put(cfg.file, old)
            else:  # the file did not exist before: remove it (needs rules:delete), else leave an empty file
                try:
                    await api.rule_file_delete(cfg.file)
                except WazuhAPIError:
                    await api.rule_file_put(cfg.file, "<!-- Managed by Occultera. -->\n")
            v = await api.config_validation(cluster)
            if not all(x.get("status") == "OK" for x in v):
                step("rollback validation", False, v)
                return False
            await api.restart(cluster)
            await _wait_back(api, [], cfg.file, cfg.restart_timeout)
            step("rollback done", True, "previous content restored and the manager is back")
            return True
        except (WazuhAPIError, DeployError) as e:
            step("rollback FAILED — check the manager now", False, e)
            return False

    try:
        try:
            await api.rule_file_put(cfg.file, new)
        except WazuhAPIError as e:
            # nothing was written: no rollback, no restart
            hint = ""
            if "Permission denied" in str(e) or "4000" in str(e):
                hint = (f" — the deploy user needs rules:update on *:*:* and rules:delete on rule:file:{cfg.file}"
                        " (overwrite); see docs/rule-deployment.md")
            step("upload", False, f"{e}{hint}")
            step("nothing was changed", True, "the rule file and the manager are untouched")
            err = DeployError(f"upload refused{hint}")
            err.steps = steps
            raise err from e
        step("upload", True)
        val = await api.config_validation(cluster)
        bad = [x for x in val if x.get("status") != "OK"]
        if bad:
            step("validation", False, bad)
            if not await rollback("validation failed — restart skipped"):
                raise DeployError("manager rejected the configuration; rollback FAILED — check the manager now")
            raise DeployError("manager rejected the configuration")
        step("validation", True, "OK")
        await api.restart(cluster)
        step("restart requested", True)
        step("manager back", True, await _wait_back(api, ids, cfg.file, cfg.restart_timeout, present=not remove))
        if tests and not remove and not replayable:
            step("logtest", True, "manager-internal events (rootcheck / FIM / SCA / vulnerability) cannot be "
                 "replayed through logtest — the rule is loaded; confirm it on the next real event",
                 state="not_run")
        elif tests and not remove:
            if replay > 1:
                step("logtest replay", True, f"stateful rule: each sample is sent {replay}× in one logtest session")
            res = await _run_tests(api, ids, tests, replay)
            failed = [r for r in res if r["state"] == "failed"]
            unclear = [r for r in res if r["state"] == "inconclusive"]
            blocked = bool(failed) or (bool(unclear) and not allow_inconclusive)
            detail = _test_summary(res)
            if unclear and not failed:
                detail += (" — '?' = no rule matched the sample at all (it cannot be replayed through logtest); "
                           "confirm the rule on the next real event")
                if not allow_inconclusive:
                    detail += " — deployment blocked: a non-reproducible sample is not a pass " \
                              "(rule_deploy.allow_inconclusive)"
            step("logtest", not blocked, detail,
                 state="failed" if failed else ("inconclusive" if unclear else "passed"))
            if blocked:
                reason = ("logtest expectations not met" if failed
                          else "logtest inconclusive — sample could not be reproduced")
                if not await rollback(reason):
                    raise DeployError(f"{reason}; rollback FAILED — check the manager now")
                raise DeployError(reason)
    except WazuhAPIError as e:
        step("error", False, e)
        # The upload succeeded before this error (upload errors are handled above and change nothing),
        # so the manager now holds a possibly broken file: restore it and verify the rollback.
        if not await rollback(str(e)[:200]):
            err = DeployError(f"{e}; rollback FAILED — check the manager now")
            err.steps, err.rollback = steps, "failed"
            raise err from e
        err = DeployError(str(e))
        err.steps, err.rollback = steps, "done"
        raise err from e
    except DeployError as e:
        if not any(s["step"] in ("rollback", "nothing was changed") for s in steps):
            step("error", False, e)
            if not await rollback("manager did not come back"):
                raise DeployError(f"{e}; rollback FAILED — check the manager now") from e
        rb = [s for s in steps if str(s.get("step", "")).startswith("rollback")]
        e.rollback = ("failed" if any(not s["ok"] for s in rb) else "done") if rb else "not_needed"
        e.steps = steps
        raise
    return steps
