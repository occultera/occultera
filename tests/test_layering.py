# SPDX-License-Identifier: AGPL-3.0-only
"""Structure rules for the 1.0 work (Wazuh 5 adapter, smaller modules).

1. Wazuh field paths and index patterns are named in ``app/wazuh`` only; everything else uses ``S.<FIELD>``.
2. No module grows past ``MAX_LINES``; the few that are still larger have a ceiling that may only go down.
3. The bound schema is per task, so two environments on different Wazuh versions cannot mix.
"""
import asyncio
import re
from pathlib import Path

from app.wazuh import schema as W

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"

# Allowed to spell Wazuh 4.x paths:
#  app/wazuh/       the schema itself
#  app/demo*.py     the synthetic 4.x documents (the demo engine is a 4.x indexer)
#  app/query_guard  the field vocabulary the AI and MCP clients may query (4.x names; translated per version in 1.0)
#  app/whatif.py    replays 4.x XML rules on 4.x documents; uses the V4 schema explicitly
ALLOWED = ("wazuh/", "demo", "query_guard.py", "whatif.py")
NOT_FIELDS = {"agent.trace", "rule.deploy", "rule.undeploy"}   # audit actions and stored keys, not Wazuh fields
PATH = re.compile(r'"((?:rule|agent|data|manager|decoder|vulnerability|package|syscheck|predecoder)\.[A-Za-z0-9_.]+)"')
INDEX = re.compile(r'"wazuh-(?:alerts|states|archives|events|findings)[^"]*"')

MAX_LINES = 450
CEILING = {   # current size of the modules still to split; lower these as they shrink, never raise them
    "config.py": 654,
    "demo.py": 618, "collector.py": 613, "web/api.py": 525, "privacy.py": 497, "rules.py": 465,
}


def _modules():
    for p in APP.rglob("*.py"):
        if "__pycache__" not in p.parts:
            yield p, p.relative_to(APP).as_posix()


def test_wazuh_paths_only_in_the_adapter():
    bad = []
    for p, rel in _modules():
        if rel.startswith(ALLOWED):
            continue
        text = p.read_text(encoding="utf-8")
        for m in PATH.finditer(text):
            if m.group(1) not in NOT_FIELDS:
                bad.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}: {m.group(0)} -> use S.<FIELD>")
        for m in INDEX.finditer(text):
            if rel != "config.py":      # the configurable defaults
                bad.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}: {m.group(0)}")
    assert not bad, "raw Wazuh paths outside app/wazuh:\n" + "\n".join(bad)


DATA = re.compile(r"^i18n/[a-z]{2}\.py$")   # message catalogues are data, one key per line


def test_module_size():
    bad = []
    for p, rel in _modules():
        if DATA.match(rel):
            continue
        n = sum(1 for _ in p.open(encoding="utf-8"))
        limit = CEILING.get(rel, MAX_LINES)
        if n > limit:
            bad.append(f"{rel}: {n} lines (limit {limit})")
    assert not bad, "split these modules:\n" + "\n".join(bad)


def test_ceilings_are_tight():
    """A ceiling that is no longer needed is removed, so the limit applies again."""
    stale = [rel for rel, lim in CEILING.items()
             if (APP / rel).exists() and sum(1 for _ in (APP / rel).open(encoding="utf-8")) <= MAX_LINES]
    missing = [rel for rel in CEILING if not (APP / rel).exists()]
    assert not stale and not missing, f"drop from CEILING: {stale + missing}"


async def test_schema_is_bound_per_task():
    class Env:
        def __init__(self, v):
            self.wazuh_version = v

    other = W.Schema(version=99, alerts_index="x-*", vuln_index="y-*", RULE_LEVEL="x.level")
    W.SCHEMAS[99] = other
    try:
        async def one(v):
            W.bind(Env(v))
            await asyncio.sleep(0)
            return W.S.RULE_LEVEL

        a, b = await asyncio.gather(one(4), one(99))
        assert (a, b) == ("rule.level", "x.level")
        assert W.current() is W.V4          # the caller's context is untouched by its child tasks
    finally:
        W.SCHEMAS.pop(99)


def test_severity_mapping_round_trip():
    for level in range(0, 17):
        assert W.SEVERITY_LEVELS[W.severity_of(level)] >= level or level > 15
    assert [W.severity_of(x) for x in (0, 4, 7, 10, 13)] == ["informational", "low", "medium", "high", "critical"]
    assert W.V4.level_gte(7) == {"range": {"rule.level": {"gte": 7}}}
