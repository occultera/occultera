# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""Rule drafts: extraction, safety analysis, manual commands and (opt-in) deployment.

Deployment is the ONLY write path towards Wazuh in this application. It is off unless an environment sets
`rule_deploy.enabled: true` with a separate API user, it writes to a single dedicated rules file, and every
change is validated by the manager before restart and rolled back automatically if anything fails.
"""
from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET  # ParseError only; parsing goes through defusedxml
from datetime import UTC, datetime

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .config import RuleDeployCfg
from .wazuh.api import WazuhAPI, WazuhAPIError

HEREDOC = "WDT_RULE_EOF"
POLL_FIRST, POLL_EVERY = 5.0, 4.0   # seconds; tests shorten these
_BLOCK = r"<!-- wdt:begin {kid} -->.*?<!-- wdt:end {kid} -->\n?"


# ----------------------------------------------------------------------------- extraction
def extract_xml(entry: dict) -> str:
    """The XML of a rule draft: the explicit `xml` field, else the <group>/<rule> elements inside the body."""
    if (entry.get("xml") or "").strip():
        return entry["xml"].strip()
    body = (entry.get("body") or "")[:200_000]
    # fenced blocks (``` or ```xml), found with plain string operations (no backtracking on long input)
    parts = body.split("```")
    for block in parts[1::2]:
        first, _, rest = block.partition("\n")
        code = rest if first.strip() in ("", "xml") else block
        if "<rule" in code:
            return code.strip()
    for tag in ("group", "rule"):
        a, b = body.find(f"<{tag}"), body.rfind(f"</{tag}>")
        if a != -1 and b > a:
            return body[a:b + len(tag) + 3].strip()
    return ""


def _normalise(xml: str) -> str:
    """Rules must sit inside <group>; wrap bare <rule> elements."""
    if xml.lstrip().startswith("<group"):
        return xml
    return f'<group name="wazuh-daily-triage,">\n{xml}\n</group>'


# ----------------------------------------------------------------------------- analysis
def ip_element_issues(tag: str, el) -> list[str]:
    """Problems with a <srcip>/<dstip> condition. Wazuh takes only an IP address or CIDR block there (optionally
    negated with "!", several elements = any of them); a regex or a type="" attribute fails `wazuh-analysisd -t`."""
    issues = []
    if el.attrib:
        issues.append(f"<{tag}> takes no attributes ({', '.join(el.attrib)}) — only an IP or CIDR, e.g. "
                      f"<{tag}>192.168.68.52/31</{tag}>")
    text = (el.text or "").strip()
    if not text:
        issues.append(f"<{tag}> is empty")
    for part in (x.strip() for x in text.split(",")):
        if not part:
            continue
        try:
            ipaddress.ip_network(part.lstrip("!"), strict=False)
        except ValueError:
            issues.append(f"<{tag}>{part}</{tag}> is not an IP address or CIDR block (no regex here: use a CIDR "
                          f"such as 10.0.0.0/24, or one <{tag}> element per address)")
    return issues


def parse(xml: str) -> tuple[list[dict], list[str]]:
    errors: list[str] = []
    rules: list[dict] = []
    if not xml.strip():
        return [], ["no rule XML found in this entry"]
    if "wdt:" in xml or HEREDOC in xml:
        errors.append("XML contains reserved markers (wdt: / heredoc terminator)")
    try:
        root = SafeET.fromstring(f"<root>{_normalise(xml)}</root>")   # no DTD / entity expansion
    except DefusedXmlException:
        return [], ["XML error: DTDs and entities are not allowed"]
    except ET.ParseError as e:
        return [], [f"XML error: {e}"]
    for top in root:
        if top.tag != "group":
            errors.append(f"top-level <{top.tag}> is not allowed; only <group>")
    for r in root.iter("rule"):
        for tag in ("srcip", "dstip"):
            for el in r.iter(tag):
                errors.extend(f"rule {r.get('id')}: {m}" for m in ip_element_issues(tag, el))
        opts = [o.text.strip() for o in r.iter("options") if o.text]
        parents = [x.strip() for t in ("if_sid", "if_matched_sid") for el in r.iter(t)
                   for x in re.split(r"[,\s]+", el.text or "") if x.strip()]
        desc = next((el.text or "" for el in r.iter("description")), "").strip()
        conds = []
        for el in r:
            if el.tag in ("if_sid", "if_matched_sid", "description", "options", "mitre", "group", "info"):
                continue
            attrs = " ".join(f'{k}="{v}"' for k, v in el.attrib.items())
            conds.append(f"<{el.tag}{' ' + attrs if attrs else ''}>{(el.text or '').strip()}")
        rules.append({"id": r.get("id"), "level": r.get("level"), "overwrite": r.get("overwrite") == "yes",
                      "options": opts, "parents": parents, "description": desc, "conditions": conds,
                      "frequency": r.get("frequency"), "timeframe": r.get("timeframe"), "ignore": r.get("ignore"),
                      "if_group": [el.text for el in r.iter("if_group")] + [el.text for el in r.iter("if_matched_group")],
                      "matched": any(True for t in ("if_matched_sid", "if_matched_group") for _ in r.iter(t))})
    if not rules:
        errors.append("no <rule> element")
    return rules, errors


MAX_REPLAY = 64


def replay_count(rules: list[dict]) -> int:
    """How many times a logtest sample must be replayed in one session for the draft's rules to be able to fire.

    A frequency rule fires only after ``frequency`` matching events within ``timeframe`` (two extra events
    cover off-by-one differences between Wazuh versions); an ``if_matched_sid``/``if_matched_group`` rule
    needs at least one earlier event. Stateless rules need one.
    """
    n = 1
    for r in rules:
        f = str(r.get("frequency") or "").strip()
        if f.isdigit():
            n = max(n, int(f) + 2)
        elif r.get("matched"):
            n = max(n, 2)
    return min(n, MAX_REPLAY)


INTERNAL_GROUPS = {"rootcheck", "syscheck", "syscheck_file", "syscheck_entry_added", "syscheck_entry_modified",
                   "syscheck_entry_deleted", "sca", "vulnerability-detector", "ossec"}


async def analyse(xml: str, cfg: RuleDeployCfg, api: WazuhAPI | None, high_level: int = 7) -> dict:
    """Errors block deployment; `risky` (silencing / level lowering) needs a second, typed confirmation."""
    rules, errors = parse(xml)
    risky: list[str] = []
    ids = [r["id"] for r in rules]
    for r in rules:
        rid, lvl = r["id"], r["level"]
        if not rid or not rid.isdigit():
            errors.append(f"rule without numeric id: {rid!r}")
            continue
        if not (cfg.id_min <= int(rid) <= cfg.id_max):
            errors.append(f"rule {rid}: id outside the allowed range {cfg.id_min}-{cfg.id_max}")
        if lvl is None or not lvl.isdigit():
            errors.append(f"rule {rid}: missing or invalid level")
            continue
        if int(lvl) == 0:
            risky.append(f"rule {rid}: level 0 — matching events will NOT raise alerts")
        if r["overwrite"]:
            risky.append(f"rule {rid}: overwrite=\"yes\" replaces an existing rule")
        for o in r["options"]:
            if o in ("no_log", "no_full_log", "no_email_alert", "no_ar"):
                risky.append(f"rule {rid}: <options>{o}</options>")
    if len(set(ids)) != len(ids):
        errors.append("duplicate rule ids in the draft")
    parents_info: dict[str, dict] = {}
    # existing-rule checks also when the id range is wrong, so a collision is reported at the same time
    if api and rules and all(r["id"] and r["id"].isdigit() for r in rules):
        want = sorted({p for r in rules for p in r["parents"]} | set(ids))
        api_ok = True
        try:
            for x in await api.rules(want):
                parents_info[str(x["id"])] = x
        except WazuhAPIError as e:
            api_ok = False
            errors.append(f"cannot check existing rules (Wazuh API unreachable, parent/collision checks skipped): {e}")
        # without an API answer an empty lookup says nothing — do not report parents as missing
        for rid in (ids if api_ok else []):
            ex = parents_info.get(rid)
            if ex and ex.get("filename") != cfg.file:
                errors.append(f"rule {rid} already exists in {ex.get('filename')} (id collision)")
        for r in (rules if api_ok else []):
            for p in r["parents"]:
                pl = parents_info.get(p, {}).get("level")
                if pl is not None and r["level"] and r["level"].isdigit() and int(r["level"]) < int(pl):
                    risky.append(f"rule {r['id']}: lowers level {pl} → {r['level']} for child events of {p}")
                if p not in parents_info:
                    errors.append(f"rule {r['id']}: parent rule {p} does not exist")
                    continue
                pi = parents_info[p]
                # etc/rules files load alphabetically: a parent in a later file is not known yet
                if pi.get("relative_dirname") == "etc/rules" and pi.get("filename") != cfg.file \
                        and str(pi.get("filename", "")) > cfg.file:
                    errors.append(f"rule {r['id']}: parent {p} is in {pi.get('filename')}, which loads after "
                                  f"{cfg.file} (alphabetical) — rename rule_deploy.file, e.g. zz_{cfg.file}")
    # events produced inside the manager (rootcheck, FIM, SCA, vulnerability detection, agent status) cannot be
    # replayed through /logtest — their samples would never reach the rule
    internal = set(re.findall(r"<if_group>\s*([^<\s]+)\s*</if_group>", xml))
    internal |= set(re.findall(r"<decoded_as>\s*([^<\s]+)\s*</decoded_as>", xml))
    if re.search(r"<category>\s*ossec\s*</category>", xml):
        internal.add("ossec")
    for v in parents_info.values():
        internal |= set(v.get("groups") or [])
    not_replayable = sorted(internal & INTERNAL_GROUPS)
    return {"replay": replay_count(rules), "ok": not errors, "errors": errors, "risky": sorted(set(risky)), "ids": ids,
            "replayable": not not_replayable, "internal_groups": not_replayable,
            "test_policy": {"require_tests": cfg.require_tests, "allow_inconclusive": cfg.allow_inconclusive},
            "xml": _normalise(xml), "parents": {k: {"level": v.get("level"), "description": v.get("description"),
                                                    "filename": v.get("filename")} for k, v in parents_info.items()}}


# ----------------------------------------------------------------------------- file content
def block(kid: str, xml: str, title: str = "") -> str:
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%MZ")
    t = re.sub(r"-{2,}", "-", re.sub(r"[^\w .,:/()-]", "", title))[:120].rstrip("-")
    return f"<!-- wdt:begin {kid} -->\n<!-- {t} · {stamp} -->\n{_normalise(xml)}\n<!-- wdt:end {kid} -->\n"


def with_block(content: str | None, kid: str, xml: str, title: str = "") -> str:
    base = remove_block(content or "", kid)
    if not base.strip():
        base = "<!-- Managed by Occultera: approved rule drafts. Edit with care. -->\n"
    return base.rstrip("\n") + "\n\n" + block(kid, xml, title)


def remove_block(content: str, kid: str) -> str:
    return re.sub(_BLOCK.format(kid=re.escape(kid)), "", content, flags=re.S)


# ----------------------------------------------------------------------------- manual commands
def commands(kid: str, xml: str, cfg: RuleDeployCfg, title: str = "", ids: list[str] | None = None,
             tests: list[dict] | None = None) -> str:
    f = f"/var/ossec/etc/rules/{cfg.file}"
    first = (ids or ["?"])[0]
    lines = [
        f"# Occultera — {title}",
        "# Run as root on the Wazuh manager (the MASTER node in a cluster; workers receive rules from it).",
        "# Kubernetes/Docker: kubectl exec -it <master-pod> -- bash, then paste.",
        f'F={f}; B="$F.bak.$(date +%Y%m%d-%H%M%S)"',
        '[ -f "$F" ] && cp -a "$F" "$B" || { touch "$F"; B=; }',
        f"sed -i '/<!-- wdt:begin {kid} -->/,/<!-- wdt:end {kid} -->/d' \"$F\"   # previous version of this draft",
        f"cat >> \"$F\" <<'{HEREDOC}'",
        block(kid, xml, title).rstrip("\n"),
        HEREDOC,
        'chown wazuh:wazuh "$F" 2>/dev/null; chmod 660 "$F"',
        "# syntax/ruleset check — restores the backup and stops if it fails",
        'if ! /var/ossec/bin/wazuh-analysisd -t; then echo "INVALID - restoring"; '
        '[ -n "$B" ] && cp -a "$B" "$F" || rm -f "$F"; false; fi',
        "systemctl restart wazuh-manager 2>/dev/null || /var/ossec/bin/wazuh-control restart",
        f"grep -c 'id=\"{first}\"' \"$F\"   # 1 = in the file",
    ]
    if tests:
        lines.append("# logtest: paste each event into /var/ossec/bin/wazuh-logtest")
        rc = replay_count(parse(xml)[0])
        if rc > 1:
            lines.append(f"#   stateful rule (frequency / if_matched): paste the same event {rc} times in ONE session")
        for t in tests[:6]:
            lines.append(f"#   expect {t.get('expect', 'match')}: {str(t.get('event', ''))[:300]}")
    lines += [
        "# Roll back:",
        f"#   sed -i '/<!-- wdt:begin {kid} -->/,/<!-- wdt:end {kid} -->/d' {f} && systemctl restart wazuh-manager",
    ]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------- deployment


from .rules_apply import DeployError, _run_tests, _test_summary, _wait_back, apply  # noqa: E402,F401 - re-exported
