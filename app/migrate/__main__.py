# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Rüstem Duru
"""python -m app.migrate local_rules.xml [more.xml …] [--events alerts.jsonl] [--out migrate-out] [--json]

Writes one Sigma file per convertible rule into --out, plus report.md (and report.json with --json).
--events: 4.x alert documents, one JSON object per line (e.g. exported from wazuh-alerts-4.x-*), used for the
match check. Nothing is sent anywhere.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .check import check
from .convert import convert
from .fields import FIELDS


def report_md(name: str, res: dict, chk: dict) -> str:
    s = res["summary"]
    lines = [f"# occultera-migrate — {name}", "",
             f"{s['total']} rules: **{s['converted']} converted**, {s['review']} need review, "
             f"{s['unsupported']} without a Sigma equivalent · coverage {s['coverage_percent']} %"
             + (f" · {s['decoders_reported']} custom decoders (not converted in this version)" if s["decoders_reported"] else ""),
             "", "| Rule | Level | Status | Match check | Needs a person |", "|---|---|---|---|---|"]
    for r in res["rules"]:
        c = chk.get(r["id"])
        mc = f"{c['agree']}/{c['events']} agree (xml {c['xml_matches']}, sigma {c['sigma_matches']})" if c else "—"
        lines.append(f"| {r['id']} {r['title'][:60]} | {r['level']} | {r['status']} | {mc} | "
                     + "<br>".join(r["review"])[:400] + " |")
    lines += ["", "## Field map (4.x → Wazuh Common Schema, 5.0 rc)", "", "| 4.x | 5.x |", "|---|---|"]
    lines += [f"| `{a}` | `{b}` |" for a, b in FIELDS.items()]
    lines += ["", "Preview: field names follow the Wazuh 5.0 release candidates and are re-checked at GA. "
              "Test every rule on real events before enabling it."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.migrate", description=__doc__.splitlines()[0])
    ap.add_argument("xml", nargs="+", type=Path)
    ap.add_argument("--events", type=Path)
    ap.add_argument("--out", type=Path, default=Path("migrate-out"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    events = []
    if a.events:
        events = [json.loads(x) for x in a.events.read_text(encoding="utf-8").splitlines() if x.strip()]
    a.out.mkdir(parents=True, exist_ok=True)
    allres = {}
    md = []
    for f in a.xml:
        xml = f.read_text(encoding="utf-8")
        res = convert(xml)
        chk = check(xml, res["rules"], events) if events else {}
        for r in res["rules"]:
            if r["status"] != "unsupported":
                (a.out / f"wazuh-{r['id']}.yml").write_text(r["yaml"], encoding="utf-8")
        md.append(report_md(f.name, res, chk))
        allres[f.name] = {**res, "check": chk}
        s = res["summary"]
        print(f"{f.name}: {s['total']} rules — {s['converted']} converted, {s['review']} review, "
              f"{s['unsupported']} unsupported ({s['coverage_percent']} %)", file=sys.stderr)
    (a.out / "report.md").write_text("\n".join(md), encoding="utf-8")
    if a.json:
        (a.out / "report.json").write_text(json.dumps(allres, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    print(f"written to {a.out}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
